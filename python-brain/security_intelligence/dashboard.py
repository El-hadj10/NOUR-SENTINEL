"""Tableau de bord local du laboratoire NOUR SENTINEL.

Le tableau de bord est une interface, pas un contournement : il ne desserre
aucun garde-fou. Il n'écoute que sur ``127.0.0.1``, n'ouvre aucune route API
sans le jeton de session affiché au lancement, et délègue chaque capacité aux
fonctions ``lab``/``network_scan`` déjà instrumentées par ``collection_trace``.

Point important : ``authz`` s'appuie sur une ``ContextVar``. Les handlers HTTP
s'exécutent dans des threads secondaires, qui ne voient pas le jeton délivré au
thread principal. L'exécution des capacités est donc mise en file et traitée
par le thread principal (``service_jobs``), le seul à détenir l'autorisation.
Les handlers attendent le résultat sans jamais collecter eux-mêmes.

Aucune dépendance externe : ``http.server`` et la bibliothèque standard.
"""

import json
import queue
import secrets
import sys
import threading
import time
from collections import deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import authz
from security_intelligence import (
    CORE_VERSION,
    PROTOCOL_VERSION,
    VERSION,
    lab,
    network_scan,
    profiles,
)

HOST = "127.0.0.1"
DEFAULT_PORT = 8765
MAX_BODY_BYTES = 8192
JOB_TIMEOUT_SECONDS = 180
WAVE_HISTORY = 120
MAX_TEXT_LENGTH = 64

WEB_ROOT = Path(__file__).resolve().parent / "web"

PUBLIC_FILES = {
    "index.html": "text/html; charset=utf-8",
    "dashboard.css": "text/css; charset=utf-8",
    "dashboard.js": "text/javascript; charset=utf-8",
}

OPTIONS = (
    "inventory",
    "full-local",
    "discover",
    "scan",
    "fingerprint",
    "tls",
    "cve",
)

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'"
)


class NetworkWaves:
    """Débit réseau réellement observé, lu dans ``/proc/net/dev``.

    Les compteurs sont cumulés depuis le démarrage du noyau : on ne publie que
    des deltas par seconde, jamais une valeur absolue, et l'historique reste en
    mémoire du processus.
    """

    def __init__(self, path="/proc/net/dev", history=WAVE_HISTORY):
        self._path = Path(path)
        self._lock = threading.Lock()
        self._previous = None
        self._previous_at = None
        self._history = deque(maxlen=history)

    def _read(self):
        try:
            text = self._path.read_text(encoding="utf-8")
        except OSError:
            return {}

        counters = {}

        for line in text.splitlines():
            if ":" not in line:
                continue

            name, _, rest = line.partition(":")
            fields = rest.split()

            if len(fields) < 16:
                continue

            try:
                counters[name.strip()] = {
                    "rx_bytes": int(fields[0]),
                    "rx_packets": int(fields[1]),
                    "tx_bytes": int(fields[8]),
                    "tx_packets": int(fields[9]),
                }
            except ValueError:
                continue

        return counters

    def sample(self):
        with self._lock:
            now = time.monotonic()
            counters = self._read()
            elapsed = (
                None if self._previous_at is None else max(now - self._previous_at, 1e-6)
            )
            previous = self._previous or {}

            interfaces = []
            total = {"rx_bps": 0.0, "tx_bps": 0.0, "rx_pps": 0.0, "tx_pps": 0.0}

            for name, values in sorted(counters.items()):
                before = previous.get(name)

                if before is None or elapsed is None:
                    rates = {"rx_bps": 0.0, "tx_bps": 0.0, "rx_pps": 0.0, "tx_pps": 0.0}
                else:
                    rates = {
                        "rx_bps": max(values["rx_bytes"] - before["rx_bytes"], 0) / elapsed,
                        "tx_bps": max(values["tx_bytes"] - before["tx_bytes"], 0) / elapsed,
                        "rx_pps": max(values["rx_packets"] - before["rx_packets"], 0) / elapsed,
                        "tx_pps": max(values["tx_packets"] - before["tx_packets"], 0) / elapsed,
                    }

                entry = {"name": name, **rates}
                interfaces.append(entry)

                if name != "lo":
                    for key in total:
                        total[key] += rates[key]

            self._previous = counters
            self._previous_at = now
            self._history.append({"rx": total["rx_bps"], "tx": total["tx_bps"]})

            return {
                "available": bool(counters),
                "read_at": int(time.time()),
                "rx_bps": total["rx_bps"],
                "tx_bps": total["tx_bps"],
                "rx_pps": total["rx_pps"],
                "tx_pps": total["tx_pps"],
                "interfaces": interfaces,
                "history": list(self._history),
            }


def _require_text(value, name, maximum=MAX_TEXT_LENGTH):
    if value is None:
        return None

    if not isinstance(value, str):
        raise ValueError(f"{name} doit être une chaîne")

    text = value.strip()

    if len(text) > maximum:
        raise ValueError(f"{name} trop long ({maximum} caractères maximum)")

    return text


def _require_port(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ValueError("port invalide (1-65535)")

    return value


class _Job:
    __slots__ = ("payload", "event", "result")

    def __init__(self, payload):
        self.payload = payload
        self.event = threading.Event()
        self.result = (
            HTTPStatus.SERVICE_UNAVAILABLE,
            {"ok": False, "error": "tableau de bord arrêté"},
        )


class Dashboard:
    """Serveur local et file d'exécution des capacités."""

    def __init__(self, config, port=DEFAULT_PORT, waves=None):
        if not authz.is_granted():
            raise PermissionError(
                "tableau de bord refusé : authentifiez-vous d'abord avec "
                "./lancer-nour-sentinel.sh --setup-auth"
            )

        self._config = config
        self._port = port
        self._token = secrets.token_urlsafe(24)
        self._jobs = queue.Queue()
        self._waves = waves or NetworkWaves()
        self._server = None
        self._http_thread = None
        self._closed = False

    @property
    def port(self):
        return self._port

    @property
    def token(self):
        return self._token

    @property
    def url(self):
        # Le jeton vit dans le fragment : il n'est ni envoyé au serveur dans
        # l'URL, ni journalisé, ni transmis par Referer.
        return f"http://{HOST}:{self._port}/#t={self._token}"

    def bind(self):
        handler = _build_handler(self)
        self._server = ThreadingHTTPServer((HOST, self._port), handler)
        self._server.daemon_threads = True
        self._port = self._server.server_address[1]

        return self

    def serve_http(self):
        if self._server is None:
            self.bind()

        self._server.serve_forever(poll_interval=0.2)

    def start_http(self):
        """Démarre le serveur HTTP dans un thread secondaire (tests, CLI)."""

        if self._server is None:
            self.bind()

        self._http_thread = threading.Thread(
            target=self.serve_http, name="nour-dashboard-http", daemon=True
        )
        self._http_thread.start()

        return self

    def waves(self):
        return self._waves.sample()

    def meta(self):
        return {
            "version": VERSION,
            "core_version": CORE_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "environment": self._config.get("environment"),
            "options": list(OPTIONS),
            "profiles": {
                name: {
                    "description": profile["description"],
                    "timeout_factor": profile["timeout_factor"],
                    "concurrency": profile["concurrency"],
                    "tcp_ports": len(profile["tcp_ports"]),
                    "udp_ports": len(profile["udp_ports"]),
                }
                for name, profile in profiles.PROFILES.items()
            },
            "default_profile": profiles.DEFAULT_PROFILE,
            "authorized_targets": list(self._config.get("authorized_targets") or []),
            "online_enabled": bool((self._config.get("online") or {}).get("enabled")),
            "limits": {
                "max_ports_per_protocol": network_scan.MAX_PORTS_PER_PROTOCOL,
                "job_timeout_seconds": JOB_TIMEOUT_SECONDS,
            },
        }

    def submit(self, payload):
        """Confie une exécution au thread principal et attend son résultat."""

        job = _Job(payload)
        self._jobs.put(job)

        if not job.event.wait(JOB_TIMEOUT_SECONDS):
            return (
                HTTPStatus.GATEWAY_TIMEOUT,
                {"ok": False, "error": "délai d'exécution dépassé"},
            )

        return job.result

    def service_jobs(self):
        """Boucle d'exécution : à lancer depuis le thread authentifié."""

        while True:
            job = self._jobs.get()

            if job is None:
                return

            try:
                job.result = (
                    HTTPStatus.OK,
                    {"ok": True, "report": self._execute(job.payload)},
                )
            except authz.AuthorizationError as error:
                job.result = (HTTPStatus.FORBIDDEN, {"ok": False, "error": str(error)})
            except PermissionError as error:
                job.result = (HTTPStatus.FORBIDDEN, {"ok": False, "error": str(error)})
            except ValueError as error:
                job.result = (HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(error)})
            except Exception as error:  # noqa: BLE001 - une sonde ne tue pas le serveur
                job.result = (
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"ok": False, "error": f"{type(error).__name__}: {error}"[:300]},
                )
            finally:
                job.event.set()

    def _execute(self, payload):
        if not isinstance(payload, dict):
            raise ValueError("corps JSON objet requis")

        option = payload.get("option")

        if option not in OPTIONS:
            raise ValueError(f"option inconnue: {option!r}")

        profile = payload.get("profile", profiles.DEFAULT_PROFILE)

        if profile not in profiles.PROFILES:
            raise ValueError(f"profil inconnu: {profile!r}")

        if option == "inventory":
            return lab.run_inventory(self._config)

        if option == "full-local":
            return lab.run_full_local(self._config)

        if option == "discover":
            return network_scan.discover_neighbors()

        if option == "cve":
            if payload.get("online") is not True:
                raise PermissionError(
                    "aucun appel externe implicite : cochez l'accès en ligne"
                )

            package = _require_text(payload.get("package"), "package")
            version = _require_text(payload.get("version"), "version")

            return lab.run_cve_online(
                self._config,
                package=package or None,
                version=version or None,
            )

        target = _require_text(payload.get("target"), "target")

        if not target:
            raise ValueError("cible requise pour cette option")

        if option == "scan":
            if payload.get("confirm") is not True:
                raise PermissionError(
                    "confirmation d'autorisation requise avant toute sonde"
                )

            protocol = payload.get("protocol", "both")

            if protocol not in ("tcp", "udp", "both"):
                raise ValueError("protocole attendu: tcp, udp ou both")

            # scan_target revérifie le plafond de 32 ports, la sélection ARP et
            # la cible ; le profil ne lève aucun de ces contrôles.
            return network_scan.scan_target(
                target,
                protocol=protocol,
                authorized=True,
                profile=profile,
            )

        port = _require_port(payload.get("port"))

        if option == "fingerprint":
            protocol = payload.get("protocol", "http")

            if protocol not in ("ssh", "http"):
                raise ValueError("protocole attendu: ssh ou http")

            return lab.run_fingerprint(
                self._config, target, port, protocol=protocol, profile=profile
            )

        return lab.run_tls(self._config, target, port, profile=profile)

    def close(self):
        if self._closed:
            return

        self._closed = True
        self._jobs.put(None)

        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()


def _build_handler(dashboard):
    class Handler(BaseHTTPRequestHandler):
        server_version = "NourSentinelLab"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        # Aucun jeton, aucun en-tête : uniquement la route et le statut.
        def log_message(self, format, *args):  # noqa: A002 - signature imposée
            status = args[1] if len(args) > 1 else "-"
            sys.stderr.write(f"[LAB] dashboard {self.command} {self.path} {status}\n")

        def _host_allowed(self):
            host = (self.headers.get("Host") or "").strip().lower()

            return host in {
                f"127.0.0.1:{dashboard.port}",
                f"localhost:{dashboard.port}",
            }

        def _origin_allowed(self):
            origin = (self.headers.get("Origin") or "").strip().lower()

            if not origin:
                return True

            return origin in {
                f"http://127.0.0.1:{dashboard.port}",
                f"http://localhost:{dashboard.port}",
            }

        def _token_allowed(self):
            given = self.headers.get("X-Nour-Token") or ""

            return secrets.compare_digest(given, dashboard.token)

        def _respond(self, status, payload=None, body=None, content_type=None):
            data = (
                body
                if body is not None
                else json.dumps(payload, ensure_ascii=False).encode("utf-8")
            )

            self.send_response(status)
            self.send_header("Content-Type", content_type or "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", CSP)
            self.end_headers()

            if self.command != "HEAD":
                self.wfile.write(data)

        def _refuse_foreign_host(self):
            if self._host_allowed():
                return False

            self._respond(
                HTTPStatus.FORBIDDEN, {"ok": False, "error": "hôte non autorisé"}
            )

            return True

        def do_GET(self):  # noqa: N802 - API BaseHTTPRequestHandler
            if self._refuse_foreign_host():
                return

            path = urlsplit(self.path).path

            if path in ("/api/meta", "/api/waves"):
                if not self._token_allowed():
                    self._respond(
                        HTTPStatus.UNAUTHORIZED,
                        {"ok": False, "error": "jeton de session requis"},
                    )
                    return

                if path == "/api/meta":
                    self._respond(HTTPStatus.OK, dashboard.meta())
                else:
                    self._respond(HTTPStatus.OK, dashboard.waves())

                return

            name = "index.html" if path in ("/", "/index.html") else path.lstrip("/")

            if name not in PUBLIC_FILES:
                self._respond(HTTPStatus.NOT_FOUND, {"ok": False, "error": "route inconnue"})
                return

            try:
                body = (WEB_ROOT / name).read_bytes()
            except OSError:
                self._respond(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"ok": False, "error": "ressource indisponible"},
                )
                return

            self._respond(
                HTTPStatus.OK, body=body, content_type=PUBLIC_FILES[name]
            )

        def do_POST(self):  # noqa: N802 - API BaseHTTPRequestHandler
            if self._refuse_foreign_host():
                return

            if urlsplit(self.path).path != "/api/run":
                self._respond(HTTPStatus.NOT_FOUND, {"ok": False, "error": "route inconnue"})
                return

            if not self._token_allowed():
                self._respond(
                    HTTPStatus.UNAUTHORIZED,
                    {"ok": False, "error": "jeton de session requis"},
                )
                return

            if not self._origin_allowed():
                self._respond(
                    HTTPStatus.FORBIDDEN, {"ok": False, "error": "origine refusée"}
                )
                return

            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = -1

            if length <= 0 or length > MAX_BODY_BYTES:
                self._respond(
                    HTTPStatus.BAD_REQUEST,
                    {"ok": False, "error": "corps JSON absent ou trop volumineux"},
                )
                return

            raw = self.rfile.read(length)

            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                self._respond(
                    HTTPStatus.BAD_REQUEST, {"ok": False, "error": "JSON invalide"}
                )
                return

            status, body = dashboard.submit(payload)
            self._respond(status, body)

    return Handler


def serve(config, port=DEFAULT_PORT, stream=None):
    """Sert le tableau de bord jusqu'à Ctrl+C, depuis un processus authentifié."""

    stream = stream or sys.stderr
    dashboard = Dashboard(config, port).bind()
    dashboard.start_http()

    print(f"[LAB] dashboard: {dashboard.url}", file=stream)
    print("[LAB] arrêt : Ctrl+C", file=stream)
    stream.flush()

    try:
        dashboard.service_jobs()
    except KeyboardInterrupt:
        print("[LAB] dashboard arrêté", file=stream)
    finally:
        dashboard.close()

    return 0


__all__ = [
    "CSP",
    "Dashboard",
    "MAX_BODY_BYTES",
    "NetworkWaves",
    "OPTIONS",
    "serve",
]
