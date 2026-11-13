"""Intelligence externe explicite : OSV, NVD, CISA KEV, FIRST EPSS.

Règles du laboratoire :

- jamais d'appel implicite : `--online` et `online.enabled` sont requis ;
- budget de requêtes et cache local ;
- redirections HTTP refusées ;
- aucun constat « applicable confirmée » : tout reste `to_verify` tant que le
  paquet de distribution et le correctif ne sont pas vérifiés.
"""

import hashlib
import json
import os
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import authz
from intelligence.models import make_finding
from security_intelligence import collection_trace
from security_intelligence.reports import ensure_private_directory

OSV_URL = "https://api.osv.dev/v1/query"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
EPSS_URL = "https://api.first.org/data/v1/epss"
USER_AGENT = "NOUR-SENTINEL-LAB/0.6.0-beta.4 (defensive audit)"

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "IMPORTANT": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNIMPORTANT": "low",
    "NEGLIGIBLE": "low",
}


class LookupFailed(RuntimeError):
    """Une requête externe a échoué ou a été refusée."""


class BudgetExceeded(LookupFailed):
    """Le budget de requêtes de cette exécution est épuisé."""


class UrllibTransport:
    """Transport réel, sans redirection et avec plafond de lecture."""

    def __init__(self, max_bytes=2_000_000):
        self.max_bytes = max_bytes

    @collection_trace.instrument("external", "online.UrllibTransport.fetch")
    def fetch(self, method, url, body=None, headers=None, timeout=10.0):
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, response_headers, newurl):
                raise LookupFailed("redirection HTTP refusée")

        opener = urllib.request.build_opener(_NoRedirect)
        request = urllib.request.Request(
            url,
            data=body,
            headers=headers or {},
            method=method,
        )

        try:
            with opener.open(request, timeout=timeout) as response:
                return response.read(self.max_bytes)
        except LookupFailed:
            raise
        except (urllib.error.URLError, OSError, ValueError) as error:
            raise LookupFailed(f"requête externe échouée: {error}") from error


class Cache:
    """Cache JSON privé, indexé par empreinte de requête."""

    def __init__(self, directory, ttl_seconds=86400, now=None):
        self.directory = ensure_private_directory(directory)
        self.ttl_seconds = int(ttl_seconds)
        self.now = now or time.time

    def _path(self, key):
        digest = hashlib.sha256(str(key).encode("utf-8")).hexdigest()

        return self.directory / f"{digest}.json"

    def get(self, key):
        if self.ttl_seconds <= 0:
            return None

        path = self._path(key)

        try:
            age = self.now() - path.stat().st_mtime
        except OSError:
            return None

        if age < 0 or age > self.ttl_seconds:
            return None

        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def put(self, key, value):
        path = self._path(key)
        descriptor, temporary = tempfile.mkstemp(
            prefix=".cache.", dir=str(self.directory)
        )

        try:
            os.fchmod(descriptor, 0o600)

            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(value, handle, ensure_ascii=False)
                handle.flush()
                os.fsync(handle.fileno())

            os.replace(temporary, path)
            os.chmod(path, 0o600)
        except Exception:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise


class Budget:
    def __init__(self, max_requests):
        self.max_requests = max(1, int(max_requests))
        self.used = 0

    def consume(self):
        if self.used >= self.max_requests:
            raise BudgetExceeded(
                f"budget de {self.max_requests} requête(s) externe(s) épuisé"
            )

        self.used += 1


def _severity(document):
    database = document.get("database_specific") or {}

    for key in ("severity", "urgency"):
        value = str(database.get(key) or "").strip().upper()

        if value in SEVERITY_MAP:
            return SEVERITY_MAP[value], True

    return "medium", False


def _fixed_version(document):
    for affected in document.get("affected") or []:
        for entry in affected.get("ranges") or []:
            for event in entry.get("events") or []:
                if event.get("fixed"):
                    return str(event["fixed"])

    return None


def _references(document):
    references = []

    for reference in document.get("references") or []:
        url = reference.get("url") if isinstance(reference, dict) else None

        if url:
            references.append(str(url))

    return references[:5]


def _osv_finding(host, package, version, document):
    identifier = str(document.get("id") or "OSV-UNKNOWN")
    aliases = [str(alias) for alias in document.get("aliases") or []]
    cve = next((alias for alias in aliases if alias.upper().startswith("CVE-")), None)

    if cve is None and identifier.upper().startswith("CVE-"):
        cve = identifier

    fixed = _fixed_version(document)
    severity, severity_known = _severity(document)
    summary = str(document.get("summary") or document.get("details") or "").strip()

    return make_finding(
        asset=host,
        component=package,
        check=f"cve.{cve or identifier}",
        observation=(
            f"{package} {version} correspond à {cve or identifier} dans OSV"
        ),
        evidence=(
            f"osv:{identifier}; package={package}; installed={version}; "
            f"fixed={fixed or 'unknown'}"
        ),
        confidence="corroborated",
        confidence_reason=(
            "Correspondance OSV uniquement : le paquet de distribution, le "
            "correctif rétroporté et les conditions d'exploitation ne sont pas vérifiés."
        ),
        severity=severity,
        exposure="local",
        recommendation=(
            f"Mettre à jour {package} vers {fixed} ou appliquer le correctif "
            "fournisseur, puis vérifier l'avis de la distribution."
            if fixed
            else f"Vérifier l'avis de la distribution pour {package} et appliquer le correctif."
        ),
        references=_references(document)
        or ([f"https://osv.dev/vulnerability/{identifier}"]),
        status="to_verify",
        cve=cve,
        metadata={
            "source": "OSV",
            "osv_id": identifier,
            "fixed_version": fixed,
            "severity_source": "OSV" if severity_known else "non fournie",
            "summary": summary[:300],
        },
    )


class OnlineIntel:
    """Client unique, injectable pour des tests entièrement hors ligne."""

    def __init__(self, config, transport=None, cache=None, budget=None, cache_dir=None):
        options = (config or {}).get("online") or {}
        self.timeout = float(options.get("timeout_seconds") or 10.0)
        self.api_key_env = str(options.get("nvd_api_key_env") or "NVD_API_KEY")

        if cache is None:
            if cache_dir is None:
                base = Path(
                    (config or {}).get("reports_dir") or "data/reports"
                ).resolve().parent
                cache_dir = base / "cache" / "intel"

            cache = Cache(
                cache_dir,
                ttl_seconds=int(options.get("cache_ttl_seconds") or 86400),
            )

        self.cache = cache
        self.transport = transport or UrllibTransport()
        self.budget = budget or Budget(int(options.get("max_requests") or 20))

    @collection_trace.instrument("external", "online._json")
    def _json(self, method, url, body=None, headers=None):
        authz.require()
        key = f"{method} {url} {body.decode('utf-8') if body else ''}"
        cached = self.cache.get(key)

        if cached is not None:
            return cached

        self.budget.consume()
        raw = self.transport.fetch(
            method,
            url,
            body=body,
            headers=headers,
            timeout=self.timeout,
        )

        try:
            html = raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
            data = json.loads(html)
        except (UnicodeDecodeError, ValueError) as error:
            raise LookupFailed(f"réponse JSON invalide: {error}") from error

        self.cache.put(key, data)

        return data

    @collection_trace.instrument("external", "online.query_osv")
    def query_osv(self, package, version, ecosystem="Debian"):
        body = json.dumps(
            {
                "package": {"name": package, "ecosystem": ecosystem},
                "version": str(version),
            }
        ).encode("utf-8")

        data = self._json(
            "POST",
            OSV_URL,
            body=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
            },
        )

        return data.get("vulns") or []

    @collection_trace.instrument("external", "online.nvd_keyword")
    def nvd_keyword(self, keyword, limit=10):
        params = urllib.parse.urlencode(
            {"keywordSearch": str(keyword), "resultsPerPage": str(int(limit))}
        )
        headers = {"User-Agent": USER_AGENT}
        api_key = os.environ.get(self.api_key_env)

        if api_key:
            headers["apiKey"] = api_key

        data = self._json("GET", f"{NVD_URL}?{params}", headers=headers)

        return data.get("vulnerabilities") or []

    @collection_trace.instrument("external", "online.kev_catalog")
    def kev_catalog(self):
        data = self._json(
            "GET", KEV_URL, headers={"User-Agent": USER_AGENT}
        )

        return {
            str(item.get("cveID")).upper()
            for item in data.get("vulnerabilities") or []
            if item.get("cveID")
        }

    @collection_trace.instrument("external", "online.epss_scores")
    def epss_scores(self, cves):
        scores = {}
        ordered = sorted({str(cve).upper() for cve in cves if cve})

        for start in range(0, len(ordered), 50):
            chunk = ordered[start : start + 50]
            params = urllib.parse.urlencode({"cve": ",".join(chunk)})
            data = self._json(
                "GET", f"{EPSS_URL}?{params}", headers={"User-Agent": USER_AGENT}
            )

            for item in data.get("data") or []:
                try:
                    scores[str(item["cve"]).upper()] = float(item["epss"])
                except (KeyError, TypeError, ValueError):
                    continue

        return scores

    @collection_trace.instrument("external", "online.nvd_findings")
    def nvd_findings(self, host, keyword, limit=10):
        findings = []

        for wrapper in self.nvd_keyword(keyword, limit=limit):
            cve = wrapper.get("cve") or {}
            identifier = str(cve.get("id") or "")

            if not identifier:
                continue

            description = next(
                (
                    str(item.get("value") or "")
                    for item in cve.get("descriptions") or []
                    if item.get("lang") == "en"
                ),
                "",
            )
            metrics = cve.get("metrics") or {}
            severity = "medium"
            score = None

            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key) or []

                if not entries:
                    continue

                data = entries[0].get("cvssData") or {}
                severity = SEVERITY_MAP.get(
                    str(data.get("baseSeverity") or "").upper(), "medium"
                )
                score = data.get("baseScore")
                break

            findings.append(
                make_finding(
                    asset=host,
                    component=keyword,
                    check=f"cve.{identifier}",
                    observation=description[:300] or f"{identifier} (NVD)",
                    evidence=f"nvd:{identifier}; keyword={keyword}",
                    confidence="corroborated",
                    confidence_reason=(
                        "Recherche NVD par mots-clés : des faux positifs sont possibles."
                    ),
                    severity=severity,
                    exposure="local",
                    recommendation=(
                        "Vérifier la version affectée, l'avis de la distribution "
                        "et le correctif disponible."
                    ),
                    references=[f"https://nvd.nist.gov/vuln/detail/{identifier}"],
                    status="to_verify",
                    cve=identifier,
                    metadata={"source": "NVD", "cvss_base_score": score},
                )
            )

        return findings

    @collection_trace.instrument("external", "online.assess_packages")
    def assess_packages(self, host, packages, limit=10, ecosystem="Debian"):
        """Interroge OSV pour des paquets, puis ajoute KEV et EPSS connus."""

        findings = []
        errors = []
        cve_ids = set()
        queried = 0

        for package in (packages or [])[: max(1, int(limit))]:
            name = str(package.get("package") or "").strip()
            version = str(package.get("version") or "").strip()

            if not name or not version:
                continue

            try:
                vulnerabilities = self.query_osv(name, version, ecosystem=ecosystem)
            except LookupFailed as error:
                errors.append(f"OSV {name}: {error}")
                continue

            queried += 1

            for document in vulnerabilities:
                if not isinstance(document, dict):
                    continue

                finding = _osv_finding(host, name, version, document)
                findings.append(finding)

                if finding.get("cve"):
                    cve_ids.add(finding["cve"].upper())

        kev = set()
        epss = {}

        if cve_ids:
            try:
                kev = self.kev_catalog()
            except LookupFailed as error:
                errors.append(f"KEV: {error}")

            try:
                epss = self.epss_scores(cve_ids)
            except LookupFailed as error:
                errors.append(f"EPSS: {error}")

        for finding in findings:
            cve = str(finding.get("cve") or "").upper()

            if cve in kev:
                finding["kev"] = True

            if cve in epss:
                finding["epss"] = epss[cve]

        return (
            findings,
            {
                "packages_queried": queried,
                "vulnerabilities": len(findings),
                "cve": sorted(cve_ids),
                "kev_matches": sorted(cve_ids & kev),
                "epss_known": len(epss),
                "requests_used": self.budget.used,
                "budget": self.budget.max_requests,
            },
            errors,
        )
