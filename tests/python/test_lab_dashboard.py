"""Tests du tableau de bord local : jeton, garde-fous et structures."""

import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))

import authz
from security_intelligence import VERSION, cli, lab, network_scan
from security_intelligence import dashboard as dashboard_module


def make_config(directory):
    directory = Path(directory)

    return {
        "version": VERSION,
        "environment": "test",
        "authorized_targets": ("127.0.0.1", "localhost"),
        "timeout": 2.0,
        "max_response_bytes": 65536,
        "inventory": {"packages": True, "services": True, "sockets": True, "max_packages": 10},
        "probes": {"ssh_banner": True, "http_head": True, "tls": True},
        "journal": {"enabled": False, "lines": 10},
        "docker": {"enabled": False},
        "online": {
            "enabled": False,
            "max_requests": 3,
            "cache_ttl_seconds": 60,
            "timeout_seconds": 2.0,
            "nvd_api_key_env": "NVD_API_KEY",
        },
        "reports_dir": directory / "reports",
        "database": directory / "history" / "nour_sentinel_intel.db",
    }


class DashboardTestCase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.config = make_config(temporary.name)

        for patcher in (
            mock.patch.object(authz, "require"),
            mock.patch.object(authz, "is_granted", return_value=True),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

        self.dashboard = dashboard_module.Dashboard(self.config, port=0).bind()
        self.dashboard.start_http()

        worker = threading.Thread(target=self.dashboard.service_jobs, daemon=True)
        worker.start()

        self.addCleanup(self.dashboard.close)

    def _open(self, path, method="GET", payload=None, token=True, origin=None):
        url = f"http://127.0.0.1:{self.dashboard.port}{path}"
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(url, data=data, method=method)

        if data is not None:
            request.add_header("Content-Type", "application/json")
        if token:
            request.add_header("X-Nour-Token", self.dashboard.token)
        if origin:
            request.add_header("Origin", origin)

        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, dict(response.headers), response.read().decode("utf-8")
        except urllib.error.HTTPError as error:
            with error:
                return error.code, dict(error.headers), error.read().decode("utf-8")

    def request(self, path, **kwargs):
        status, headers, text = self._open(path, **kwargs)

        return status, headers, json.loads(text) if text else None


class TestDashboardServing(DashboardTestCase):
    def test_index_is_served_with_a_restrictive_policy(self):
        status, headers, text = self._open("/")

        self.assertEqual(status, 200)
        self.assertIn("NOUR SENTINEL", text)
        self.assertIn("Ondes réseau temps réel", text)
        self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")

    def test_static_assets_only_come_from_the_whitelist(self):
        status, headers, text = self._open("/dashboard.js")

        self.assertEqual(status, 200)
        self.assertIn("text/javascript", headers["Content-Type"])
        self.assertIn("api/run", text)

        status, _, payload = self.request("/dashboard.py")

        self.assertEqual(status, 404)
        self.assertFalse(payload["ok"])

    def test_token_is_never_embedded_in_the_page(self):
        _, _, text = self._open("/")

        self.assertNotIn(self.dashboard.token, text)

    def test_meta_requires_the_session_token(self):
        status, _, payload = self.request("/api/meta", token=False)

        self.assertEqual(status, 401)
        self.assertFalse(payload["ok"])

    def test_meta_describes_profiles_and_limits(self):
        status, _, payload = self.request("/api/meta")

        self.assertEqual(status, 200)
        self.assertEqual(payload["version"], VERSION)
        self.assertEqual(set(payload["profiles"]), {"passif", "standard", "agressif"})
        self.assertEqual(payload["default_profile"], "standard")
        self.assertEqual(payload["limits"]["max_ports_per_protocol"], 32)
        self.assertEqual(payload["authorized_targets"], ["127.0.0.1", "localhost"])

    def test_waves_require_the_token_and_expose_rates(self):
        status, _, payload = self.request("/api/waves", token=False)
        self.assertEqual(status, 401)

        status, _, payload = self.request("/api/waves")

        self.assertEqual(status, 200)
        for key in ("rx_bps", "tx_bps", "rx_pps", "tx_pps", "interfaces", "history"):
            self.assertIn(key, payload)

    def test_unknown_route_is_refused(self):
        status, _, payload = self.request("/api/unknown")

        self.assertEqual(status, 404)
        self.assertFalse(payload["ok"])


class TestDashboardExecution(DashboardTestCase):
    def test_unknown_option_is_refused(self):
        status, _, payload = self.request(
            "/api/run", method="POST", payload={"option": "shell"}
        )

        self.assertEqual(status, 400)
        self.assertFalse(payload["ok"])

    def test_inventory_runs_through_the_authorized_worker(self):
        report = {"mode": "inventory", "findings_count": 0, "findings": []}

        with mock.patch.object(lab, "run_inventory", return_value=report) as run:
            status, _, payload = self.request(
                "/api/run", method="POST", payload={"option": "inventory"}
            )

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["report"]["mode"], "inventory")
        run.assert_called_once_with(self.config)

    def test_scan_requires_the_authorization_checkbox(self):
        with mock.patch.object(network_scan, "scan_target") as scan:
            status, _, payload = self.request(
                "/api/run",
                method="POST",
                payload={"option": "scan", "target": "192.168.1.1", "confirm": False},
            )

        self.assertEqual(status, 403)
        self.assertIn("confirmation", payload["error"])
        scan.assert_not_called()

    def test_scan_forwards_target_profile_and_confirmation(self):
        report = {"mode": "network_scan", "target": "192.168.1.1", "protocols": {"tcp": []}}

        with mock.patch.object(
            network_scan, "scan_target", return_value=report
        ) as scan:
            status, _, payload = self.request(
                "/api/run",
                method="POST",
                payload={
                    "option": "scan",
                    "target": "192.168.1.1",
                    "protocol": "tcp",
                    "profile": "passif",
                    "confirm": True,
                },
            )

        self.assertEqual(status, 200)
        scan.assert_called_once_with(
            "192.168.1.1", protocol="tcp", authorized=True, profile="passif"
        )

    def test_tls_requires_a_valid_port(self):
        status, _, payload = self.request(
            "/api/run",
            method="POST",
            payload={"option": "tls", "target": "127.0.0.1", "port": 0},
        )

        self.assertEqual(status, 400)
        self.assertIn("port invalide", payload["error"])

    def test_cve_without_online_is_refused_before_any_call(self):
        with mock.patch.object(lab, "run_cve_online") as online:
            status, _, payload = self.request(
                "/api/run", method="POST", payload={"option": "cve", "online": False}
            )

        self.assertEqual(status, 403)
        self.assertIn("appel externe", payload["error"])
        online.assert_not_called()

    def test_authorization_failure_is_reported_as_forbidden(self):
        with mock.patch.object(
            lab, "run_inventory", side_effect=authz.AuthorizationError("refusé")
        ):
            status, _, payload = self.request(
                "/api/run", method="POST", payload={"option": "inventory"}
            )

        self.assertEqual(status, 403)
        self.assertFalse(payload["ok"])

    def test_cross_origin_post_is_refused(self):
        status, _, payload = self.request(
            "/api/run",
            method="POST",
            payload={"option": "inventory"},
            origin="http://evil.example",
        )

        self.assertEqual(status, 403)
        self.assertIn("origine", payload["error"])

    def test_post_without_token_is_refused(self):
        status, _, payload = self.request(
            "/api/run", method="POST", payload={"option": "inventory"}, token=False
        )

        self.assertEqual(status, 401)
        self.assertFalse(payload["ok"])


class TestDashboardGuard(unittest.TestCase):
    def test_dashboard_refuses_to_start_without_authentication(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(authz, "is_granted", return_value=False):
                with self.assertRaises(PermissionError):
                    dashboard_module.Dashboard(make_config(directory), port=0)


class TestNetworkWaves(unittest.TestCase):
    def _write(self, path, rx_bytes, tx_bytes):
        path.write_text(
            "Inter-|   Receive                                                |  Transmit\n"
            " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
            f"  eth0: {rx_bytes} 10 0 0 0 0 0 0 {tx_bytes} 20 0 0 0 0 0 0\n",
            encoding="utf-8",
        )

    def test_rates_are_deltas_per_second(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dev"
            self._write(path, 1000, 500)
            waves = dashboard_module.NetworkWaves(path)

            with mock.patch.object(
                dashboard_module.time, "monotonic", side_effect=[100.0, 102.0]
            ):
                waves.sample()
                self._write(path, 3000, 1500)
                sample = waves.sample()

        self.assertAlmostEqual(sample["rx_bps"], 1000.0)
        self.assertAlmostEqual(sample["tx_bps"], 500.0)
        self.assertEqual(sample["interfaces"][0]["name"], "eth0")
        self.assertEqual(len(sample["history"]), 2)

    def test_counter_reset_never_produces_negative_rates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dev"
            self._write(path, 5000, 5000)
            waves = dashboard_module.NetworkWaves(path)

            with mock.patch.object(
                dashboard_module.time, "monotonic", side_effect=[10.0, 11.0]
            ):
                waves.sample()
                self._write(path, 10, 10)
                sample = waves.sample()

        self.assertEqual(sample["rx_bps"], 0.0)
        self.assertEqual(sample["tx_bps"], 0.0)

    def test_missing_file_is_reported_as_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            sample = dashboard_module.NetworkWaves(Path(directory) / "absent").sample()

        self.assertFalse(sample["available"])
        self.assertEqual(sample["interfaces"], [])


class TestDashboardCli(unittest.TestCase):
    def test_dashboard_command_defaults_to_the_local_port(self):
        args = cli.build_parser().parse_args(["dashboard"])

        self.assertEqual(args.command, "dashboard")
        self.assertEqual(args.port, dashboard_module.DEFAULT_PORT)

    def test_dashboard_port_is_validated(self):
        with self.assertRaises(ValueError):
            cli._validate_dashboard_port(0)


if __name__ == "__main__":
    unittest.main()
