"""P0.3 — preuves que toute collecte est instrumentée et bloquée avant auth.

Chaque point de collecte est recensé dans ``EXPECTED_SITES``. Le test vérifie
d'abord que le registre d'instrumentation correspond exactement à cette liste,
puis appelle chaque point sans autorisation en instrumentant les puits réels
(`subprocess`, sockets, HTTP, SQLite, rapport). Aucun puits ne doit être
atteint : le refus intervient avant le corps de la fonction.
"""

import sqlite3
import subprocess
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import authz
from intelligence import engine
from intelligence.applications import http_analyzer
from intelligence.fingerprinting import services
from intelligence.tls import analyzer as stable_tls
from intelligence.tools import adapters
from intelligence.vulnerabilities import clients
from lab_helpers import AuthorizedTestCase, make_config
from security_intelligence import collection_trace, lab, network_scan, reports
from security_intelligence.applications import docker
from security_intelligence.fingerprinting import inventory, service_probe
from security_intelligence.intrusion import journal
from security_intelligence.passwords import policy
from security_intelligence.store import IntelStore
from security_intelligence.tls import analyzer as tls_analyzer
from security_intelligence.vulnerabilities import online

EXPECTED_SITES = {
    "system": {
        "inventory.read_os_release",
        "inventory.list_packages",
        "inventory.list_services",
        "inventory.list_listeners",
        "inventory.collect",
        "policy.read_effective_sshd",
        "policy.collect",
        "journal.collect",
        "engine._journal_findings",
        "inventory.run_command",
    },
    "application": {
        "docker.collect",
    },
    "tcp": {
        "tls.negotiate",
        "tls.read_certificate",
        "tls.audit",
        "service_probe.probe_ssh",
        "service_probe.probe_http",
        "engine.active_checks",
        "http_analyzer.probe_http",
        "tls.inspect",
        "services.probe_banner",
    },
    "external": {
        "online._json",
        "online.query_osv",
        "online.nvd_keyword",
        "online.kev_catalog",
        "online.epss_scores",
        "online.nvd_findings",
        "online.assess_packages",
        "online.UrllibTransport.fetch",
        "clients._get_json",
        "clients.query_osv",
    },
    "tool": {
        "engine.collect_tool_findings",
        "adapters.run_tool",
    },
    "report": {
        "reports.ensure_private_directory",
        "reports.write_report",
    },
    "sqlite": {
        "store.IntelStore.__init__",
        "store.save_run",
        "store.attach_report",
    },
    "analysis": {
        "engine.analyze",
    },
    "operation": {
        "lab.finalize",
        "lab.run_inventory",
        "lab.run_full_local",
        "lab.run_fingerprint",
        "lab.run_tls",
        "lab.run_cve_online",
        "network_scan.discover_neighbors",
        "network_scan.scan_target",
    },
}


def expected_registry():
    return {
        site: category
        for category, sites in EXPECTED_SITES.items()
        for site in sites
    }


def build_calls(config):
    """Un appel concret par point instrumenté, sans effet avant le décorateur."""

    client = online.OnlineIntel(
        config,
        transport=mock.Mock(),
        cache=mock.Mock(),
        budget=online.Budget(1),
    )
    detached_store = IntelStore.__new__(IntelStore)

    return {
        "inventory.read_os_release": lambda: inventory.read_os_release(),
        "inventory.list_packages": lambda: inventory.list_packages(),
        "inventory.list_services": lambda: inventory.list_services(),
        "inventory.list_listeners": lambda: inventory.list_listeners(),
        "inventory.collect": lambda: inventory.collect(config),
        "policy.read_effective_sshd": lambda: policy.read_effective_sshd(),
        "policy.collect": lambda: policy.collect(config, "localhost"),
        "journal.collect": lambda: journal.collect(config, "localhost"),
        "engine._journal_findings": lambda: engine._journal_findings(
            {"journal_audit": False}, "lab-host"
        ),
        "inventory.run_command": lambda: inventory.run_command(["true"]),
        "docker.collect": lambda: docker.collect(config, "localhost"),
        "tls.negotiate": lambda: tls_analyzer.negotiate(
            "127.0.0.1", 443, "tls1.2"
        ),
        "tls.read_certificate": lambda: tls_analyzer.read_certificate(
            "127.0.0.1", 443
        ),
        "tls.audit": lambda: tls_analyzer.audit(
            "127.0.0.1", 443, allowed=("127.0.0.1",)
        ),
        "service_probe.probe_ssh": lambda: service_probe.probe_ssh(
            "127.0.0.1", 22, allowed=("127.0.0.1",)
        ),
        "service_probe.probe_http": lambda: service_probe.probe_http(
            "127.0.0.1", 80, allowed=("127.0.0.1",)
        ),
        "engine.active_checks": lambda: engine.active_checks(
            {"listeners": []}, {}, [], "lab-host"
        ),
        "http_analyzer.probe_http": lambda: http_analyzer.probe_http(
            "127.0.0.1", 80
        ),
        "tls.inspect": lambda: stable_tls.inspect("127.0.0.1", 443),
        "services.probe_banner": lambda: services.probe_banner(
            "127.0.0.1", 22
        ),
        "online._json": lambda: client._json("GET", "https://example.invalid/"),
        "online.query_osv": lambda: client.query_osv("openssh-server", "9.6"),
        "online.nvd_keyword": lambda: client.nvd_keyword("OpenSSH"),
        "online.kev_catalog": lambda: client.kev_catalog(),
        "online.epss_scores": lambda: client.epss_scores(["CVE-2026-0001"]),
        "online.nvd_findings": lambda: client.nvd_findings("lab-host", "OpenSSH"),
        "online.assess_packages": lambda: client.assess_packages(
            "lab-host", [{"package": "openssh-server", "version": "9.6"}]
        ),
        "online.UrllibTransport.fetch": lambda: online.UrllibTransport().fetch(
            "GET", "https://example.invalid/"
        ),
        "clients._get_json": lambda: clients._get_json(
            "https://example.invalid/"
        ),
        "clients.query_osv": lambda: clients.query_osv(
            "openssh-server", "9.6"
        ),
        "engine.collect_tool_findings": lambda: engine.collect_tool_findings(
            {"enabled": False}, {"listeners": []}, [], "lab-host"
        ),
        "adapters.run_tool": lambda: adapters.run_tool(
            ["nour-sentinel-does-not-exist"]
        ),
        "reports.ensure_private_directory": lambda: reports.ensure_private_directory(
            Path(config["reports_dir"])
        ),
        "reports.write_report": lambda: reports.write_report(
            {}, config["reports_dir"]
        ),
        "store.IntelStore.__init__": lambda: IntelStore(config["database"]),
        "store.save_run": lambda: IntelStore.save_run(detached_store, {}),
        "store.attach_report": lambda: IntelStore.attach_report(
            detached_store, 1, "/tmp/report.json"
        ),
        "engine.analyze": lambda: engine.analyze({}),
        "lab.finalize": lambda: lab.finalize("inventory", config, [], []),
        "lab.run_inventory": lambda: lab.run_inventory(config),
        "lab.run_full_local": lambda: lab.run_full_local(config),
        "lab.run_fingerprint": lambda: lab.run_fingerprint(
            config, "127.0.0.1", 22, "ssh"
        ),
        "lab.run_tls": lambda: lab.run_tls(config, "127.0.0.1", 443),
        "lab.run_cve_online": lambda: lab.run_cve_online(
            config, "openssh-server", "9.6"
        ),
        "network_scan.discover_neighbors": lambda: network_scan.discover_neighbors(),
        "network_scan.scan_target": lambda: network_scan.scan_target(
            "192.168.1.10",
            protocol="tcp",
            tcp_ports=(80,),
            authorized=True,
        ),
    }


class TestCollectionInstrumentation(unittest.TestCase):
    def setUp(self):
        authz.reset()
        collection_trace.reset()

    def tearDown(self):
        authz.reset()
        collection_trace.reset()

    def test_registry_matches_every_collection_entrypoint(self):
        self.assertEqual(collection_trace.sites(), expected_registry())
        self.assertEqual(
            set(collection_trace.CATEGORIES),
            set(EXPECTED_SITES),
        )

    def test_no_sink_is_reached_without_authorization(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)
            calls = build_calls(config)

            self.assertEqual(set(calls), set(expected_registry()))

            with mock.patch.object(subprocess, "run") as run, mock.patch(
                "socket.create_connection"
            ) as connect, mock.patch("socket.socket") as socket_factory, mock.patch.object(
                urllib.request, "urlopen"
            ) as urlopen, mock.patch.object(
                sqlite3, "connect"
            ) as sqlite_connect, mock.patch(
                "tempfile.mkstemp"
            ) as mkstemp, mock.patch(
                "os.replace"
            ) as replace:
                for site, call in calls.items():
                    authz.reset()

                    with self.subTest(site=site):
                        with self.assertRaises(authz.AuthorizationError):
                            call()

                        self.assertFalse(collection_trace.started(site))

                run.assert_not_called()
                connect.assert_not_called()
                socket_factory.assert_not_called()
                urlopen.assert_not_called()
                sqlite_connect.assert_not_called()
                mkstemp.assert_not_called()
                replace.assert_not_called()

            self.assertEqual(collection_trace.events("start"), ())

            for site in expected_registry():
                self.assertTrue(
                    any(
                        event["site"] == site and event["phase"] == "attempt"
                        for event in collection_trace.events()
                    ),
                    msg=f"aucune tentative instrumentée pour {site}",
                )

            self.assertFalse((Path(directory) / "reports").exists())
            self.assertFalse((Path(directory) / "history").exists())

    def test_report_database_and_cache_are_not_created_before_auth(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)

            with self.assertRaises(authz.AuthorizationError):
                lab.run_inventory(config)

            with self.assertRaises(authz.AuthorizationError):
                reports.write_report({}, Path(directory) / "reports")

            with self.assertRaises(authz.AuthorizationError):
                IntelStore(Path(directory) / "history" / "intel.db")

            with self.assertRaises(authz.AuthorizationError):
                online.OnlineIntel(config)

            self.assertFalse((Path(directory) / "reports").exists())
            self.assertFalse((Path(directory) / "history").exists())
            self.assertFalse((Path(directory) / "cache").exists())

    def test_external_tool_is_never_launched_before_auth(self):
        with mock.patch.object(subprocess, "run") as run:
            with self.assertRaises(authz.AuthorizationError):
                engine.collect_tool_findings(
                    {"enabled": True, "nmap": True},
                    {
                        "listeners": [
                            {"address": "127.0.0.1", "port": 22}
                        ]
                    },
                    ["127.0.0.1"],
                    "lab-host",
                )

            run.assert_not_called()

        self.assertFalse(collection_trace.started("engine.collect_tool_findings"))
        self.assertTrue(
            any(
                event["site"] == "engine.collect_tool_findings"
                and event["phase"] == "attempt"
                for event in collection_trace.events()
            )
        )


class TestInstrumentedStart(AuthorizedTestCase):
    def setUp(self):
        super().setUp()
        collection_trace.reset()

    def tearDown(self):
        collection_trace.reset()
        super().tearDown()

    def test_authorized_site_records_start(self):
        inventory.read_os_release()

        self.assertTrue(collection_trace.started("inventory.read_os_release"))
        self.assertEqual(
            [
                event["phase"]
                for event in collection_trace.events()
                if event["site"] == "inventory.read_os_release"
            ],
            ["attempt", "start"],
        )


if __name__ == "__main__":
    unittest.main()
