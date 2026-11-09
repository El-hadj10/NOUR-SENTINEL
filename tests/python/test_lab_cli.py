import contextlib
import io
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))

import authz
from security_intelligence import VERSION, auth_gate, cli, lab, network_scan
from security_intelligence import config as config_module


class TestCli(unittest.TestCase):
    def setUp(self):
        authorization = mock.patch.object(authz, "require")
        authorization.start()
        self.addCleanup(authorization.stop)

    def test_operational_command_requires_authentication_before_config(self):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with mock.patch.object(
            auth_gate,
            "authenticate",
            side_effect=auth_gate.AuthError("authentification refusée"),
        ):
            with mock.patch.object(config_module, "load_config") as load_config:
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(
                    stderr
                ):
                    status = cli.main(["inventory"])

        self.assertEqual(status, 2)
        self.assertIn("AUTH ERROR", stderr.getvalue())
        self.assertEqual(stdout.getvalue(), "")
        load_config.assert_not_called()

    def test_inventory_command_returns_json_after_authentication(self):
        report = {
            "version": VERSION,
            "mode": "inventory",
            "findings": [],
            "findings_count": 0,
            "risk_summary": {"total": 0, "with_evidence": 0},
            "errors": [],
        }

        stdout = io.StringIO()
        stderr = io.StringIO()

        with mock.patch.object(auth_gate, "authenticate", return_value=True):
            with mock.patch.object(lab, "run_inventory", return_value=report):
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(
                    stderr
                ):
                    status = cli.main(["inventory"])

        self.assertEqual(status, 0)
        parsed = json.loads(stdout.getvalue())
        self.assertEqual(parsed["version"], VERSION)
        self.assertIn("[LAB] mode=inventory", stderr.getvalue())

    def test_cve_without_online_is_refused(self):
        stderr = io.StringIO()

        with mock.patch.object(auth_gate, "authenticate", return_value=True):
            with contextlib.redirect_stderr(stderr):
                status = cli.main(["cve"])

        self.assertEqual(status, 3)
        self.assertIn("--online", stderr.getvalue())

    def test_invalid_port_is_refused(self):
        stderr = io.StringIO()

        with mock.patch.object(auth_gate, "authenticate", return_value=True):
            with contextlib.redirect_stderr(stderr):
                status = cli.main(["tls", "--target", "127.0.0.1", "--port", "0"])

        self.assertEqual(status, 1)
        self.assertIn("port TCP invalide", stderr.getvalue())

    def test_discover_returns_passive_report_without_probing(self):
        report = {
            "mode": "network_discovery",
            "neighbor_count": 0,
            "neighbors": [],
            "active_probes": False,
        }
        stdout = io.StringIO()
        stderr = io.StringIO()

        with mock.patch.object(auth_gate, "authenticate", return_value=True):
            with mock.patch.object(config_module, "load_config", return_value={}):
                with mock.patch.object(
                    network_scan, "discover_neighbors", return_value=report
                ) as discover:
                    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(
                        stderr
                    ):
                        status = cli.main(["discover"])

        self.assertEqual(status, 0)
        discover.assert_called_once_with()
        self.assertEqual(json.loads(stdout.getvalue())["mode"], "network_discovery")
        self.assertIn(
            "mode=network_discovery voisins=0 sondes_actives=non",
            stderr.getvalue(),
        )

    def test_scan_without_confirmation_is_refused_before_arp_read(self):
        stderr = io.StringIO()

        with mock.patch.object(auth_gate, "authenticate", return_value=True):
            with mock.patch.object(config_module, "load_config", return_value={}):
                with mock.patch.object(network_scan, "parse_arp_table") as arp:
                    with contextlib.redirect_stderr(stderr):
                        status = cli.main(["scan", "--target", "192.168.1.1"])

        self.assertEqual(status, 3)
        self.assertIn("--confirm-authorized", stderr.getvalue())
        arp.assert_not_called()

    def test_scan_refuses_ports_of_the_other_protocol(self):
        stderr = io.StringIO()

        with mock.patch.object(auth_gate, "authenticate", return_value=True):
            with mock.patch.object(config_module, "load_config", return_value={}):
                with contextlib.redirect_stderr(stderr):
                    status = cli.main(
                        [
                            "scan",
                            "--target",
                            "192.168.1.1",
                            "--protocol",
                            "tcp",
                            "--udp-ports",
                            "53",
                        ]
                    )

        self.assertEqual(status, 1)
        self.assertIn("--udp-ports nécessite", stderr.getvalue())

    def test_scan_passes_only_the_selected_ports_and_confirmation(self):
        report = {
            "mode": "network_scan",
            "target": "192.168.1.1",
            "protocols": {"tcp": [{"port": 22, "state": "open"}, {"port": 80, "state": "closed"}]},
            "limits": {"max_ports_per_protocol": 32, "timeout_seconds": 0.5},
            "udp_note": "open_or_filtered est ambigu",
        }
        stdout = io.StringIO()
        stderr = io.StringIO()

        with mock.patch.object(auth_gate, "authenticate", return_value=True):
            with mock.patch.object(config_module, "load_config", return_value={}):
                with mock.patch.object(
                    network_scan, "scan_target", return_value=report
                ) as scan:
                    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(
                        stderr
                    ):
                        status = cli.main(
                            [
                                "scan",
                                "--target",
                                "192.168.1.1",
                                "--protocol",
                                "tcp",
                                "--tcp-ports",
                                "22,80",
                                "--confirm-authorized",
                            ]
                        )

        self.assertEqual(status, 0)
        scan.assert_called_once_with(
            "192.168.1.1",
            protocol="tcp",
            tcp_ports=(22, 80),
            udp_ports=None,
            authorized=True,
            profile="standard",
        )
        self.assertEqual(json.loads(stdout.getvalue())["target"], "192.168.1.1")
        self.assertIn(
            "mode=network_scan cible=192.168.1.1 ports={'tcp': 2}",
            stderr.getvalue(),
        )
    def test_scan_forwards_the_selected_profile(self):
        report = {
            "mode": "network_scan",
            "target": "192.168.1.1",
            "protocols": {"tcp": []},
            "limits": {
                "profile": "agressif",
                "max_ports_per_protocol": 32,
                "timeout_seconds": 0.25,
                "concurrency": 4,
            },
            "udp_note": "open_or_filtered est ambigu",
        }
        stdout = io.StringIO()
        stderr = io.StringIO()

        with mock.patch.object(auth_gate, "authenticate", return_value=True):
            with mock.patch.object(config_module, "load_config", return_value={}):
                with mock.patch.object(
                    network_scan, "scan_target", return_value=report
                ) as scan:
                    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(
                        stderr
                    ):
                        status = cli.main(
                            [
                                "scan",
                                "--target",
                                "192.168.1.1",
                                "--protocol",
                                "tcp",
                                "--profile",
                                "agressif",
                                "--confirm-authorized",
                            ]
                        )

        self.assertEqual(status, 0)
        scan.assert_called_once_with(
            "192.168.1.1",
            protocol="tcp",
            tcp_ports=None,
            udp_ports=None,
            authorized=True,
            profile="agressif",
        )
        self.assertEqual(json.loads(stdout.getvalue())["limits"]["profile"], "agressif")


if __name__ == "__main__":
    unittest.main()
