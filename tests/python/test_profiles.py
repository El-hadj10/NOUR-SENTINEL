import sys
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lab_helpers import AuthorizedTestCase
from security_intelligence import lab, network_scan, profiles

ARP_TABLE = """IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         02:00:00:00:00:01     *        wlan0
192.168.1.25     0x1         0x2         02:00:00:00:00:25     *        wlan0
"""


class TestProfileDictionary(unittest.TestCase):
    def test_profiles_are_complete_and_bounded(self):
        self.assertEqual(
            tuple(profiles.PROFILES), ("passif", "standard", "agressif")
        )

        for name, profile in profiles.PROFILES.items():
            with self.subTest(profile=name):
                self.assertEqual(profile["name"], name)

                for key in ("tcp_ports", "udp_ports"):
                    ports = profile[key]
                    self.assertTrue(ports)
                    self.assertEqual(len(ports), len(set(ports)))
                    self.assertLessEqual(
                        len(ports), network_scan.MAX_PORTS_PER_PROTOCOL
                    )
                    self.assertTrue(all(1 <= port <= 65535 for port in ports))

                self.assertGreater(profile["timeout_factor"], 0)
                self.assertGreaterEqual(profile["concurrency"], 1)
                self.assertLessEqual(
                    profile["concurrency"], profiles.MAX_CONCURRENCY
                )

    def test_aggressive_is_faster_and_more_parallel_than_passive(self):
        passive = profiles.PROFILES["passif"]
        aggressive = profiles.PROFILES["agressif"]

        self.assertGreater(
            passive["timeout_factor"], aggressive["timeout_factor"]
        )
        self.assertLess(passive["concurrency"], aggressive["concurrency"])
        self.assertLessEqual(
            len(passive["tcp_ports"]), len(aggressive["tcp_ports"])
        )

    def test_default_profile_is_standard(self):
        self.assertIs(profiles.resolve_profile(None), profiles.PROFILES["standard"])

    def test_unknown_profile_is_refused(self):
        for invalid in ("furtif", "", "  "):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                profiles.resolve_profile(invalid)


class TestScanProfiles(AuthorizedTestCase):
    def setUp(self):
        super().setUp()
        self.neighbors = mock.patch.object(
            network_scan,
            "_read_neighbors",
            return_value=network_scan.parse_arp_table(ARP_TABLE),
        )
        self.neighbors.start()
        self.addCleanup(self.neighbors.stop)

    def test_passive_profile_uses_its_ports_and_limits(self):
        with mock.patch.object(
            network_scan.socket,
            "create_connection",
            side_effect=ConnectionRefusedError,
        ) as connect:
            result = network_scan.scan_target(
                "192.168.1.25",
                protocol="tcp",
                profile="passif",
                authorized=True,
            )

        self.assertEqual(
            [entry["port"] for entry in result["protocols"]["tcp"]],
            list(profiles.PROFILES["passif"]["tcp_ports"]),
        )
        self.assertEqual(result["limits"]["profile"], "passif")
        self.assertEqual(result["limits"]["timeout_seconds"], 1.0)
        self.assertEqual(result["limits"]["concurrency"], 1)
        self.assertEqual(
            connect.call_count, len(profiles.PROFILES["passif"]["tcp_ports"])
        )

    def test_aggressive_profile_is_parallel_but_still_bounded(self):
        with mock.patch.object(
            network_scan.socket, "create_connection", return_value=mock.Mock()
        ) as connect:
            result = network_scan.scan_target(
                "192.168.1.25",
                protocol="tcp",
                profile="agressif",
                authorized=True,
            )

        self.assertEqual(result["limits"]["profile"], "agressif")
        self.assertEqual(result["limits"]["timeout_seconds"], 0.25)
        self.assertEqual(result["limits"]["concurrency"], 4)
        self.assertLessEqual(
            len(result["protocols"]["tcp"]), network_scan.MAX_PORTS_PER_PROTOCOL
        )
        self.assertEqual(
            connect.call_count, len(profiles.PROFILES["agressif"]["tcp_ports"])
        )

    def test_explicit_ports_override_profile(self):
        with mock.patch.object(
            network_scan.socket,
            "create_connection",
            side_effect=ConnectionRefusedError,
        ):
            result = network_scan.scan_target(
                "192.168.1.25",
                protocol="tcp",
                tcp_ports=(22,),
                profile="agressif",
                authorized=True,
            )

        self.assertEqual(
            [entry["port"] for entry in result["protocols"]["tcp"]], [22]
        )

    def test_aggressive_profile_cannot_exceed_32_ports(self):
        with mock.patch.object(network_scan.socket, "create_connection") as connect:
            with self.assertRaises(ValueError):
                network_scan.scan_target(
                    "192.168.1.25",
                    protocol="tcp",
                    tcp_ports=tuple(range(1, 34)),
                    profile="agressif",
                    authorized=True,
                )

        connect.assert_not_called()

    def test_aggressive_profile_does_not_bypass_arp_selection(self):
        with mock.patch.object(network_scan.socket, "create_connection") as connect:
            with self.assertRaises(PermissionError):
                network_scan.scan_target(
                    "192.168.1.99",
                    protocol="tcp",
                    profile="agressif",
                    authorized=True,
                )

        connect.assert_not_called()

    def test_profile_does_not_skip_confirmation_before_arp_read(self):
        self.neighbors.stop()

        with mock.patch.object(network_scan, "_read_neighbors") as read_neighbors:
            with self.assertRaises(PermissionError):
                network_scan.scan_target(
                    "192.168.1.25", profile="agressif", authorized=False
                )

        read_neighbors.assert_not_called()


class TestProbeProfiles(AuthorizedTestCase):
    def test_fingerprint_uses_profile_timeout_and_records_it(self):
        config = {"authorized_targets": ("192.168.1.25",), "timeout": 2.0}

        with mock.patch.object(
            lab.service_probe, "probe_ssh", return_value=([], [])
        ) as probe:
            with mock.patch.object(
                lab, "finalize", side_effect=lambda *args, **kwargs: kwargs["metadata"]
            ):
                metadata = lab.run_fingerprint(
                    config, "192.168.1.25", 22, protocol="ssh", profile="agressif"
                )

        probe.assert_called_once_with(
            "192.168.1.25", 22, timeout=1.0, allowed=("192.168.1.25",)
        )
        self.assertEqual(metadata["profile"], "agressif")

    def test_tls_uses_profile_timeout_and_records_it(self):
        config = {
            "authorized_targets": ("192.168.1.25",),
            "timeout": 2.0,
            "probes": {"tls": True},
        }

        with mock.patch.object(
            lab.tls_analyzer, "audit", return_value=([], {}, [])
        ) as audit:
            with mock.patch.object(
                lab, "finalize", side_effect=lambda *args, **kwargs: kwargs["metadata"]
            ):
                metadata = lab.run_tls(
                    config, "192.168.1.25", 443, profile="agressif"
                )

        audit.assert_called_once_with(
            "192.168.1.25", 443, timeout=1.0, allowed=("192.168.1.25",)
        )
        self.assertEqual(metadata["profile"], "agressif")

    def test_unknown_profile_is_refused_before_any_probe(self):
        config = {"authorized_targets": ("192.168.1.25",), "timeout": 2.0}

        with mock.patch.object(lab.service_probe, "probe_ssh") as probe:
            with self.assertRaises(ValueError):
                lab.run_fingerprint(
                    config, "192.168.1.25", 22, protocol="ssh", profile="furtif"
                )

        probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
