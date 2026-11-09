import sys
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import authz
from lab_helpers import AuthorizedTestCase
from security_intelligence import network_scan


ARP_TABLE = """IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         02:00:00:00:00:01     *        wlan0
192.168.1.25     0x1         0x2         02:00:00:00:00:25     *        wlan0
192.168.1.26     0x1         0x0         02:00:00:00:00:26     *        wlan0
8.8.8.8          0x1         0x2         02:00:00:00:00:88     *        wlan0
127.0.0.1        0x1         0x2         02:00:00:00:00:01     *        lo
"""


class TestArpParsing(unittest.TestCase):
    def test_only_complete_unicast_ipv4_neighbors_are_returned(self):
        self.assertEqual(
            network_scan.parse_arp_table(ARP_TABLE),
            [
                {"ip": "192.168.1.1", "interface": "wlan0"},
                {"ip": "192.168.1.25", "interface": "wlan0"},
            ],
        )

    def test_empty_and_malformed_tables_are_safe(self):
        self.assertEqual(network_scan.parse_arp_table(""), [])
        self.assertEqual(
            network_scan.parse_arp_table("header\nnot an arp row\n"), []
        )

    def test_ports_are_deduplicated_and_strictly_bounded(self):
        self.assertEqual(
            network_scan.parse_ports("80,443,80", (), "TCP"), (80, 443)
        )

        for invalid in ("0", "65536", "80-90", "80,"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                network_scan.parse_ports(invalid, (), "TCP")

        too_many = ",".join(str(port) for port in range(1, 34))
        with self.assertRaises(ValueError):
            network_scan.parse_ports(too_many, (), "TCP")


class TestNetworkScan(AuthorizedTestCase):
    def setUp(self):
        super().setUp()
        self.neighbors = mock.patch.object(
            network_scan, "_read_neighbors", return_value=network_scan.parse_arp_table(ARP_TABLE)
        )
        self.neighbors.start()
        self.addCleanup(self.neighbors.stop)

    def test_discovery_is_passive_and_does_not_expose_mac_addresses(self):
        result = network_scan.discover_neighbors()

        self.assertFalse(result["active_probes"])
        self.assertEqual(result["neighbor_count"], 2)
        self.assertNotIn("mac", result["neighbors"][0])

    def test_target_must_be_one_discovered_ipv4_before_any_probe(self):
        with mock.patch.object(network_scan.socket, "create_connection") as connect:
            with self.assertRaises(PermissionError):
                network_scan.scan_target(
                    "192.168.1.99",
                    protocol="tcp",
                    tcp_ports=(80,),
                    authorized=True,
                )

        connect.assert_not_called()

    def test_scan_requires_explicit_authorization_before_arp_read(self):
        self.neighbors.stop()

        with mock.patch.object(network_scan, "_read_neighbors") as read_neighbors:
            with self.assertRaises(PermissionError):
                network_scan.scan_target("192.168.1.25")

        read_neighbors.assert_not_called()

    def test_tcp_scan_uses_only_selected_host_and_ports(self):
        connection = mock.Mock()
        with mock.patch.object(
            network_scan.socket, "create_connection", return_value=connection
        ) as connect:
            result = network_scan.scan_target(
                "192.168.1.25",
                protocol="tcp",
                tcp_ports=(80, 443),
                authorized=True,
            )

        self.assertEqual(
            result["protocols"]["tcp"],
            [{"port": 80, "state": "open"}, {"port": 443, "state": "open"}],
        )
        self.assertEqual(connect.call_count, 2)
        self.assertEqual(connect.call_args_list[0].args[0], ("192.168.1.25", 80))
        self.assertEqual(connection.close.call_count, 2)

    def test_udp_timeout_is_reported_as_ambiguous(self):
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        connection.recv.side_effect = TimeoutError
        with mock.patch.object(network_scan.socket, "socket", return_value=connection):
            result = network_scan.scan_target(
                "192.168.1.25",
                protocol="udp",
                udp_ports=(53,),
                authorized=True,
            )

        self.assertEqual(
            result["protocols"]["udp"],
            [{"port": 53, "state": "open_or_filtered"}],
        )


if __name__ == "__main__":
    unittest.main()
