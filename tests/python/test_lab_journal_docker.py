import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lab_helpers import AuthorizedTestCase, make_config
from security_intelligence.applications import docker
from security_intelligence.intrusion import journal


def journal_runner():
    entries = []

    for index in range(5):
        entries.append(
            {
                "__REALTIME_TIMESTAMP": str(1_700_000_000_000_000 + index * 1_000_000),
                "MESSAGE": "Failed password for root from 203.0.113.5 port 22 ssh2",
            }
        )

    entries.append(
        {
            "__REALTIME_TIMESTAMP": "1700000010000000",
            "MESSAGE": "Accepted publickey for root from 203.0.113.5 port 22 ssh2",
        }
    )

    def runner(argv, timeout=20):
        return {
            "returncode": 0,
            "stdout": "\n".join(json.dumps(entry) for entry in entries),
            "stderr": "",
        }

    return runner


class TestJournal(AuthorizedTestCase):
    def test_aggregates_without_exporting_raw_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)
            findings, metadata, errors = journal.collect(
                config, "localhost", runner=journal_runner()
            )

            serialized = json.dumps(findings)
            checks = {finding["check"] for finding in findings}

            self.assertIn("intrusion.ssh_failure_burst", checks)
            self.assertNotIn("Failed password", serialized)
            self.assertNotIn("Accepted publickey", serialized)
            self.assertTrue(
                all(
                    finding["metadata"].get("raw_logs") == "not_exported"
                    for finding in findings
                )
            )
            self.assertEqual(metadata["entries"], 6)
            self.assertEqual(errors, [])

    def test_journal_failure_is_reported(self):
        def runner(argv, timeout=20):
            return {"returncode": 1, "stdout": "", "stderr": "accès refusé"}

        with tempfile.TemporaryDirectory() as directory:
            findings, metadata, errors = journal.collect(
                make_config(directory), "localhost", runner=runner
            )

            self.assertEqual(findings, [])
            self.assertEqual(metadata["entries"], 0)
            self.assertIn("journalctl", errors[0])


class TestDocker(AuthorizedTestCase):
    def test_parses_and_flags_wildcard_publication(self):
        container = {
            "ID": "a" * 64,
            "Names": "web",
            "Image": "nginx:latest",
            "State": "running",
            "Status": "Up 2 hours",
            "Ports": "0.0.0.0:8080->80/tcp, [::]:8080->80/tcp",
        }

        def runner(argv, timeout=15):
            return {
                "returncode": 0,
                "stdout": json.dumps(container),
                "stderr": "",
            }

        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)
            config["docker"]["enabled"] = True
            findings, metadata, errors = docker.collect(
                config, "localhost", runner=runner
            )

            checks = {finding["check"] for finding in findings}

            self.assertIn("docker.container", checks)
            self.assertIn("docker.published_port", checks)
            self.assertEqual(len(metadata["containers"]), 1)
            self.assertEqual(metadata["containers"][0]["name"], "web")
            self.assertEqual(errors, [])

    def test_docker_failure_is_reported(self):
        def runner(argv, timeout=15):
            return {"returncode": 1, "stdout": "", "stderr": "permission denied"}

        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)
            config["docker"]["enabled"] = True
            findings, metadata, errors = docker.collect(
                config, "localhost", runner=runner
            )

            self.assertEqual(findings, [])
            self.assertEqual(metadata["containers"], [])
            self.assertIn("docker ps", errors[0])


if __name__ == "__main__":
    unittest.main()
