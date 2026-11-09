import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))

from intelligence.risk_engine import deduplicate, prioritize, score, summarize


def finding(asset="kali", port=22, check="test", severity="medium", confidence="confirmed", exposure="lan", **extra):
    value = {
        "finding_id": f"f-{asset}-{port}-{check}",
        "asset_id": asset,
        "port": port,
        "check": check,
        "component": "OpenSSH",
        "severity": severity,
        "confidence": confidence,
        "exposure": exposure,
        "evidence": "socket:0.0.0.0:22",
        "status": "open",
        **extra,
    }

    return value


class TestDeduplication(unittest.TestCase):

    def test_keeps_highest_severity(self):
        low = finding(severity="low")
        high = finding(severity="high")

        merged = deduplicate([low, high])

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["severity"], "high")

    def test_distinct_assets_are_kept(self):
        merged = deduplicate([finding(asset="a"), finding(asset="b")])

        self.assertEqual(len(merged), 2)

    def test_distinct_components_are_kept(self):
        first = finding(check="cve.1")
        second = finding(check="cve.2")

        self.assertEqual(len(deduplicate([first, second])), 2)

    def test_identical_finding_is_not_its_own_duplicate(self):
        item = finding()
        merged = deduplicate([item, item])

        self.assertEqual(len(merged), 1)
        self.assertNotIn("duplicates", merged[0].get("metadata") or {})

    def test_distinct_duplicate_identifier_is_recorded_once(self):
        first = finding(severity="high")
        second = finding(severity="low")
        second["finding_id"] = "f-manual-other"

        merged = deduplicate([first, second])

        self.assertEqual(merged[0]["severity"], "high")
        self.assertEqual(
            merged[0]["metadata"]["duplicates"], ["f-manual-other"]
        )


class TestScoring(unittest.TestCase):

    def test_external_exposure_scores_higher(self):
        internal = finding(exposure="local")
        external = finding(exposure="external")

        self.assertGreater(score(external), score(internal))

    def test_kev_adds_weight(self):
        baseline = finding(severity="high")
        exploited = finding(severity="high", kev=True)

        self.assertGreater(score(exploited), score(baseline))

    def test_epss_adds_weight(self):
        self.assertGreater(
            score(finding(severity="medium", epss=0.9)),
            score(finding(severity="medium")),
        )

    def test_low_confidence_reduces_score(self):
        self.assertGreater(
            score(finding(confidence="confirmed")),
            score(finding(confidence="low")),
        )


class TestPrioritization(unittest.TestCase):

    def test_sorted_and_labelled(self):
        critical = finding(check="a", severity="critical", exposure="external")
        info = finding(check="b", severity="info", exposure="local")

        ordered = prioritize([info, critical])

        self.assertEqual(ordered[0]["check"], "a")
        self.assertEqual(ordered[0]["priority"], "P1")
        self.assertEqual(ordered[1]["priority"], "P4")
        self.assertIn("priority_score", ordered[1])

    def test_empty_input(self):
        self.assertEqual(prioritize([]), [])


class TestSummary(unittest.TestCase):

    def test_counts_by_severity_and_evidence(self):
        summary = summarize(
            [
                finding(severity="high"),
                finding(severity="info"),
                {**finding(severity="low"), "evidence": ""},
            ]
        )

        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["by_severity"]["high"], 1)
        self.assertEqual(summary["with_evidence"], 2)
        self.assertEqual(summary["without_evidence"], 1)
        self.assertEqual(summary["by_priority"]["P4"], 1)


if __name__ == "__main__":
    unittest.main()
