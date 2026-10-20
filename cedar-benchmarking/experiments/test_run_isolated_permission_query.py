"""Tests of isolated benchmark process accounting; no Cedar binary needed."""

import json
import unittest
from pathlib import Path
from unittest.mock import patch
import run_isolated_permission_query as runner


def fake_result(size):
    row = {
        "documents": size,
        "trials": 3,
        "query_resource": {"mean_us": 120.0},
        "query_resource_prepared": {"mean_us": 60.0},
        "snapshot_preparation_us": 180.0,
        "rss_before_preparation_kib": 7000,
        "rss_after_preparation_kib": 7150,
    }
    return type("Proc", (), {"stdout": json.dumps({"cedar_version": "test", "rows": [row]})})()


class IsolatedBenchTests(unittest.TestCase):
    def test_distinct_process_for_each_size_and_correct_accounting(self):
        with patch.object(runner.subprocess, "run", side_effect=[
            fake_result(100), fake_result(1000),
        ]) as run:
            report = runner.measure([100, 1000], Path("/bin/bench"), 3, 1)
        self.assertEqual(run.call_count, 2)
        self.assertEqual([r["size"] for r in report["results"]], [100, 1000])
        self.assertEqual(report["results"][0]["derived"]["mean_speedup"], 2)
        self.assertEqual(report["results"][0]["derived"]["rss_change_kib"], 150)
        self.assertEqual(report["results"][0]["derived"]["estimated_minimum_queries_to_amortize"], 4)
        self.assertEqual(report["protocol"], "isolated-one-process-per-workload-size")
        self.assertIn("--sizes", run.call_args_list[0].args[0])

    def test_mismatched_size_is_a_hard_failure(self):
        with patch.object(runner.subprocess, "run", return_value=fake_result(100)):
            with self.assertRaisesRegex(ValueError, "unexpected result"):
                runner.measure([1000], Path("/bin/bench"), 3, 1)

    def test_invalid_counts_fail_before_launch(self):
        with patch.object(runner.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                runner.measure([0], Path("/bin/bench"), 3, 1)
            with self.assertRaises(ValueError):
                runner.measure([1], Path("/bin/bench"), 0, 1)
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
