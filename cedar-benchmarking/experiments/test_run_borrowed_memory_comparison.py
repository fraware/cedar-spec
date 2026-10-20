"""Independent-process memory harness tests."""

import json
import unittest
from pathlib import Path
from unittest.mock import patch

import run_borrowed_memory_comparison as m


def payload(mode, n):
    delta = 120 if mode == "owned" else 80
    return type("Result", (), {"stdout": json.dumps({
        "snapshot_mode": mode, "documents": n, "authorized": 7,
        "rss_before_kib": 10000, "rss_after_kib": 10000 + delta,
        "snapshot_preparation_us": 300 if mode == "owned" else 250,
    })})()


class MemoryComparisonTests(unittest.TestCase):
    def test_independent_processes_and_median(self):
        with patch.object(m.subprocess, "run", side_effect=[
            payload("owned", 10), payload("borrowed", 10),
            payload("borrowed", 10), payload("owned", 10),
            payload("owned", 10), payload("borrowed", 10),
        ]) as cmd:
            output = m.compare(Path("/fake/benchmark"), [10], 3)
        self.assertEqual(cmd.call_count, 6)
        self.assertEqual(output["aggregates"][0]["owned_median_rss_delta_kib"], 120)
        self.assertEqual(output["aggregates"][0]["borrowed_median_rss_delta_kib"], 80)

    def test_mismatched_variant_fails(self):
        with patch.object(m.subprocess, "run", return_value=payload("borrowed", 10)):
            with self.assertRaisesRegex(ValueError, "variant"):
                m.compare(Path("/fake/benchmark"), [10], 1)

    def test_invalid_parameters_do_not_launch_processes(self):
        with patch.object(m.subprocess, "run") as cmd:
            with self.assertRaises(ValueError):
                m.compare(Path("/fake/benchmark"), [0], 3)
            with self.assertRaises(ValueError):
                m.compare(Path("/fake/benchmark"), [10], 0)
            cmd.assert_not_called()


if __name__ == "__main__":
    unittest.main()
