"""Regression tests for fuzz-manager process reporting.

These tests mock only the cargo-fuzz subprocess, leaving the status parser
and result-reporting code under test.
"""

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import fuzz_manager


class FakeProcess:
    """A completed subprocess exposing an asynchronous stdout stream."""

    def __init__(self, output: str, returncode: int):
        self.stdout = asyncio.StreamReader()
        self.stdout.feed_data(output.encode("utf-8"))
        self.stdout.feed_eof()
        self.returncode = returncode

    async def wait(self) -> int:
        return self.returncode


class FuzzManagerStatusTests(unittest.IsolatedAsyncioTestCase):
    """A smoke run succeeds only after at least one input and a zero exit."""

    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.reports_dir = Path(self.temp.name)

    async def run_with_output(self, output: str, returncode: int):
        stats = fuzz_manager.FuzzStats()
        fake = FakeProcess(output, returncode)
        with patch.object(
            fuzz_manager.asyncio, "create_subprocess_exec", return_value=fake
        ) as create:
            await fuzz_manager.run_target(
                "test-target", "test-target", stats, 1, self.reports_dir, "none"
            )
        create.assert_awaited_once()
        return stats

    async def test_completed_run_succeeds(self):
        stats = await self.run_with_output("Done 7 runs in 1 second\n", 0)
        self.assertEqual(stats.status, "done")
        self.assertEqual(stats.runs, 7)
        self.assertEqual(stats.report_path, "")

    async def test_clean_exit_after_progress_without_done_is_failure(self):
        stats = await self.run_with_output(
            "#8 NEW cov: 10 ft: 11 corp: 1/1b exec/s: 10 rss: 20Mb\n", 0
        )
        self.assertEqual(stats.status, "error")
        self.assertEqual(stats.runs, 8)
        self.assertIn(
            "without a libFuzzer completion message",
            Path(stats.report_path).read_text(),
        )

    async def test_nonzero_exit_overrides_done_message(self):
        stats = await self.run_with_output(
            "Done 7 runs in 1 second\nfatal error\n", 42
        )
        self.assertEqual(stats.status, "error")
        self.assertIn("fatal error", Path(stats.report_path).read_text())
        self.assertIn("status 42", Path(stats.report_path).read_text())

    async def test_zero_executions_fail_closed(self):
        stats = await self.run_with_output("Done 0 runs in 1 second\n", 0)
        self.assertEqual(stats.status, "error")
        self.assertIn(
            "without executing any inputs", Path(stats.report_path).read_text()
        )

    async def test_clean_exit_without_fuzzer_output_is_not_success(self):
        stats = await self.run_with_output("misconfigured target\n", 0)
        self.assertEqual(stats.status, "error")
        self.assertEqual(stats.runs, 0)

    async def test_subprocess_launch_failure_is_reported(self):
        stats = fuzz_manager.FuzzStats()
        with patch.object(
            fuzz_manager.asyncio,
            "create_subprocess_exec",
            side_effect=OSError("cargo-fuzz unavailable"),
        ):
            await fuzz_manager.run_target_with_error_reporting(
                "test-target", "test-target", stats, 1, self.reports_dir, "none"
            )
        self.assertEqual(stats.status, "error")
        self.assertIn("cargo-fuzz unavailable", Path(stats.report_path).read_text())

    async def test_completion_code_requires_all_targets_done(self):
        done = fuzz_manager.FuzzStats(status="done", runs=10)
        stopped = fuzz_manager.FuzzStats(status="stopped", runs=10)
        error = fuzz_manager.FuzzStats(status="error", runs=0)
        running = fuzz_manager.FuzzStats(status="running", runs=10)
        self.assertEqual(fuzz_manager.completion_exit_code({"a": done}, False), 0)
        for incomplete in (stopped, error, running):
            self.assertEqual(
                fuzz_manager.completion_exit_code(
                    {"a": done, "b": incomplete}, False
                ),
                1,
            )
        self.assertEqual(fuzz_manager.completion_exit_code({}, False), 1)

    async def test_interrupted_campaign_exits_nonzero_even_if_all_done(self):
        done = fuzz_manager.FuzzStats(status="done", runs=10)
        self.assertEqual(fuzz_manager.completion_exit_code({"a": done}, True), 130)

    async def test_incidental_done_substring_does_not_pass(self):
        stats = await self.run_with_output(
            "target says Done 7 runs in 1 second as diagnostic\\n", 0
        )
        self.assertEqual(stats.status, "error")
        self.assertEqual(stats.runs, 0)

    async def test_cancel_signals_process_group_and_fails_closed(self):
        class BlockingReader:
            def __init__(self):
                self.entered = asyncio.Event()

            async def readline(self):
                self.entered.set()
                await asyncio.Future()

        class BlockingProcess:
            def __init__(self):
                self.pid = 424242
                self.returncode = None
                self.stdout = BlockingReader()

            async def wait(self):
                self.returncode = -15
                return self.returncode

        fake = BlockingProcess()
        stats = fuzz_manager.FuzzStats()
        with patch.object(
            fuzz_manager.asyncio, "create_subprocess_exec", return_value=fake
        ) as spawn, patch.object(fuzz_manager.os, "killpg") as killpg:
            task = asyncio.create_task(
                fuzz_manager.run_target(
                    "target", "target", stats, 1, self.reports_dir, "none"
                )
            )
            await asyncio.wait_for(fake.stdout.entered.wait(), timeout=2)
            task.cancel()
            await asyncio.wait_for(task, timeout=2)
        self.assertEqual(stats.status, "stopped")
        self.assertEqual(
            fuzz_manager.completion_exit_code({"target": stats}, False), 1
        )
        spawn.assert_awaited_once()
        self.assertTrue(spawn.call_args.kwargs["start_new_session"])
        killpg.assert_called_once_with(fake.pid, fuzz_manager.signal.SIGTERM)

    async def test_unexpected_stream_failure_stops_process_group(self):
        class BrokenReader:
            async def readline(self):
                raise ValueError("fuzzer output line exceeds stream limit")

        class RunningProcess:
            def __init__(self):
                self.pid = 424243
                self.returncode = None
                self.stdout = BrokenReader()

            async def wait(self):
                self.returncode = -15
                return self.returncode

        fake = RunningProcess()
        stats = fuzz_manager.FuzzStats()
        with patch.object(
            fuzz_manager.asyncio, "create_subprocess_exec", return_value=fake
        ) as spawn, patch.object(fuzz_manager.os, "killpg") as killpg:
            await fuzz_manager.run_target_with_error_reporting(
                "target", "target", stats, 1, self.reports_dir, "none"
            )
        self.assertEqual(stats.status, "error")
        self.assertIn(
            "fuzzer output line exceeds stream limit",
            Path(stats.report_path).read_text(),
        )
        self.assertTrue(spawn.call_args.kwargs["start_new_session"])
        killpg.assert_called_once_with(fake.pid, fuzz_manager.signal.SIGTERM)

    async def test_nonzero_exit_without_done_message(self):
        stats = await self.run_with_output("boom\n", 1)
        self.assertEqual(stats.status, "error")
        self.assertIn("boom", Path(stats.report_path).read_text())


if __name__ == "__main__":
    unittest.main()
