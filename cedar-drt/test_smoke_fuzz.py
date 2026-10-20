"""Unit tests for smoke-fuzz target accounting and subprocess failures."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import smoke_fuzz


class ManifestTests(unittest.TestCase):
    def test_manifest_enumeration_and_duplicate_rejection(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "Cargo.toml"
            path.write_text('[[bin]]\nname="a"\n[[bin]]\nname="b"\n')
            self.assertEqual(smoke_fuzz.manifest_targets(path), {"a", "b"})
            path.write_text('[[bin]]\nname="a"\n[[bin]]\nname="a"\n')
            with self.assertRaisesRegex(ValueError, "duplicate"):
                smoke_fuzz.manifest_targets(path)

    def test_input_generation_fixtures_are_relative_to_repository_root(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "cedar-spec"
            drt = root / "cedar-drt"
            sample = root / "cedar" / "cedar-policy-cli" / "sample-data" / "sandbox_a"
            sample.mkdir(parents=True)
            drt.mkdir()
            (sample / "schema.cedarschema").write_text("entity User;")
            (sample / "policies_1.cedar").write_text("permit(principal,action,resource);")
            with patch.object(smoke_fuzz, "HERE", drt):
                env = smoke_fuzz.target_environment("input-generation")
            self.assertEqual(env["CEDAR_SCHEMA_FILE"], str(sample / "schema.cedarschema"))
            self.assertEqual(env["CEDAR_POLICY_FILE"], str(sample / "policies_1.cedar"))

    def test_missing_input_generation_fixtures_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "cedar-spec"
            drt = root / "cedar-drt"
            drt.mkdir(parents=True)
            with patch.object(smoke_fuzz, "HERE", drt):
                with self.assertRaisesRegex(FileNotFoundError, "fixture missing"):
                    smoke_fuzz.target_environment("input-generation")

    def test_discovery_failure(self):
        with patch.object(smoke_fuzz.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "bad")):
            with self.assertRaisesRegex(RuntimeError, "bad"):
                smoke_fuzz.discovered_targets()

    def test_target_mismatch_aborts_before_running(self):
        with patch.object(smoke_fuzz, "manifest_targets", return_value={"a", "b"}), \
             patch.object(smoke_fuzz, "discovered_targets", return_value={"a"}), \
             patch.object(smoke_fuzz, "run_target") as run:
            with self.assertRaisesRegex(RuntimeError, "Missing"):
                smoke_fuzz.smoke_all(runs=2, input_seconds=3, wall_seconds=4)
            run.assert_not_called()


class FuzzExecutionTests(unittest.TestCase):
    def invoke(self, rc: int, stderr: str):
        with patch.object(smoke_fuzz, "target_environment", return_value={}), \
             patch.object(smoke_fuzz.subprocess, "run", return_value=subprocess.CompletedProcess([], rc, "", stderr)):
            return smoke_fuzz.run_target("example", runs=8, input_seconds=10, wall_seconds=20)

    def test_success_requires_exit_zero_and_iterations(self):
        self.assertTrue(self.invoke(0, "Done 8 runs in 0 second(s)").ok)
        self.assertFalse(self.invoke(0, "Done 0 runs in 0 second(s)").ok)
        self.assertFalse(self.invoke(0, "something else").ok)

    def test_timeout_controls_full_process_group(self):
        with patch.object(smoke_fuzz, "target_environment", return_value={}), \
             patch.object(smoke_fuzz.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "Done 1 runs in 0 second(s)")) as invoke:
            self.assertTrue(smoke_fuzz.run_target("example", runs=1, input_seconds=3, wall_seconds=7).ok)
            command = invoke.call_args.args[0]
            self.assertEqual(command[:3], ["timeout", "--kill-after=5s", "7s"])
            self.assertEqual(invoke.call_args.kwargs["timeout"], 17)

    def test_nonzero_exit_overrides_done(self):
        res = self.invoke(42, "Done 8 runs in 1 second\ncrash")
        self.assertFalse(res.ok)
        self.assertIn("exit=42", res.detail)
        self.assertIn("crash", res.detail)

    def test_timeout_and_spawn_errors_fail_closed(self):
        for exc in (subprocess.TimeoutExpired(["cargo"], 10), OSError("missing cargo")):
            with patch.object(smoke_fuzz, "target_environment", return_value={}), \
                 patch.object(smoke_fuzz.subprocess, "run", side_effect=exc):
                self.assertFalse(smoke_fuzz.run_target("x", runs=1, input_seconds=2, wall_seconds=3).ok)

    def test_command_includes_bounded_flags_and_features(self):
        cmd = smoke_fuzz.fuzz_command("input-generation", runs=8, input_seconds=10)
        self.assertIn("--all-features", cmd)
        self.assertIn("-runs=8", cmd)
        self.assertIn("-timeout=10", cmd)

    def test_all_targets_executed_and_failure_aggregated(self):
        def fake_run(target, **kwargs):
            return smoke_fuzz.SmokeResult(target, target != "b", 0.01, 7, "failed")
        with patch.object(smoke_fuzz, "manifest_targets", return_value={"a", "b"}), \
             patch.object(smoke_fuzz, "discovered_targets", return_value={"a", "b"}), \
             patch.object(smoke_fuzz, "run_target", side_effect=fake_run) as run:
            self.assertEqual(smoke_fuzz.smoke_all(runs=2, input_seconds=3, wall_seconds=4), 1)
            self.assertEqual(run.call_count, 2)


if __name__ == "__main__":
    unittest.main()
