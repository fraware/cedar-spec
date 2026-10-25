#!/usr/bin/env python3
"""Bounded CI smoke test for every declared Cedar fuzz target.

This gate tests that fuzz harnesses launch and execute inputs. It does not
measure language-semantic coverage or replace longer-running fuzz campaigns.
Run from the cedar-spec checkout after building the Lean libraries and installing
cargo-fuzz; a prebuild and corpus initialization are separate CI steps.
"""

import argparse
import re
import subprocess
import sys
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
FUZZ_MANIFEST = HERE / "fuzz" / "Cargo.toml"
FUZZ_DIR = HERE / "fuzz"
SUCCESS_PATTERN = re.compile(r"\bDone\s+(\d+)\s+runs?\s+in\b")


@dataclass(frozen=True)
class SmokeResult:
    """Result of one bounded libFuzzer invocation."""

    target: str
    ok: bool
    duration: float
    runs: int
    detail: str


def manifest_targets(path: Path = FUZZ_MANIFEST) -> set[str]:
    """Read the source-of-truth target list; reject invalid or duplicate names."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    try:
        names = [entry["name"] for entry in data["bin"]]
    except (KeyError, TypeError) as exc:
        raise ValueError("Fuzz Cargo.toml contains malformed [[bin]] entries") from exc
    if not names or len(names) != len(set(names)):
        raise ValueError("Fuzz Cargo.toml contains no targets or duplicate target names")
    return set(names)


def discovered_targets() -> set[str]:
    """Ask cargo-fuzz to enumerate targets and report any discovery failures."""
    result = subprocess.run(
        ["cargo", "fuzz", "list"],
        cwd=HERE,
        text=True,
        capture_output=True,
        check=False,
        timeout=45,
    )
    if result.returncode:
        raise RuntimeError(f"cargo fuzz list failed:\n{result.stderr}")
    names = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not names or len(names) != len(set(names)):
        raise RuntimeError("cargo fuzz list returned zero or duplicate targets")
    return set(names)


def target_environment(target: str) -> dict[str, str]:
    """Provide the checked-in Cedar sample needed by the feature-gated target."""
    import os

    env = os.environ.copy()
    if target == "input-generation":
        sample = HERE.parent / "cedar" / "cedar-policy-cli" / "sample-data" / "sandbox_a"
        paths = {
            "CEDAR_SCHEMA_FILE": sample / "schema.cedarschema",
            "CEDAR_POLICY_FILE": sample / "policies_1.cedar",
        }
        for key, path in paths.items():
            if not path.is_file():
                raise FileNotFoundError(f"Required smoke-test fixture missing: {path}")
            env[key] = str(path)
    return env


def fuzz_command(target: str, *, runs: int, input_seconds: int) -> list[str]:
    """Use the prebuilt, unsanitized fuzz targets and cap individual inputs."""
    return [
        "cargo", "fuzz", "run", "-s", "none", "--all-features", target,
        "--", f"-runs={runs}", f"-timeout={input_seconds}",
        "-rss_limit_mb=2048", "-print_final_stats=1",
    ]


def run_target(target: str, *, runs: int, input_seconds: int, wall_seconds: int) -> SmokeResult:
    """Treat process exit, timeouts and execution counts as authoritative."""
    # GNU timeout terminates the cargo-fuzz process group, including the fuzz
    # binary and solver subprocesses; subprocess.run alone kills only Cargo.
    command = [
        "timeout", "--kill-after=5s", f"{wall_seconds}s",
        *fuzz_command(target, runs=runs, input_seconds=input_seconds),
    ]
    start = time.monotonic()
    try:
        finished = subprocess.run(
            command, cwd=HERE, env=target_environment(target),
            capture_output=True, text=True, errors="replace", check=False,
            timeout=wall_seconds + 10,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return SmokeResult(target, False, time.monotonic() - start, 0, str(exc))
    output = finished.stdout + "\n" + finished.stderr
    matches = SUCCESS_PATTERN.findall(output)
    observed = int(matches[-1]) if matches else 0
    successful = finished.returncode == 0 and observed >= runs
    detail = "" if successful else (
        f"exit={finished.returncode}; reported_runs={observed}\n"
        + "\n".join(output.splitlines()[-45:])
    )
    return SmokeResult(target, successful, time.monotonic() - start, observed, detail)


def smoke_all(*, runs: int, input_seconds: int, wall_seconds: int, suite_seconds: int = 900) -> int:
    """Run exactly the declared targets and return nonzero if any fails."""
    declared = manifest_targets()
    actual = discovered_targets()
    if actual != declared:
        raise RuntimeError(
            "Target list mismatch; refusing incomplete smoke test.\n"
            f"Missing: {sorted(declared - actual)}\nUnexpected: {sorted(actual - declared)}"
        )

    failures = []
    deadline = time.monotonic() + suite_seconds
    print(f"Smoke-testing all {len(actual)} declared targets", flush=True)
    for i, target in enumerate(sorted(actual), start=1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            print(
                f"Smoke-test suite budget exhausted before target {i}/{len(actual)} "
                f"({target}); targets remain untested", file=sys.stderr,
            )
            return 1
        result = run_target(
            target, runs=runs, input_seconds=input_seconds,
            wall_seconds=min(wall_seconds, max(1, int(remaining))),
        )
        status = "PASS" if result.ok else "FAIL"
        print(
            f"[{i}/{len(actual)}] {status} {target} "
            f"({result.runs} runs, {result.duration:.2f}s)", flush=True,
        )
        if not result.ok:
            failures.append(result)
            print(result.detail, file=sys.stderr, flush=True)

    if failures:
        print(f"{len(failures)} / {len(actual)} targets failed", file=sys.stderr)
        return 1
    print(f"All {len(actual)} targets completed a bounded smoke run", flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI with deliberately small and auditable resource budgets."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=8)
    parser.add_argument("--input-seconds", type=int, default=10)
    parser.add_argument("--wall-seconds", type=int, default=60)
    parser.add_argument("--suite-seconds", type=int, default=900)
    args = parser.parse_args(argv)
    if min(args.runs, args.input_seconds, args.wall_seconds, args.suite_seconds) <= 0:
        parser.error("all budgets must be positive")
    try:
        return smoke_all(
            runs=args.runs, input_seconds=args.input_seconds,
            wall_seconds=args.wall_seconds, suite_seconds=args.suite_seconds,
        )
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"Smoke-test setup failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
