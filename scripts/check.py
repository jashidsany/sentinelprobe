#!/usr/bin/env python3
"""Run SentinelProbe regression checks from the source tree."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable
CLI = ROOT / "prompt_injection_harness" / "pi_harness.py"
WRAPPER = ROOT / "prompt_injection_harness" / "wrappers" / "claude_code_wrapper.py"
VULNERABLE = ROOT / "prompt_injection_harness" / "examples" / "vulnerable_echo_target.py"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run SentinelProbe source-tree regression checks.")
    parser.add_argument("--build", action="store_true", help="Build sdist and wheel with the project virtualenv when available.")
    parser.add_argument("--wheel-smoke", action="store_true", help="Install the built wheel into a fresh venv and run smoke checks.")
    parser.add_argument("--skip-slow", action="store_true", help="Skip checks that create venvs or build packages.")
    parser.add_argument("--keep-artifacts", action="store_true", help="Keep temporary check reports and venvs.")
    return parser.parse_args()


def run_step(name: str, command: list[str], *, expect_failure: bool = False, cwd: Path = ROOT) -> None:
    print(f"\n== {name}", flush=True)
    print(" ".join(command), flush=True)
    completed = subprocess.run(command, cwd=str(cwd), text=True, check=False)
    if expect_failure:
        if completed.returncode == 0:
            raise SystemExit(f"{name} was expected to fail but returned 0")
        print(f"Expected failure observed: exit {completed.returncode}")
        return
    if completed.returncode != 0:
        raise SystemExit(f"{name} failed with exit {completed.returncode}")


def py_compile() -> None:
    run_step(
        "py_compile",
        [
            PYTHON,
            "-m",
            "py_compile",
            str(CLI),
            str(WRAPPER),
            str(VULNERABLE),
        ],
    )


def cli(*args: str) -> list[str]:
    return [PYTHON, str(CLI), *args]


def source_checks(artifact_dir: Path) -> None:
    run_step("validate builtin", cli("validate", "--cases", "builtin"))
    run_step("validate indirect mutations", cli("validate", "--cases", "indirect", "--mutations"))
    run_step("validate agent-files", cli("validate", "--cases", "agent-files"))
    run_step("list suites", cli("list-suites"))
    run_step("examples agent-files", cli("examples", "agent-files"))
    run_step("doctor browser", cli("doctor", "--target", "browser"))

    run_step(
        "direct mock smoke",
        cli(
            "run",
            "--cases",
            "direct",
            "--provider",
            "mock",
            "--limit",
            "4",
            "--report",
            str(artifact_dir / "direct_mock.json"),
        ),
    )
    run_step(
        "indirect mutation mock smoke",
        cli(
            "run",
            "--cases",
            "indirect",
            "--mutations",
            "--provider",
            "mock",
            "--limit",
            "5",
            "--report",
            str(artifact_dir / "indirect_mutations_mock.json"),
        ),
    )
    run_step(
        "agent-files mock smoke",
        cli(
            "run",
            "--cases",
            "agent-files",
            "--provider",
            "mock",
            "--report",
            str(artifact_dir / "agent_files_mock.json"),
            "--html-report",
            str(artifact_dir / "agent_files_mock.html"),
            "--trace-file",
            str(artifact_dir / "agent_files_trace.txt"),
        ),
    )
    run_step(
        "agent-files vulnerable calibration",
        cli(
            "run",
            "--cases",
            "agent-files",
            "--provider",
            "command",
            "--command",
            f"{PYTHON} {VULNERABLE}",
            "--report",
            str(artifact_dir / "agent_files_vulnerable.json"),
        ),
        expect_failure=True,
    )


def project_python() -> str:
    venv_python = ROOT / ".venv" / "bin" / "python"
    if venv_python.exists():
        return str(venv_python)
    return PYTHON


def package_version() -> str:
    init_file = ROOT / "prompt_injection_harness" / "__init__.py"
    namespace: dict[str, str] = {}
    exec(init_file.read_text(encoding="utf-8"), namespace)
    return str(namespace["__version__"])


def build_package() -> None:
    run_step("build package", [project_python(), "-m", "build"])
    version = package_version()
    artifacts = sorted(str(path.relative_to(ROOT)) for path in (ROOT / "dist").glob(f"sentinelprobe-{version}*"))
    if not artifacts:
        raise SystemExit(f"No built artifacts found for version {version}")
    run_step(
        "twine check",
        [project_python(), "-m", "twine", "check", *artifacts],
    )


def wheel_smoke(artifact_dir: Path) -> None:
    version = package_version()
    wheel = ROOT / "dist" / f"sentinelprobe-{version}-py3-none-any.whl"
    if not wheel.exists():
        raise SystemExit(f"Missing wheel: {wheel}. Run with --build first.")

    venv_dir = artifact_dir / "wheel-smoke-venv"
    run_step("create wheel smoke venv", [PYTHON, "-m", "venv", str(venv_dir)])
    pip = venv_dir / "bin" / "pip"
    sentinelprobe = venv_dir / "bin" / "sentinelprobe"
    run_step("install wheel", [str(pip), "install", "--quiet", str(wheel)])
    run_step("wheel validate builtin", [str(sentinelprobe), "validate", "--cases", "builtin"], cwd=artifact_dir)
    run_step(
        "wheel agent-files mock",
        [
            str(sentinelprobe),
            "run",
            "--cases",
            "agent-files",
            "--provider",
            "mock",
            "--limit",
            "2",
            "--report",
            str(artifact_dir / "wheel_agent_files_mock.json"),
        ],
        cwd=artifact_dir,
    )


def main() -> int:
    args = parse_args()
    artifact_dir = Path(tempfile.mkdtemp(prefix="sentinelprobe-check-"))
    print(f"Artifacts: {artifact_dir}", flush=True)
    try:
        py_compile()
        source_checks(artifact_dir)
        if not args.skip_slow and args.build:
            build_package()
        if not args.skip_slow and args.wheel_smoke:
            wheel_smoke(artifact_dir)
        print("\nAll requested checks passed.")
    finally:
        if args.keep_artifacts:
            print(f"Kept artifacts: {artifact_dir}")
        else:
            shutil.rmtree(artifact_dir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
