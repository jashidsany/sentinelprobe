"""Setup checks for SentinelProbe targets."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from prompt_injection_harness.cases import load_cases, package_root, resolve_cases_path
from prompt_injection_harness.providers import missing_browser_config_keys
from prompt_injection_harness.reports import load_json


try:
    import yaml  # type: ignore
except ImportError:
    yaml = None


@dataclass
class DoctorCheck:
    status: str
    name: str
    detail: str


def use_color(color_mode: str | None = None) -> bool:
    mode = color_mode or "auto"
    if mode == "always":
        return True
    if mode == "never":
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("CLICOLOR_FORCE") == "1":
        return True
    return sys.stdout.isatty()


def colorize(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m"


def tag_color(tag: str) -> str:
    return {
        "OK": "32;1",
        "WARN": "33;1",
        "FAIL": "31;1",
    }.get(tag, "0")


def tagged_label(tag: str, color: bool | None = None) -> str:
    normalized = str(tag).upper()
    label = f"[{normalized}]"
    if color is None:
        color = use_color()
    if color:
        return colorize(label, tag_color(normalized))
    return label


def doctor_label(status: str, color: bool | None = None) -> str:
    tag = {"ok": "OK", "warn": "WARN", "fail": "FAIL"}.get(status, "WARN")
    return tagged_label(tag, color)


def package_version() -> str:
    try:
        from prompt_injection_harness import __version__

        return str(__version__)
    except Exception:
        init_file = package_root() / "__init__.py"
        try:
            match = re.search(r'__version__\s*=\s*"([^"]+)"', init_file.read_text(encoding="utf-8"))
        except OSError:
            match = None
        return match.group(1) if match else "unknown"


def add_check(checks: list[DoctorCheck], status: str, name: str, detail: str) -> None:
    checks.append(DoctorCheck(status=status, name=name, detail=detail))


def check_writable_directory(path: Path) -> tuple[bool, str]:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".sentinelprobe_write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        return False, str(exc)
    return True, str(path)


def run_doctor(target: str = "all", browser_config: str = "", workdir: str = "") -> int:
    color = use_color()
    checks: list[DoctorCheck] = []

    add_check(checks, "ok", "Python", sys.version.split()[0])
    add_check(checks, "ok", "SentinelProbe package", f"version {package_version()}")
    add_check(checks, "ok" if yaml else "fail", "PyYAML", "available" if yaml else "missing. Install PyYAML.")

    try:
        builtin_cases = load_cases(resolve_cases_path("builtin"))
        add_check(checks, "ok", "Bundled cases", f"{len(builtin_cases)} cases loaded")
    except Exception as exc:
        add_check(checks, "fail", "Bundled cases", str(exc))

    writable, detail = check_writable_directory(Path("reports"))
    add_check(checks, "ok" if writable else "fail", "Reports directory", detail if writable else f"not writable: {detail}")

    if target in {"all", "claude-code"}:
        claude_path = shutil.which("claude")
        add_check(checks, "ok" if claude_path else "fail", "Claude CLI", claude_path or "not found on PATH")
        if claude_path:
            try:
                completed = subprocess.run(
                    [claude_path, "--help"],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10,
                    check=False,
                )
                detail = "help command returned 0" if completed.returncode == 0 else f"help returned {completed.returncode}"
                add_check(checks, "ok" if completed.returncode == 0 else "warn", "Claude CLI help", detail)
            except (OSError, subprocess.TimeoutExpired) as exc:
                add_check(checks, "warn", "Claude CLI help", str(exc))
        wrapper_path = shutil.which("claude-code-wrapper")
        local_wrapper = package_root() / "wrappers" / "claude_code_wrapper.py"
        if wrapper_path:
            add_check(checks, "ok", "Claude wrapper", wrapper_path)
        elif local_wrapper.exists():
            add_check(checks, "warn", "Claude wrapper", f"console script not on PATH, local wrapper exists at {local_wrapper}")
        else:
            add_check(checks, "fail", "Claude wrapper", "claude-code-wrapper not found")
        if workdir:
            workdir_path = Path(workdir)
            if workdir_path.exists() and not workdir_path.is_dir():
                add_check(checks, "fail", "Claude workdir", f"{workdir_path} exists and is not a directory")
            else:
                add_check(checks, "ok", "Claude workdir", f"{workdir_path} can be used as disposable sandbox")
        add_check(checks, "ok", "Built-in data safety", "bundled cases use fake documents and fake secrets")

    if target in {"all", "browser"}:
        try:
            import playwright  # type: ignore  # noqa: F401

            add_check(checks, "ok", "Playwright package", "available")
        except ImportError:
            add_check(checks, "warn", "Playwright package", "not installed. Install sentinelprobe[browser] and run playwright install chromium.")
        config_path = Path(browser_config)
        if config_path.exists():
            try:
                config = load_json(config_path)
                missing = missing_browser_config_keys(config)
                if missing:
                    add_check(checks, "warn", "Browser config", f"{config_path} missing values: {', '.join(missing)}")
                else:
                    add_check(checks, "ok", "Browser config", f"{config_path} has required keys")
            except SystemExit as exc:
                add_check(checks, "fail", "Browser config", str(exc))
        else:
            add_check(checks, "warn", "Browser config", f"{config_path} not found")

    print("Doctor")
    print("------")
    for check in checks:
        print(f"{doctor_label(check.status, color)} {check.name}: {check.detail}")

    fail_count = sum(1 for check in checks if check.status == "fail")
    warn_count = sum(1 for check in checks if check.status == "warn")
    print(f"\nSummary: ok={sum(1 for check in checks if check.status == 'ok')} warn={warn_count} fail={fail_count}")
    return 1 if fail_count else 0
