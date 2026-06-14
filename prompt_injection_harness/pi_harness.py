#!/usr/bin/env python3
"""Holistic CLI for authorized AI security testing."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import sys
import time
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prompt_injection_harness.compare import compare_reports_command
from prompt_injection_harness.doctor import run_doctor
from prompt_injection_harness.html_reports import (
    resolve_html_report_path,
    write_html_report,
)
from prompt_injection_harness.reports import load_json, write_report
from prompt_injection_harness.cases import (
    CASE_SUITES,
    SUITE_DESCRIPTIONS,
    apply_case_limit,
    load_cases,
    package_root,
    resolve_cases_path,
    slugify,
    validate_cases,
)
from prompt_injection_harness.providers import (
    TargetResult,
    call_browser,
    call_command,
    call_http,
    call_mock,
    render_case_input,
)
from prompt_injection_harness.presets import render_preset, render_preset_list, write_preset
from prompt_injection_harness.scoring import score_case


try:
    import yaml  # type: ignore
except ImportError:
    yaml = None


VERBOSE_CASE_SEPARATOR = "-" * 78


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run authorized AI prompt-injection and agent-boundary tests.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--color", choices=["auto", "always", "never"], default="auto", help="Control ANSI color output.")
    subparsers = parser.add_subparsers(dest="command_name", required=True)

    run = subparsers.add_parser("run", help="Run test cases.")
    run.add_argument("--cases", required=True, help="YAML case file, case directory, or 'builtin'.")
    run.add_argument("--provider", choices=["mock", "http", "command", "browser"], required=True)
    run.add_argument("--endpoint", help="HTTP endpoint for --provider http.")
    run.add_argument("--header", action="append", default=[], help="HTTP header, for example 'Authorization: Bearer TOKEN'.")
    run.add_argument("--command", help="Command for --provider command. Receives JSON on stdin.")
    run.add_argument("--browser-config", help="JSON browser target config for --provider browser.")
    run.add_argument("--headed", action="store_true", help="Show browser window for --provider browser.")
    run.add_argument("--slow-mo", type=int, default=0, help="Playwright slow motion delay in milliseconds.")
    run.add_argument("--timeout", type=int, default=45)
    run.add_argument("--report", help="Report path. Defaults to reports/<provider>_<cases>_<timestamp>.json.")
    run.add_argument("--mutations", action="store_true", help="Add deterministic variants for cases that define mutations.")
    run.add_argument("--limit", type=positive_int, help="Send only the first N loaded cases. Applied after mutations.")
    run.add_argument("--fail-on-review", action="store_true", help="Return non-zero when any case needs review.")
    run.add_argument("--verbose", action="store_true", help="Show each case status plus prompt and response text.")
    run.add_argument("--show-findings", action="store_true", help="Print full finding details for each non-pass case during the run.")
    run.add_argument("--only-findings", action="store_true", help="With --verbose, hide passing case lines and show only review/fail cases.")
    run.add_argument("--trace", action="store_true", help="Compatibility alias for terminal prompt and response output. Prefer --verbose.")
    run.add_argument("--trace-limit", type=int, default=4000, help="Maximum characters per printed prompt or response. Use 0 for no limit.")
    run.add_argument("--trace-file", help="Write full case inputs and target responses to this text file.")
    run.add_argument("--html-report", nargs="?", const="", help="Write an HTML report. Defaults to the JSON report path with .html when used without a value.")

    claude_code = subparsers.add_parser("claude-code", help="Run Claude Code with response-only defaults.")
    claude_code.add_argument("--test", dest="test", default="direct", help="Test suite alias or case path. Default: direct.")
    claude_code.add_argument("--suite", dest="test", help=argparse.SUPPRESS)
    claude_code.add_argument("--model", default="sonnet", help="Claude model alias passed to claude-code-wrapper. Default: sonnet.")
    claude_code.add_argument("--budget", default="0.25", help="Max Claude Code budget in USD. Default: 0.25.")
    claude_code.add_argument("--mode", choices=["response-only", "agent-sandbox"], default="response-only")
    claude_code.add_argument("--workdir", help="Disposable workdir for --mode agent-sandbox.")
    claude_code.add_argument(
        "--agent-files",
        action="store_true",
        help="Write case documents into a disposable sandbox and ask Claude Code to inspect files. Uses agent-sandbox mode.",
    )
    claude_code.add_argument("--timeout", type=int, default=180)
    claude_code.add_argument("--report", help="Report path. Defaults to reports/claude-code_<test>_<timestamp>.json.")
    claude_code.add_argument("--mutations", action="store_true", help="Add deterministic variants for cases that define mutations.")
    claude_code.add_argument("--limit", type=positive_int, help="Send only the first N loaded cases. Applied after mutations.")
    claude_code.add_argument("--fail-on-review", action="store_true", help="Return non-zero when any case needs review.")
    claude_code.add_argument("--verbose", action="store_true", help="Show each case status plus prompt and response text.")
    claude_code.add_argument("--quiet", action="store_true", help="Hide per-case status lines.")
    claude_code.add_argument("--show-findings", action="store_true", help="Print full finding details for each non-pass case during the run.")
    claude_code.add_argument("--only-findings", action="store_true", help="Hide passing case lines and show only review/fail cases.")
    claude_code.add_argument("--trace", action="store_true", help="Compatibility alias for terminal prompt and response output. Prefer --verbose.")
    claude_code.add_argument("--trace-limit", type=int, default=4000, help="Maximum characters per printed prompt or response. Use 0 for no limit.")
    claude_code.add_argument("--trace-file", help="Write full case inputs and Claude Code responses to this text file.")
    claude_code.add_argument("--html-report", nargs="?", const="", help="Write an HTML report. Defaults to the JSON report path with .html when used without a value.")

    list_cases = subparsers.add_parser("list-cases", help="List loaded cases.")
    list_cases.add_argument("--cases", required=True, help="YAML case file, case directory, or suite alias such as 'builtin' or 'direct'.")
    list_cases.add_argument("--mutations", action="store_true", help="Include deterministic variants for cases that define mutations.")

    validate = subparsers.add_parser("validate", help="Validate case files without running a target.")
    validate.add_argument("--cases", required=True, help="YAML case file, case directory, or suite alias such as 'builtin' or 'direct'.")
    validate.add_argument("--mutations", action="store_true", help="Include deterministic variants for cases that define mutations.")

    summarize = subparsers.add_parser("summarize", help="Summarize a JSON report.")
    summarize.add_argument("--report", required=True)
    summarize.add_argument("--plain", action="store_true", help="Use compact plain-text output.")
    summarize.add_argument("--html-report", nargs="?", const="", help="Write an HTML report from this JSON report. Defaults to the JSON report path with .html when used without a value.")

    compare = subparsers.add_parser("compare", help="Compare two JSON reports.")
    compare.add_argument("--before", required=True, help="Baseline JSON report.")
    compare.add_argument("--after", required=True, help="New JSON report.")
    compare.add_argument("--plain", action="store_true", help="Use compact plain-text output.")
    compare.add_argument("--html-report", nargs="?", const="", help="Write an HTML comparison report. Defaults to reports/compare_<before>_to_<after>.html when used without a value.")

    doctor = subparsers.add_parser("doctor", help="Check local SentinelProbe setup.")
    doctor.add_argument("--target", choices=["all", "claude-code", "browser"], default="all", help="Target-specific checks to run. Default: all.")
    doctor.add_argument("--browser-config", default="prompt_injection_harness/browser_targets/claude_template.json", help="Browser config path to validate for browser checks.")
    doctor.add_argument("--workdir", default="prompt_injection_harness/targets/claude_code_sandbox", help="Claude Code disposable workdir to check.")

    init_browser = subparsers.add_parser("init-browser-config", help="Write a browser provider config template.")
    init_browser.add_argument("--output", default="prompt_injection_harness/browser_targets/generic_browser.json")
    init_browser.add_argument("--base-url", default="https://app.example.test")

    init_project = subparsers.add_parser("init-project", help="Copy starter cases, configs, wrappers, and report folders.")
    init_project.add_argument("--output", default="ai_security_tests")
    init_project.add_argument("--force", action="store_true", help="Overwrite existing starter files in the output folder.")

    presets = subparsers.add_parser("presets", help="List, show, or write target presets.")
    preset_subparsers = presets.add_subparsers(dest="preset_command", required=True)
    preset_subparsers.add_parser("list", help="List available presets.")
    preset_show = preset_subparsers.add_parser("show", help="Show a preset.")
    preset_show.add_argument("name")
    preset_init = preset_subparsers.add_parser("init", help="Write a preset JSON file.")
    preset_init.add_argument("name")
    preset_init.add_argument("--output", required=True)
    preset_init.add_argument("--force", action="store_true", help="Overwrite an existing preset file.")

    subparsers.add_parser("banner", help="Print the SentinelProbe banner.")
    subparsers.add_parser("list-suites", help="List bundled case suite aliases.")
    examples = subparsers.add_parser("examples", help="Print copy-ready example commands.")
    examples.add_argument("target", nargs="?", choices=["all", "claude-code", "mock", "indirect", "agent-files", "compare", "doctor", "presets", "http", "browser"], default="all")
    subparsers.add_parser("wizard", help="Interactive setup for common test runs.")

    return parser


def parse_args() -> argparse.Namespace:
    return create_parser().parse_args()


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def color_mode_from_argv() -> str:
    for index, value in enumerate(sys.argv):
        if value == "--color" and index + 1 < len(sys.argv):
            return sys.argv[index + 1]
        if value.startswith("--color="):
            return value.split("=", 1)[1]
    return "auto"


def use_color(mode: str | None = None) -> bool:
    mode = mode or color_mode_from_argv()
    if mode == "always":
        return True
    if mode == "never":
        return False
    if os.environ.get("CLICOLOR_FORCE") == "1":
        return True
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def colorize(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m"


def severity_color(severity: str) -> str:
    return {
        "pass": "32;1",
        "review": "33;1",
        "fail": "31;1",
    }.get(severity, "0")


def tag_color(tag: str) -> str:
    return {
        "INFO": "34;1",
        "OK": "32;1",
        "WARN": "33;1",
        "TRACE": "36;1",
        "PROMPT": "36;1",
        "RESPONSE": "34;1",
        "SECRET": "35;1",
        "CRITICAL": "31;1",
        "PASS": "32;1",
        "REVIEW": "33;1",
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


def severity_label(severity: str, color: bool | None = None) -> str:
    normalized = str(severity).lower()
    if normalized in {"pass", "review", "fail"}:
        return tagged_label(normalized.upper(), color)
    return tagged_label(normalized, color)


def finding_label(finding: dict[str, Any], color: bool | None = None) -> str:
    check = str(finding.get("check", "finding"))
    severity = str(finding.get("severity", "review"))
    detail = str(finding.get("detail", ""))
    if check == "fake_secret_leak" or re.search(r"FAKE_[A-Z0-9_]{8,}", detail):
        return tagged_label("SECRET", color)
    if severity == "fail" and check in {"forbidden_pattern", "forbidden_regex"}:
        return tagged_label("CRITICAL", color)
    if check.startswith("warning_"):
        return tagged_label("WARN", color)
    return severity_label(severity, color)


def status_text(status: str, color: bool | None = None) -> str:
    normalized = str(status).lower()
    if color is None:
        color = use_color()
    if color and normalized in {"pass", "review", "fail"}:
        return colorize(normalized, severity_color(normalized))
    return normalized


def banner_text(color: bool = False) -> str:
    art = r"""
  ____             _   _            _ ____            _
 / ___|  ___ _ __ | |_(_)_ __   ___| |  _ \ _ __ ___ | |__   ___
 \___ \ / _ \ '_ \| __| | '_ \ / _ \ | |_) | '__/ _ \| '_ \ / _ \
  ___) |  __/ | | | |_| | | | |  __/ |  __/| | | (_) | |_) |  __/
 |____/ \___|_| |_|\__|_|_| |_|\___|_|_|   |_|  \___/|_.__/ \___|

 Authorized AI prompt-injection and agent-boundary testing
""".strip("\n")
    if not color:
        return art
    lines = art.splitlines()
    art_lines = "\n".join(colorize(line, "36;1") for line in lines[:5])
    tagline = colorize(lines[6], "32;1") if len(lines) > 6 else ""
    return f"{art_lines}\n\n{tagline}"


def print_banner(color_mode: str | None = None) -> None:
    print(banner_text(color=use_color(color_mode)))


def default_report_path(provider: str, cases_name: str) -> Path:
    timestamp = time.strftime("%Y%m%d_%H%M%S", time.localtime())
    return Path("reports") / f"{slugify(provider)}_{slugify(cases_name)}_{timestamp}.json"


def copy_asset_dir(name: str, destination_root: Path, force: bool) -> None:
    source = package_root() / name
    destination = destination_root / name
    if not source.exists():
        raise SystemExit(f"Missing packaged asset directory: {source}")
    destination.mkdir(parents=True, exist_ok=True)
    for item in source.iterdir():
        if item.name == "__pycache__":
            continue
        target = destination / item.name
        if target.exists() and not force:
            continue
        if item.is_dir():
            if target.exists() and force:
                shutil.rmtree(target)
            shutil.copytree(item, target)
        else:
            shutil.copy2(item, target)


def init_project(output: Path, force: bool) -> None:
    output.mkdir(parents=True, exist_ok=True)
    for directory in ("cases", "browser_targets", "wrappers", "examples"):
        copy_asset_dir(directory, output, force)
    for directory in ("reports", "browser_profiles", "targets/claude_code_sandbox"):
        (output / directory).mkdir(parents=True, exist_ok=True)
    readme = output / "README.md"
    if force or not readme.exists():
        readme.write_text(
            "\n".join(
                [
                    "# SentinelProbe Workspace",
                    "",
                    "Use this folder for authorized AI prompt-injection and agent-boundary testing.",
                    "",
                    "Quick check:",
                    "",
                    "```bash",
                    "sentinelprobe doctor",
                    "sentinelprobe validate --cases cases",
                    "sentinelprobe run --cases cases --provider mock --report reports/mock_report.json --verbose",
                    "```",
                    "",
                    "Indirect prompt injection with generated variants:",
                    "",
                    "```bash",
                    "sentinelprobe run --cases indirect --mutations --provider mock --verbose",
                    "```",
                    "",
                    "Claude Code response-only run:",
                    "",
                    "```bash",
                    "sentinelprobe claude-code --test direct",
                    "```",
                    "",
                    "Claude Code file-based coding-agent run:",
                    "",
                    "```bash",
                    "sentinelprobe claude-code --test agent-files --agent-files --verbose --only-findings --html-report",
                    "```",
                    "",
                    "Compare reports:",
                    "",
                    "```bash",
                    "sentinelprobe compare --before reports/baseline.json --after reports/latest.json --html-report",
                    "```",
                    "",
                ]
            ),
            encoding="utf-8",
        )
    print(f"Initialized SentinelProbe workspace: {output}")


def build_headers(header_args: list[str]) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    for item in header_args:
        if ":" not in item:
            raise SystemExit(f"Invalid header {item!r}; expected 'Name: value'")
        name, value = item.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


def status_bar(label: str, value: int, total: int, width: int = 28, color: bool | None = None) -> str:
    filled = int((value / total) * width) if total else 0
    rendered_label = status_text(label, color)
    padded_label = f"{rendered_label:<7}" if not (color or False) else rendered_label
    if color:
        padded_label = f"{rendered_label}{' ' * max(1, 7 - len(label))}"
    return f"{padded_label} [{'#' * filled}{'.' * (width - filled)}] {value}"


def print_summary_graph(summary: dict[str, Any], color: bool | None = None) -> None:
    total = int(summary.get("total", 0) or 0)
    print("Results")
    print(status_bar("pass", int(summary.get("pass", 0) or 0), total, color=color))
    print(status_bar("review", int(summary.get("review", 0) or 0), total, color=color))
    print(status_bar("fail", int(summary.get("fail", 0) or 0), total, color=color))
    print(f"total   {total}")


def print_case_catalog(cases: list[dict[str, Any]]) -> None:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for case in cases:
        grouped.setdefault(str(case.get("category", "uncategorized")), []).append(case)
    for category, items in sorted(grouped.items()):
        print(f"\n{category}")
        print("-" * len(category))
        for case in items:
            print(f"{case.get('id'):<16} {case.get('name', '')}")


def print_suites() -> None:
    print("Bundled suites")
    print("--------------")
    for name, target in sorted(CASE_SUITES.items()):
        if isinstance(target, list):
            display = ", ".join(target)
        else:
            display = target
        count = len(load_cases(resolve_cases_path(name)))
        description = SUITE_DESCRIPTIONS.get(name, "")
        print(f"{name:<24} {count:>3} cases  {description}  [{display}]")


def print_examples(target: str) -> None:
    examples = {
        "claude-code": [
            "Claude Code direct prompt injection:",
            "sentinelprobe claude-code",
            "",
            "Claude Code advanced direct prompt injection:",
            "sentinelprobe claude-code --test direct-advanced",
            "",
            "Claude Code file-based coding-agent prompt injection:",
            "sentinelprobe claude-code --test agent-files --agent-files --verbose --only-findings --html-report",
            "",
            "Claude Code indirect smoke test with five prompts:",
            "sentinelprobe claude-code --test indirect --mutations --limit 5 --verbose --only-findings",
        ],
        "mock": [
            "Local mock baseline:",
            "sentinelprobe run --cases direct --provider mock --verbose",
        ],
        "indirect": [
            "Indirect prompt injection with generated variants:",
            "sentinelprobe run --cases indirect --mutations --provider mock --verbose",
            "",
            "Claude Code indirect prompt injection with generated variants:",
            "sentinelprobe claude-code --test indirect --mutations --verbose --only-findings",
            "",
            "Claude Code file-based coding-agent prompt injection:",
            "sentinelprobe claude-code --test agent-files --agent-files --verbose --only-findings --html-report",
            "",
            "Claude Code indirect smoke test with five prompts:",
            "sentinelprobe claude-code --test indirect --mutations --limit 5 --verbose --only-findings",
        ],
        "agent-files": [
            "Validate file-based coding-agent cases:",
            "sentinelprobe validate --cases agent-files",
            "",
            "Local mock baseline:",
            "sentinelprobe run --cases agent-files --provider mock --verbose",
            "",
            "Claude Code file-based coding-agent run:",
            "sentinelprobe claude-code --test agent-files --agent-files --verbose --only-findings --html-report",
        ],
        "compare": [
            "Compare two JSON reports:",
            "sentinelprobe compare --before reports/baseline.json --after reports/latest.json --html-report",
        ],
        "doctor": [
            "Check general setup:",
            "sentinelprobe doctor",
            "",
            "Check Claude Code setup:",
            "sentinelprobe doctor --target claude-code",
            "",
            "Check browser setup:",
            "sentinelprobe doctor --target browser --browser-config prompt_injection_harness/browser_targets/claude_template.json",
        ],
        "presets": [
            "List target presets:",
            "sentinelprobe presets list",
            "",
            "Show a preset:",
            "sentinelprobe presets show claude-code",
            "",
            "Write a preset JSON file:",
            "sentinelprobe presets init glean-browser --output sentinelprobe-targets/glean-browser.json",
        ],
        "http": [
            "Approved HTTP endpoint:",
            "sentinelprobe run --cases direct --provider http --endpoint http://127.0.0.1:8080/ask --header 'Authorization: Bearer TEST_TOKEN'",
        ],
        "browser": [
            "Browser target after configuring selectors:",
            "sentinelprobe run --cases direct --provider browser --browser-config prompt_injection_harness/browser_targets/claude_template.json --timeout 180",
        ],
    }
    selected = examples.keys() if target == "all" else [target]
    for index, key in enumerate(selected):
        if index:
            print()
        print("\n".join(examples[key]))


def summarize_report(path: Path, plain: bool = False, html_report: str | None = None) -> int:
    report = load_json(path)
    summary = report.get("summary", {})
    color = use_color()
    print(f"{tagged_label('INFO', color)} Report: {path}")
    html_report_path = resolve_html_report_path(html_report, path)
    if html_report_path:
        write_html_report(html_report_path, report, path)
        print(f"{tagged_label('INFO', color)} HTML report: {html_report_path}")
    if plain:
        print(
            "Summary: "
            f"pass={summary.get('pass', 0)} "
            f"review={summary.get('review', 0)} "
            f"fail={summary.get('fail', 0)} "
            f"total={summary.get('total', 0)}"
        )
    else:
        print_summary_graph(summary, color=color)
    for result in report.get("results", []):
        if result.get("status") == "pass":
            continue
        status = str(result.get("status", "review"))
        print(f"{severity_label(status, color)} {result.get('id')}: {status_text(status, color)}")
        for finding in result.get("findings", []):
            print(f"  - {finding_label(finding, color)} {finding.get('check')}: {finding.get('detail')}")
    return 0


def write_browser_template(output: Path, base_url: str) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    template = {
        "name": "generic-browser-target",
        "base_url": base_url,
        "profile_dir": "prompt_injection_harness/browser_profiles/generic",
        "wait_until": "domcontentloaded",
        "ready_selector": "textarea, [contenteditable='true']",
        "prompt_selector": "textarea, [contenteditable='true']",
        "submit_selector": "button[type='submit'], button:has-text('Send'), button:has-text('Ask')",
        "response_selector": "[data-testid='answer'], .answer, main",
        "done_selector": "",
        "send_documents_inline": True,
        "screenshot_dir": "prompt_injection_harness/reports/screenshots",
        "notes": [
            "Use only with authorized accounts and sandbox data.",
            "Run with --headed the first time and log in manually if the target requires browser SSO.",
            "Customize selectors for the target UI. For Glean, inspect the chat/search input, submit button, and answer container in your tenant.",
        ],
    }
    output.write_text(json.dumps(template, indent=2) + "\n", encoding="utf-8")


def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        value = input(f"{prompt}{suffix}: ").strip()
    except EOFError:
        print()
        return default
    return value or default


def choose(prompt: str, options: list[tuple[str, str]], default_index: int = 0) -> str:
    print(prompt)
    for index, (key, description) in enumerate(options, start=1):
        marker = " default" if index - 1 == default_index else ""
        print(f"  {index}. {key} - {description}{marker}")
    while True:
        raw = ask("Choose", str(default_index + 1))
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1][0]
        print("Enter a listed number.")


def run_wizard(color_mode: str = "auto") -> int:
    del color_mode
    print("SentinelProbe Wizard")
    print("Use only approved systems, accounts, and test data.\n")

    cases_path = ask("Cases path", "builtin")
    cases = load_cases(resolve_cases_path(cases_path))
    print(f"Loaded {len(cases)} cases.")
    print_case_catalog(cases)

    provider = choose(
        "\nTarget provider",
        [
            ("mock", "local baseline, no external calls"),
            ("command", "local CLI wrapper such as Claude Code"),
            ("http", "approved HTTP test endpoint"),
            ("browser", "Playwright browser automation"),
        ],
    )

    command = None
    endpoint = None
    browser_config = None
    headed = False
    timeout = 45

    if provider == "command":
        preset = choose(
            "\nCommand preset",
            [
                ("claude", "Claude Code response-only wrapper"),
                ("custom", "custom command that reads case JSON on stdin"),
            ],
        )
        if preset == "claude":
            command = "claude-code-wrapper --mode response-only --max-budget-usd 0.25"
            timeout = 180
        else:
            command = ask("Command")
            timeout = int(ask("Timeout seconds", "180"))
    elif provider == "http":
        endpoint = ask("HTTP endpoint")
        timeout = int(ask("Timeout seconds", "45"))
    elif provider == "browser":
        browser_config = ask("Browser config path", "browser_targets/claude_template.json")
        headed = choose("Browser mode", [("headed", "show browser"), ("headless", "hide browser")]) == "headed"
        timeout = int(ask("Timeout seconds", "120"))

    report = ask("Report path", f"reports/{provider}_report.json")
    verbose = choose("Verbose output", [("yes", "show each case"), ("no", "summary only")]) == "yes"

    args = argparse.Namespace(
        provider=provider,
        endpoint=endpoint,
        header=[],
        command=command,
        browser_config=browser_config,
        headed=headed,
        slow_mo=0,
        timeout=timeout,
        report=report,
        fail_on_review=False,
        limit=None,
        verbose=verbose,
        compact_status=False,
        show_findings=False,
        only_findings=False,
        trace=False,
        trace_limit=4000,
        trace_file=None,
        html_report=None,
    )
    return run_cases(args, cases)


def run_cases(args: argparse.Namespace, cases: list[dict[str, Any]]) -> int:
    headers = build_headers(args.header)
    browser_config = load_json(Path(args.browser_config)) if args.provider == "browser" and args.browser_config else {}
    color = use_color()
    trace_file = Path(args.trace_file) if getattr(args, "trace_file", None) else None
    trace_handle = None

    if args.provider == "http" and not args.endpoint:
        raise SystemExit("--endpoint is required for --provider http")
    if args.provider == "command" and not args.command:
        raise SystemExit("--command is required for --provider command")
    if args.provider == "browser" and not args.browser_config:
        raise SystemExit("--browser-config is required for --provider browser")

    if trace_file:
        trace_file.parent.mkdir(parents=True, exist_ok=True)
        trace_handle = trace_file.open("w", encoding="utf-8")
        print(f"{tagged_label('INFO', color)} Writing prompt and response trace: {trace_file}")

    results = []
    displayed_case_blocks = 0
    try:
        for case in cases:
            pre_response_trace = getattr(args, "trace", False) and not getattr(args, "verbose", False)
            if pre_response_trace:
                trace_case_start(case, args.provider, browser_config, int(getattr(args, "trace_limit", 4000) or 0), sys.stdout, color)
            if trace_handle:
                trace_case_start(case, args.provider, browser_config, 0, trace_handle, False)
            target_result = call_target(case, args, headers, browser_config)
            if pre_response_trace:
                trace_case_response(case, target_result, int(getattr(args, "trace_limit", 4000) or 0), sys.stdout, color)
            if trace_handle:
                trace_case_response(case, target_result, 0, trace_handle, False)
                trace_handle.flush()
            scored = score_case(case, target_result)
            results.append(scored)
            show_case_status = getattr(args, "verbose", False) or getattr(args, "compact_status", False)
            hide_passing = getattr(args, "only_findings", False) and scored["status"] == "pass"
            if show_case_status and not hide_passing:
                if displayed_case_blocks:
                    if getattr(args, "verbose", False):
                        print(VERBOSE_CASE_SEPARATOR)
                    else:
                        print()
                status = str(scored["status"])
                findings = scored.get("findings", [])
                summary = compact_findings_summary(findings, color)
                suffix = f"  {summary}" if summary else ""
                print(f"{severity_label(status, color)} {scored['id']}: {status_text(status, color)} ({scored['elapsed_ms']} ms){suffix}")
                if getattr(args, "verbose", False):
                    print_verbose_case_io(
                        case,
                        args.provider,
                        browser_config,
                        target_result,
                        int(getattr(args, "trace_limit", 4000) or 0),
                        sys.stdout,
                        color,
                    )
                if getattr(args, "show_findings", False):
                    for finding in findings:
                        print(f"  - {finding_label(finding, color)} {finding.get('check')}: {finding.get('detail')}")
                displayed_case_blocks += 1
    finally:
        if trace_handle:
            trace_handle.close()

    cases_name = getattr(args, "cases_name", None) or getattr(args, "cases", "cases")
    report_path = Path(args.report) if args.report else default_report_path(args.provider, str(cases_name))
    metadata = run_metadata(args)
    write_report(report_path, args.provider, results, metadata)
    html_report_path = resolve_html_report_path(getattr(args, "html_report", None), report_path)
    if html_report_path:
        report = load_json(report_path)
        write_html_report(html_report_path, report, report_path)

    failed = sum(1 for item in results if item["status"] == "fail")
    review = sum(1 for item in results if item["status"] == "review")
    passed = sum(1 for item in results if item["status"] == "pass")
    print(f"{tagged_label('INFO', color)} Report: {report_path}")
    if html_report_path:
        print(f"{tagged_label('INFO', color)} HTML report: {html_report_path}")
    if getattr(args, "limit", None) and getattr(args, "original_case_count", None):
        print(f"{tagged_label('INFO', color)} Limit: sent {len(results)} of {args.original_case_count} loaded cases")
    print_summary_graph({"pass": passed, "review": review, "fail": failed, "total": len(results)}, color=color)

    if failed or (review and args.fail_on_review):
        return 1
    return 0


def call_target(
    case: dict[str, Any],
    args: argparse.Namespace,
    headers: dict[str, str],
    browser_config: dict[str, Any],
) -> TargetResult:
    if args.provider == "mock":
        return call_mock(case, args.timeout)
    if args.provider == "http":
        return call_http(case, args.endpoint, headers, args.timeout)
    if args.provider == "browser":
        return call_browser(case, browser_config, args.headed, args.slow_mo, args.timeout)
    return call_command(case, args.command, args.timeout)


def run_metadata(args: argparse.Namespace) -> dict[str, Any]:
    fields = {
        "trace_file": getattr(args, "trace_file", None),
        "cases_name": getattr(args, "cases_name", None),
        "limit": getattr(args, "limit", None),
        "original_case_count": getattr(args, "original_case_count", None),
    }
    metadata: dict[str, Any] = {}
    for key, value in fields.items():
        if value is None:
            continue
        metadata[key] = int(value) if key in {"limit", "original_case_count"} else str(value)
    return metadata


def limit_trace_text(text: str, limit: int) -> str:
    if limit <= 0 or len(text) <= limit:
        return text
    omitted = len(text) - limit
    return f"{text[:limit]}\n[trace truncated: {omitted} characters omitted]"


def compact_findings_summary(findings: list[dict[str, str]], color: bool) -> str:
    if not findings:
        return ""
    counts: dict[str, int] = {}
    for finding in findings:
        label = visible_tag(finding_label(finding, False))
        counts[label] = counts.get(label, 0) + 1
    priority = ["SECRET", "CRITICAL", "FAIL", "WARN", "REVIEW"]
    parts = []
    for label in priority:
        count = counts.get(label)
        if count:
            parts.append(f"{tagged_label(label, color)} x{count}")
    return " ".join(parts)


def visible_tag(label: str) -> str:
    return label.strip("[]").upper()


def print_verbose_case_io(
    case: dict[str, Any],
    provider: str,
    browser_config: dict[str, Any],
    result: TargetResult,
    limit: int,
    stream: Any,
    color: bool,
) -> None:
    case_id = case.get("id", "case")
    case_name = case.get("name", "")
    print(f"  {tagged_label('PROMPT', color)}", file=stream, flush=True)
    if case_name:
        print(f"    Case: {case_name}", file=stream, flush=True)
    print(f"    Provider: {provider}", file=stream, flush=True)
    print(indent_block(limit_trace_text(render_case_input(case, provider, browser_config), limit), "    "), file=stream, flush=True)
    print(f"  {tagged_label('RESPONSE', color)}", file=stream, flush=True)
    if result.error:
        print(f"    {tagged_label('WARN', color)} Target error: {result.error}", file=stream, flush=True)
    response = result.text or ""
    if not response:
        response = "[empty response]"
    print(indent_block(limit_trace_text(response, limit), "    "), file=stream, flush=True)
    print(f"  End {case_id}", file=stream, flush=True)


def indent_block(text: str, prefix: str) -> str:
    return "\n".join(f"{prefix}{line}" if line else prefix.rstrip() for line in text.splitlines())


def trace_case_start(
    case: dict[str, Any],
    provider: str,
    browser_config: dict[str, Any],
    limit: int,
    stream: Any,
    color: bool,
) -> None:
    case_id = case.get("id", "case")
    case_name = case.get("name", "")
    print(f"\n{tagged_label('TRACE', color)} {case_id} input start", file=stream, flush=True)
    if case_name:
        print(f"Case: {case_name}", file=stream, flush=True)
    print(f"Provider: {provider}", file=stream, flush=True)
    print(limit_trace_text(render_case_input(case, provider, browser_config), limit), file=stream, flush=True)
    print(f"{tagged_label('TRACE', color)} {case_id} input end", file=stream, flush=True)


def trace_case_response(case: dict[str, Any], result: TargetResult, limit: int, stream: Any, color: bool) -> None:
    case_id = case.get("id", "case")
    print(f"{tagged_label('TRACE', color)} {case_id} response start", file=stream, flush=True)
    if result.error:
        print(f"{tagged_label('WARN', color)} Target error: {result.error}", file=stream, flush=True)
    print(limit_trace_text(result.text or "", limit), file=stream, flush=True)
    print(f"{tagged_label('TRACE', color)} {case_id} response end\n", file=stream, flush=True)


def claude_code_command(args: argparse.Namespace) -> str:
    mode = "agent-sandbox" if getattr(args, "agent_files", False) and args.mode == "response-only" else args.mode
    command = [
        "claude-code-wrapper",
        "--mode",
        mode,
        "--model",
        args.model,
        "--max-budget-usd",
        str(args.budget),
    ]
    if getattr(args, "agent_files", False):
        command.extend(["--input-mode", "files"])
    if args.workdir:
        command.extend(["--workdir", args.workdir])
    return shlex.join(command)


def run_claude_code(args: argparse.Namespace) -> int:
    test_name = getattr(args, "test", "direct")
    cases = load_cases(resolve_cases_path(test_name), args.mutations)
    cases, original_case_count = apply_case_limit(cases, args.limit)
    run_args = argparse.Namespace(
        provider="command",
        endpoint=None,
        header=[],
        command=claude_code_command(args),
        browser_config=None,
        headed=False,
        slow_mo=0,
        timeout=args.timeout,
        report=args.report,
        fail_on_review=args.fail_on_review,
        limit=args.limit,
        original_case_count=original_case_count,
        verbose=args.verbose,
        compact_status=not args.quiet,
        show_findings=args.show_findings,
        only_findings=args.only_findings,
        trace=args.trace,
        trace_limit=args.trace_limit,
        trace_file=args.trace_file,
        html_report=args.html_report,
        cases_name=f"claude-code_{test_name}{'_mutations' if args.mutations else ''}{'_agent-files' if args.agent_files else ''}{'_limit' + str(args.limit) if args.limit else ''}",
    )
    return run_cases(run_args, cases)


def main() -> int:
    color_mode = color_mode_from_argv()
    print_banner(color_mode)

    parser = create_parser()
    if len(sys.argv) == 1:
        print()
        parser.print_help()
        return 0

    args = parser.parse_args()

    if args.command_name == "banner":
        return 0

    if args.command_name == "list-suites":
        print_suites()
        return 0

    if args.command_name == "examples":
        print_examples(args.target)
        return 0

    if args.command_name == "doctor":
        return run_doctor(args.target, args.browser_config, args.workdir)

    if args.command_name == "claude-code":
        return run_claude_code(args)

    if args.command_name == "wizard":
        return run_wizard(args.color)

    if args.command_name == "init-project":
        init_project(Path(args.output), args.force)
        return 0

    if args.command_name == "init-browser-config":
        write_browser_template(Path(args.output), args.base_url)
        print(f"Wrote browser config template: {args.output}")
        return 0

    if args.command_name == "presets":
        if args.preset_command == "list":
            print(render_preset_list())
            return 0
        if args.preset_command == "show":
            print(render_preset(args.name))
            return 0
        if args.preset_command == "init":
            write_preset(args.name, Path(args.output), args.force)
            print(f"Wrote preset: {args.output}")
            return 0

    if args.command_name == "summarize":
        return summarize_report(Path(args.report), args.plain, args.html_report)

    if args.command_name == "compare":
        return compare_reports_command(Path(args.before), Path(args.after), args.plain, args.html_report)

    cases = load_cases(resolve_cases_path(args.cases), getattr(args, "mutations", False))
    cases, original_case_count = apply_case_limit(cases, getattr(args, "limit", None))
    args.original_case_count = original_case_count
    args.cases_name = f"{args.cases}{'_mutations' if getattr(args, 'mutations', False) else ''}{'_limit' + str(args.limit) if getattr(args, 'limit', None) else ''}"

    if args.command_name == "list-cases":
        print_case_catalog(cases)
        return 0

    if args.command_name == "validate":
        errors = validate_cases(cases)
        if errors:
            print("Case validation failed:")
            for error in errors:
                print(f"- {error}")
            return 1
        print(f"{tagged_label('OK')} Case validation passed: {len(cases)} cases")
        return 0

    return run_cases(args, cases)


if __name__ == "__main__":
    raise SystemExit(main())
