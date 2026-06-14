"""CLI-facing report comparison helpers."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from prompt_injection_harness.html_reports import resolve_compare_html_path, write_compare_html
from prompt_injection_harness.reports import compare_reports, load_json


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
        "INFO": "34;1",
        "OK": "32;1",
        "WARN": "33;1",
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


def compare_kind_label(kind: str, color: bool | None = None) -> str:
    tag = {
        "new": "INFO",
        "removed": "WARN",
        "fixed": "OK",
        "regressed": "FAIL",
        "changed": "REVIEW",
        "unchanged": "PASS",
    }.get(kind, "REVIEW")
    return tagged_label(tag, color)


def compare_reports_command(before_path: Path, after_path: Path, plain: bool = False, html_report: str | None = None) -> int:
    before = load_json(before_path)
    after = load_json(after_path)
    comparison = compare_reports(before, after)
    color = use_color()
    html_report_path = resolve_compare_html_path(html_report, before_path, after_path)
    if html_report_path:
        write_compare_html(html_report_path, comparison, before_path, after_path)

    summary = comparison["summary"]
    print(f"{tagged_label('INFO', color)} Before: {before_path}")
    print(f"{tagged_label('INFO', color)} After: {after_path}")
    if html_report_path:
        print(f"{tagged_label('INFO', color)} HTML report: {html_report_path}")
    if plain:
        print(
            "Compare: "
            f"new={summary.get('new', 0)} "
            f"removed={summary.get('removed', 0)} "
            f"fixed={summary.get('fixed', 0)} "
            f"regressed={summary.get('regressed', 0)} "
            f"changed={summary.get('changed', 0)} "
            f"unchanged={summary.get('unchanged', 0)} "
            f"total={summary.get('total', 0)}"
        )
    else:
        print("Compare")
        for key in ("new", "removed", "fixed", "regressed", "changed", "unchanged"):
            print(f"{key:<10} {summary.get(key, 0)}")
        print(f"total      {summary.get('total', 0)}")

    for change in comparison.get("changes", []):
        if not isinstance(change, dict) or change.get("kind") == "unchanged":
            continue
        kind = str(change.get("kind", "changed"))
        before_status = change.get("before_status") or "missing"
        after_status = change.get("after_status") or "missing"
        print(
            f"{compare_kind_label(kind, color)} {change.get('id')}: "
            f"{kind} ({before_status} -> {after_status})"
        )
    return 0
