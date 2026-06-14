"""Portable HTML report renderers for SentinelProbe."""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any


def default_html_report_path(report_path: Path) -> Path:
    return report_path.with_suffix(".html")


def resolve_html_report_path(value: str | None, report_path: Path) -> Path | None:
    if value is None:
        return None
    if value == "":
        return default_html_report_path(report_path)
    return Path(value)


def default_compare_html_path(before_path: Path, after_path: Path) -> Path:
    before_name = before_path.with_suffix("").name
    after_name = after_path.with_suffix("").name
    return Path("reports") / f"compare_{before_name}_to_{after_name}.html"


def resolve_compare_html_path(value: str | None, before_path: Path, after_path: Path) -> Path | None:
    if value is None:
        return None
    if value == "":
        return default_compare_html_path(before_path, after_path)
    return Path(value)


def html_escape(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def html_link(path_value: Any, label: str, base_path: Path | None = None) -> str:
    if not path_value:
        return ""
    path = Path(str(path_value))
    href_path = path
    if base_path:
        try:
            href_path = path.resolve().relative_to(base_path.parent.resolve())
        except (OSError, ValueError):
            href_path = path
    return f'<a href="{html_escape(href_path.as_posix())}">{html_escape(label)}</a>'


def status_class(status: Any) -> str:
    normalized = str(status or "review").lower()
    if normalized in {"pass", "review", "fail"}:
        return normalized
    return "review"


def response_excerpt(text: Any, limit: int = 1600) -> str:
    value = str(text or "")
    if len(value) <= limit:
        return value
    return f"{value[:limit]}\n[truncated: {len(value) - limit} characters omitted]"


def write_html_report(path: Path, report: dict[str, Any], source_report_path: Path | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    summary = report.get("summary", {}) or {}
    results = [item for item in report.get("results", []) if isinstance(item, dict)]
    non_pass = [item for item in results if item.get("status") != "pass"]
    metadata = report.get("metadata", {}) or {}
    source_report_link = html_link(source_report_path, "JSON report", path) if source_report_path else ""
    trace_link = html_link(metadata.get("trace_file"), "Trace file", path)
    links = " ".join(item for item in (source_report_link, trace_link) if item)

    finding_cards = []
    for result in non_pass:
        status = status_class(result.get("status"))
        findings = result.get("findings", []) or []
        finding_items = "\n".join(
            f"<li><strong>{html_escape(finding.get('check'))}</strong>: {html_escape(finding.get('detail'))}</li>"
            for finding in findings
            if isinstance(finding, dict)
        )
        if not finding_items:
            finding_items = "<li>No finding details recorded.</li>"
        finding_cards.append(
            "\n".join(
                [
                    f'<section class="case {status}">',
                    f'<div class="case-head"><span class="badge {status}">{html_escape(status.upper())}</span> '
                    f'<strong>{html_escape(result.get("id"))}</strong> {html_escape(result.get("name"))}</div>',
                    f'<div class="meta">Category: {html_escape(result.get("category"))} | Elapsed: {html_escape(result.get("elapsed_ms"))} ms</div>',
                    f"<ul>{finding_items}</ul>",
                    "<details open><summary>Response excerpt</summary>",
                    f"<pre>{html_escape(response_excerpt(result.get('response')))}</pre>",
                    "</details>",
                    "</section>",
                ]
            )
        )

    if not finding_cards:
        finding_cards.append('<section class="case pass"><strong>No review or fail findings.</strong></section>')

    rows = []
    for result in results:
        status = status_class(result.get("status"))
        rows.append(
            "<tr>"
            f'<td><span class="badge {status}">{html_escape(status.upper())}</span></td>'
            f"<td>{html_escape(result.get('id'))}</td>"
            f"<td>{html_escape(result.get('name'))}</td>"
            f"<td>{html_escape(result.get('category'))}</td>"
            f"<td>{html_escape(result.get('elapsed_ms'))}</td>"
            f"<td>{html_escape(len(result.get('findings', []) or []))}</td>"
            "</tr>"
        )

    generated_at = html_escape(report.get("generated_at", ""))
    provider = html_escape(report.get("provider", ""))
    html_text = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SentinelProbe Report</title>
  <style>
    :root {{ color-scheme: light; --bg: #f6f7f9; --panel: #fff; --text: #20242a; --muted: #5d6673; --line: #d8dde6; }}
    body {{ margin: 0; font-family: Arial, Helvetica, sans-serif; background: var(--bg); color: var(--text); }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 28px; }}
    h1, h2 {{ margin: 0 0 12px; }}
    .top, .case, table {{ background: var(--panel); border: 1px solid var(--line); border-radius: 6px; }}
    .top {{ padding: 20px; margin-bottom: 18px; }}
    .meta {{ color: var(--muted); font-size: 13px; margin: 6px 0; }}
    .cards {{ display: grid; grid-template-columns: repeat(4, minmax(120px, 1fr)); gap: 12px; margin: 18px 0; }}
    .card {{ background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: 14px; }}
    .card strong {{ display: block; font-size: 26px; margin-top: 4px; }}
    .case {{ padding: 14px; margin: 12px 0; border-left-width: 6px; }}
    .case-head {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }}
    .pass {{ border-left-color: #238636; }}
    .review {{ border-left-color: #b7791f; }}
    .fail {{ border-left-color: #c62828; }}
    .badge {{ border-radius: 4px; color: #fff; padding: 2px 7px; font-size: 12px; font-weight: 700; }}
    .badge.pass {{ background: #238636; }}
    .badge.review {{ background: #b7791f; }}
    .badge.fail {{ background: #c62828; }}
    pre {{ white-space: pre-wrap; word-break: break-word; background: #f0f2f5; border: 1px solid var(--line); border-radius: 4px; padding: 12px; }}
    table {{ width: 100%; border-collapse: collapse; overflow: hidden; }}
    th, td {{ border-bottom: 1px solid var(--line); padding: 9px; text-align: left; font-size: 14px; }}
    th {{ background: #eef1f5; }}
    a {{ color: #0b5cad; }}
    @media (max-width: 760px) {{ main {{ padding: 14px; }} .cards {{ grid-template-columns: repeat(2, minmax(120px, 1fr)); }} }}
  </style>
</head>
<body>
<main>
  <section class="top">
    <h1>SentinelProbe Report</h1>
    <div class="meta">Generated: {generated_at} | Provider: {provider}</div>
    <div class="meta">{links}</div>
  </section>
  <section class="cards">
    <div class="card">Total<strong>{html_escape(summary.get('total', 0))}</strong></div>
    <div class="card">Pass<strong>{html_escape(summary.get('pass', 0))}</strong></div>
    <div class="card">Review<strong>{html_escape(summary.get('review', 0))}</strong></div>
    <div class="card">Fail<strong>{html_escape(summary.get('fail', 0))}</strong></div>
  </section>
  <h2>Findings</h2>
  {''.join(finding_cards)}
  <h2>All Results</h2>
  <table>
    <thead><tr><th>Status</th><th>Case</th><th>Name</th><th>Category</th><th>ms</th><th>Findings</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</main>
</body>
</html>
"""
    path.write_text(html_text, encoding="utf-8")


def finding_list_html(findings: list[Any]) -> str:
    items = []
    for finding in findings:
        if isinstance(finding, dict):
            items.append(f"<li>{html_escape(finding.get('severity'))} {html_escape(finding.get('check'))}: {html_escape(finding.get('detail'))}</li>")
    if not items:
        return "<span class=\"muted\">none</span>"
    return f"<ul>{''.join(items)}</ul>"


def write_compare_html(path: Path, comparison: dict[str, Any], before_path: Path, after_path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    summary = comparison.get("summary", {}) or {}
    rows = []
    detail_cards = []
    for change in comparison.get("changes", []) or []:
        if not isinstance(change, dict):
            continue
        kind = str(change.get("kind", "changed"))
        before_status = change.get("before_status") or "missing"
        after_status = change.get("after_status") or "missing"
        rows.append(
            "<tr>"
            f"<td>{html_escape(kind)}</td>"
            f"<td>{html_escape(change.get('id'))}</td>"
            f"<td>{html_escape(change.get('name'))}</td>"
            f"<td>{html_escape(before_status)}</td>"
            f"<td>{html_escape(after_status)}</td>"
            "</tr>"
        )
        if kind != "unchanged":
            detail_cards.append(
                "\n".join(
                    [
                        f'<section class="case {status_class(after_status)}">',
                        f"<h3>{html_escape(kind.upper())}: {html_escape(change.get('id'))} {html_escape(change.get('name'))}</h3>",
                        f'<div class="meta">Before: {html_escape(before_status)} | After: {html_escape(after_status)}</div>',
                        "<div class=\"columns\">",
                        f"<div><h4>Before findings</h4>{finding_list_html(change.get('before_findings', []))}</div>",
                        f"<div><h4>After findings</h4>{finding_list_html(change.get('after_findings', []))}</div>",
                        "</div>",
                        "</section>",
                    ]
                )
            )
    if not detail_cards:
        detail_cards.append('<section class="case pass"><strong>No changed cases.</strong></section>')

    html_text = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SentinelProbe Compare</title>
  <style>
    :root {{ color-scheme: light; --bg: #f6f7f9; --panel: #fff; --text: #20242a; --muted: #5d6673; --line: #d8dde6; }}
    body {{ margin: 0; font-family: Arial, Helvetica, sans-serif; background: var(--bg); color: var(--text); }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 28px; }}
    h1, h2, h3 {{ margin: 0 0 12px; }}
    .top, .case, table, .card {{ background: var(--panel); border: 1px solid var(--line); border-radius: 6px; }}
    .top {{ padding: 20px; margin-bottom: 18px; }}
    .meta, .muted {{ color: var(--muted); font-size: 13px; }}
    .cards {{ display: grid; grid-template-columns: repeat(6, minmax(110px, 1fr)); gap: 12px; margin: 18px 0; }}
    .card {{ padding: 14px; }}
    .card strong {{ display: block; font-size: 24px; margin-top: 4px; }}
    .case {{ padding: 14px; margin: 12px 0; border-left-width: 6px; }}
    .pass {{ border-left-color: #238636; }}
    .review {{ border-left-color: #b7791f; }}
    .fail {{ border-left-color: #c62828; }}
    .columns {{ display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }}
    table {{ width: 100%; border-collapse: collapse; overflow: hidden; }}
    th, td {{ border-bottom: 1px solid var(--line); padding: 9px; text-align: left; font-size: 14px; vertical-align: top; }}
    th {{ background: #eef1f5; }}
    a {{ color: #0b5cad; }}
    @media (max-width: 900px) {{ main {{ padding: 14px; }} .cards {{ grid-template-columns: repeat(2, minmax(110px, 1fr)); }} .columns {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
<main>
  <section class="top">
    <h1>SentinelProbe Compare</h1>
    <div class="meta">Generated: {html_escape(comparison.get('generated_at'))}</div>
    <div class="meta">Before: {html_link(before_path, before_path.name, path)} | After: {html_link(after_path, after_path.name, path)}</div>
  </section>
  <section class="cards">
    <div class="card">Total<strong>{html_escape(summary.get('total', 0))}</strong></div>
    <div class="card">New<strong>{html_escape(summary.get('new', 0))}</strong></div>
    <div class="card">Removed<strong>{html_escape(summary.get('removed', 0))}</strong></div>
    <div class="card">Fixed<strong>{html_escape(summary.get('fixed', 0))}</strong></div>
    <div class="card">Regressed<strong>{html_escape(summary.get('regressed', 0))}</strong></div>
    <div class="card">Changed<strong>{html_escape(summary.get('changed', 0))}</strong></div>
  </section>
  <h2>Changed Cases</h2>
  {''.join(detail_cards)}
  <h2>All Cases</h2>
  <table>
    <thead><tr><th>Change</th><th>Case</th><th>Name</th><th>Before</th><th>After</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</main>
</body>
</html>
"""
    path.write_text(html_text, encoding="utf-8")
