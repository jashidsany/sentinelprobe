"""Provider implementations and provider-specific prompt rendering."""

from __future__ import annotations

import json
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from prompt_injection_harness.cases import extract_business_lines, iter_case_sources


TEXT_RESPONSE_KEYS = ("answer", "result", "response", "text", "message", "content", "output")
BROWSER_REQUIRED_KEYS = ("base_url", "profile_dir", "prompt_selector", "submit_selector", "response_selector")


@dataclass
class TargetResult:
    ok: bool
    text: str
    error: str | None = None
    elapsed_ms: int = 0


def call_mock(case: dict[str, Any], timeout: int) -> TargetResult:
    del timeout
    start = time.monotonic()
    mock_response = (case.get("metadata") or {}).get("mock_response")
    if mock_response:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return TargetResult(ok=True, text=str(mock_response), elapsed_ms=elapsed_ms)

    business_lines: list[str] = []
    citations: list[str] = []
    for label, content in iter_case_sources(case):
        citations.append(label)
        business_lines.extend(extract_business_lines(content))
    if not business_lines:
        business_lines = ["No business content found."]
    text = " ".join(business_lines)
    if citations:
        text += "\n\nSources: " + "; ".join(citations)
    elapsed_ms = int((time.monotonic() - start) * 1000)
    return TargetResult(ok=True, text=text, elapsed_ms=elapsed_ms)


def call_http(case: dict[str, Any], endpoint: str, headers: dict[str, str], timeout: int) -> TargetResult:
    body = json.dumps(public_case_payload(case)).encode("utf-8")
    request = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")
    start = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError) as exc:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return TargetResult(ok=False, text="", error=str(exc), elapsed_ms=elapsed_ms)

    elapsed_ms = int((time.monotonic() - start) * 1000)
    return TargetResult(ok=True, text=extract_text(raw), elapsed_ms=elapsed_ms)


def call_command(case: dict[str, Any], command: str, timeout: int) -> TargetResult:
    start = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            input=json.dumps(public_case_payload(case)),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            shell=True,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return TargetResult(ok=False, text="", error=f"command timed out: {exc}", elapsed_ms=elapsed_ms)

    elapsed_ms = int((time.monotonic() - start) * 1000)
    if completed.returncode != 0:
        return TargetResult(ok=False, text=completed.stdout, error=completed.stderr.strip(), elapsed_ms=elapsed_ms)
    return TargetResult(ok=True, text=extract_text(completed.stdout), elapsed_ms=elapsed_ms)


def call_browser(case: dict[str, Any], config: dict[str, Any], headed: bool, slow_mo: int, timeout: int) -> TargetResult:
    start = time.monotonic()
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except ImportError:
        return TargetResult(
            ok=False,
            text="",
            error="Playwright is not installed. Run 'python3 -m pip install playwright' and 'python3 -m playwright install chromium'.",
            elapsed_ms=0,
        )

    missing = missing_browser_config_keys(config)
    if missing:
        return TargetResult(ok=False, text="", error=f"Browser config missing: {', '.join(missing)}", elapsed_ms=0)

    prompt = browser_prompt_for_case(case, config)
    timeout_ms = timeout * 1000

    try:
        with sync_playwright() as p:
            context = p.chromium.launch_persistent_context(
                user_data_dir=str(config["profile_dir"]),
                headless=not headed,
                slow_mo=slow_mo,
            )
            page = context.pages[0] if context.pages else context.new_page()
            page.set_default_timeout(timeout_ms)
            page.goto(str(config["base_url"]), wait_until=str(config.get("wait_until", "domcontentloaded")))

            if config.get("ready_selector"):
                page.locator(str(config["ready_selector"])).wait_for(state="visible", timeout=timeout_ms)

            before_text = collect_response_text(page, str(config["response_selector"]))
            prompt_box = page.locator(str(config["prompt_selector"])).last
            prompt_box.click()
            fill_prompt(prompt_box, prompt)
            page.locator(str(config["submit_selector"])).last.click()

            response_text = wait_for_response_change(
                page,
                str(config["response_selector"]),
                before_text,
                timeout_ms,
                str(config.get("done_selector", "")),
            )
            if config.get("screenshot_dir"):
                screenshot_dir = Path(str(config["screenshot_dir"]))
                screenshot_dir.mkdir(parents=True, exist_ok=True)
                page.screenshot(path=str(screenshot_dir / f"{case.get('id', 'case')}.png"), full_page=True)
            context.close()
    except PlaywrightTimeoutError as exc:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return TargetResult(ok=False, text="", error=f"browser timeout: {exc}", elapsed_ms=elapsed_ms)
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return TargetResult(ok=False, text="", error=f"browser error: {exc}", elapsed_ms=elapsed_ms)

    elapsed_ms = int((time.monotonic() - start) * 1000)
    return TargetResult(ok=True, text=response_text, elapsed_ms=elapsed_ms)


def browser_prompt_for_case(case: dict[str, Any], config: dict[str, Any]) -> str:
    if config.get("send_documents_inline", True):
        sources = [f"Source: {label}\n{content}" for label, content in iter_case_sources(case)]
        if not sources:
            return str(case.get("user_prompt", "")).strip()
        joined_sources = "\n\n---\n\n".join(sources)
        return (
            f"{case.get('user_prompt', '')}\n\n"
            "Use only the following approved test sources for this authorized security test.\n\n"
            f"{joined_sources}"
        ).strip()
    return str(case.get("user_prompt", ""))


def fill_prompt(locator: Any, prompt: str) -> None:
    try:
        locator.fill(prompt)
    except Exception:
        locator.type(prompt)


def collect_response_text(page: Any, selector: str) -> str:
    loc = page.locator(selector)
    if loc.count() == 0:
        return ""
    return loc.last.inner_text(timeout=1000).strip()


def wait_for_response_change(page: Any, selector: str, before_text: str, timeout_ms: int, done_selector: str) -> str:
    deadline = time.monotonic() + (timeout_ms / 1000)
    last_text = ""
    stable_count = 0
    while time.monotonic() < deadline:
        if done_selector:
            done = page.locator(done_selector)
            if done.count() > 0 and done.last.is_visible():
                text = collect_response_text(page, selector)
                if text:
                    return text
        text = collect_response_text(page, selector)
        if text and text != before_text:
            if text == last_text:
                stable_count += 1
            else:
                stable_count = 0
                last_text = text
            if stable_count >= 3:
                return text
        page.wait_for_timeout(750)
    return last_text or collect_response_text(page, selector)


def public_case_payload(case: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": case.get("id"),
        "name": case.get("name"),
        "category": case.get("category"),
        "user_prompt": case.get("user_prompt"),
        "documents": case.get("documents", []),
        "files": case.get("files", []),
        "metadata": case.get("metadata", {}),
    }


def extract_text(raw: str) -> str:
    stripped = raw.strip()
    if not stripped:
        return ""
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return stripped
    if isinstance(data, str):
        return data
    if isinstance(data, dict):
        for key in TEXT_RESPONSE_KEYS:
            value = data.get(key)
            if isinstance(value, str):
                return value
        return json.dumps(data, ensure_ascii=False, sort_keys=True)
    return json.dumps(data, ensure_ascii=False)


def missing_browser_config_keys(config: dict[str, Any]) -> list[str]:
    return [key for key in BROWSER_REQUIRED_KEYS if not config.get(key)]


def render_case_input(case: dict[str, Any], provider: str, browser_config: dict[str, Any]) -> str:
    if provider == "browser":
        return browser_prompt_for_case(case, browser_config)

    sections = [f"User prompt:\n{case.get('user_prompt', '')}".rstrip()]
    documents = case.get("documents", []) or []
    if documents:
        for index, document in enumerate(documents, start=1):
            sections.append(
                "\n".join(
                    [
                        f"Document {index}: {document.get('title', 'Untitled')}",
                        str(document.get("content", "")),
                    ]
                ).rstrip()
            )
    files = case.get("files", []) or []
    if files:
        for index, file_item in enumerate(files, start=1):
            sections.append(
                "\n".join(
                    [
                        f"File {index}: {file_item.get('path', 'untitled.txt')}",
                        str(file_item.get("content", "")),
                    ]
                ).rstrip()
            )
    return "\n\n---\n\n".join(sections)
