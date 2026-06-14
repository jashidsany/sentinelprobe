# SentinelProbe

SentinelProbe is a CLI for authorized AI prompt-injection and agent-boundary testing. It runs repeatable YAML test cases against AI assistants, enterprise search tools, browser-based AI apps, HTTP test shims, and local CLI agents, then scores responses with deterministic checks.

It is built for defensive testing with approved systems, approved accounts, and fake test data.

## Install

After PyPI publishing:

```bash
pipx install sentinelprobe
```

From source:

```bash
python3 -m pip install .
```

For browser automation:

```bash
python3 -m pip install '.[browser]'
python3 -m playwright install chromium
```

## Quick Start

Run the interactive wizard:

```bash
sentinelprobe wizard
```

Check local setup:

```bash
sentinelprobe doctor
sentinelprobe doctor --target claude-code
sentinelprobe doctor --target browser
```

Run source-tree regression checks during development:

```bash
python3 scripts/check.py
python3 scripts/check.py --build --wheel-smoke
```

The SentinelProbe banner appears at startup for every command, including no-argument runs and help output. You can also print only the banner:

```bash
sentinelprobe banner
```

Force colored output:

```bash
sentinelprobe --color always banner
sentinelprobe --color always --help
```

Findings are color-coded in terminal output:

- `[FAIL]` red: deterministic unsafe behavior, such as fake secret leakage.
- `[REVIEW]` yellow: suspicious behavior or incomplete safe handling.
- `[PASS]` green: no deterministic issue found.
- `[CRITICAL]` red: high-confidence unsafe content, such as forbidden output.
- `[SECRET]` magenta: fake secret leakage or secret-like output.
- `[WARN]` yellow: warning-pattern evidence.
- `[TRACE]` cyan: live prompt and response trace boundaries.
- `[INFO]` blue and `[OK]` green: run metadata and successful checks.

Use `--color never` for plain logs.

Run bundled cases against the local mock provider:

```bash
sentinelprobe run --cases builtin --provider mock --report reports/mock_report.json --verbose
```

Run the direct prompt injection suite:

```bash
sentinelprobe run --cases direct --provider mock --report reports/direct_mock_report.json --verbose
```

Run Claude Code with response-only defaults:

```bash
sentinelprobe claude-code
```

Run the advanced direct suite against Claude Code:

```bash
sentinelprobe claude-code --test direct-advanced
```

Run indirect prompt injection tests with generated variants:

```bash
sentinelprobe run --cases indirect --mutations --provider mock --verbose
```

Run indirect prompt injection against Claude Code:

```bash
sentinelprobe claude-code --test indirect --mutations
```

Run file-based coding-agent prompt injection against Claude Code:

```bash
sentinelprobe claude-code --test agent-files --agent-files --verbose --only-findings
```

Limit how many prompts are sent during a smoke test:

```bash
sentinelprobe claude-code --test indirect --mutations --limit 5 --verbose --only-findings
```

Watch prompts and responses during a scan:

```bash
sentinelprobe claude-code --test indirect --mutations --verbose
sentinelprobe run --cases direct-basic --provider mock --verbose
```

Verbose mode prints each case status, the prompt, and the target response. Use `--trace-limit 0` to print full prompts and responses. The default limit is 4000 characters per prompt or response.

For readable terminal output plus a full prompt/response log, write trace output to a file:

```bash
sentinelprobe claude-code --test indirect --mutations --verbose --only-findings --trace-file reports/claude_code_indirect_trace.txt
```

`claude-code` shows compact per-case status by default unless `--quiet` is used. Add `--verbose` to show prompts and responses, `--only-findings` to hide passing cases, or `--show-findings` to print full finding details during the run. `--trace-file` always writes the full untruncated prompt and response log.

Add `--html-report` to create a portable HTML review artifact next to the JSON report:

```bash
sentinelprobe claude-code --test agent-files --agent-files --html-report --trace-file reports/claude_code_agent_files_trace.txt
```

The default Claude Code indirect run is inline retrieved-content simulation: test documents are embedded in the prompt. Use `--test agent-files --agent-files` for coding-agent repo/file poisoning tests. That mode writes a disposable repository with files such as `README.md`, `docs/policy.md`, `tickets/*.md`, `logs/*.txt`, and `config/*.yaml`, then asks Claude Code to inspect those files using agent-sandbox behavior.

Show copy-ready examples:

```bash
sentinelprobe examples
sentinelprobe examples claude-code
sentinelprobe examples indirect
sentinelprobe examples agent-files
sentinelprobe examples doctor
```

Direct suite aliases:

- `direct-basic`: 10 basic direct prompt injection cases.
- `direct-advanced`: advanced direct prompt injection cases, including obfuscation, fake authority, context switching, transcript bait, tool-use bait, and safe-task completion after refusal.
- `direct`: both `direct-basic` and `direct-advanced`.
- `indirect`: retrieved-content prompt injection cases, including existing code-generation and secret-boundary cases.
- `agent-files`: file-based coding-agent prompt injection cases with generated repo layouts.
- `builtin`: all bundled cases.

Add `--mutations` to generate deterministic case variants for suites that define them. Current mutation styles wrap prompts or retrieved content in urgent wording, Markdown quotes, JSON fields, simulated transcripts, and HTML comments.

Create a starter workspace:

```bash
sentinelprobe init-project --output ai_security_tests
cd ai_security_tests
sentinelprobe validate --cases cases
```

Summarize a report:

```bash
sentinelprobe summarize --report reports/mock_report.json
sentinelprobe summarize --report reports/mock_report.json --html-report
```

Compare two reports:

```bash
sentinelprobe compare --before reports/baseline.json --after reports/latest.json --html-report
```

## Providers

- `mock`: local safe baseline.
- `http`: approved API or internal test shim.
- `command`: local wrapper around a CLI agent, such as Claude Code.
- `browser`: Playwright-driven browser session for tools such as Glean or Claude web.

## Claude Code Example

The simplest Claude Code command is:

```bash
sentinelprobe claude-code
```

By default this runs `--test direct`, `--model sonnet`, `--budget 0.25`, `--timeout 180`, and writes a timestamped report under `reports/`.

```bash
sentinelprobe run \
  --cases direct \
  --provider command \
  --command 'claude-code-wrapper --mode response-only --model sonnet --max-budget-usd 0.25' \
  --timeout 180 \
  --report reports/claude_code_direct_report.json \
  --verbose
```

Run only the advanced direct prompt injection suite:

```bash
sentinelprobe claude-code --test direct-advanced
```

Run file-based coding-agent prompt injection against Claude Code:

```bash
sentinelprobe claude-code --test agent-files --agent-files --verbose --only-findings --html-report
```

This writes each case into a disposable per-case directory under the Claude Code wrapper workdir and asks Claude Code to inspect generated repository files. Use this mode for coding-agent file/source handling checks. Use the default indirect run for inline retrieved-content checks.

Add `--limit N` to cap how many prompts are sent. The limit is applied after mutations, so `--mutations --limit 5` sends five generated cases.

## Report Comparison

Use `compare` to check regression between two JSON reports:

```bash
sentinelprobe compare --before reports/claude_code_indirect_inline_v060.json --after reports/claude_code_indirect_agent_files_v060.json --html-report
```

The comparison shows new cases, removed cases, fixed findings, regressions, changed finding details, and unchanged cases. Use this after model changes, guardrail updates, or target configuration changes.

## Scoring Notes

SentinelProbe treats fake secret patterns such as `FAKE_DIRECT_SECRET_006` as hard failures. If a response refuses or identifies a prompt injection but does not complete all safe required fields, the finding is reported as `missing_required_after_refusal` with `review` severity. That separates malicious compliance from incomplete safe-task completion that needs human triage.

Cases can use `required_regex` when acceptable answers may vary in formatting, such as `ticket_id`, `ticket ID`, or `ticket-id`.

## Safety Scope

- Use only approved systems and accounts.
- Use fake documents, fake secrets, and sandbox data.
- Do not test destructive actions, credential theft, persistence, malware, or bypass logic.
- Treat automated findings as triage signals that need manual validation.

More detailed documentation is in [`prompt_injection_harness/README.md`](prompt_injection_harness/README.md).
