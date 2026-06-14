# SentinelProbe

SentinelProbe is a CLI for authorized AI prompt-injection and agent-boundary testing. It runs repeatable YAML cases against AI assistants, enterprise search tools, browser-based AI apps, HTTP test shims, and local CLI agents, then scores responses with deterministic checks.

Use it only with approved systems, approved accounts, fake documents, and fake secrets.

## Install

From source:

```bash
python3 -m pip install .
```

For isolated installs:

```bash
pipx install .
```

For browser automation:

```bash
python3 -m pip install '.[browser]'
python3 -m playwright install chromium
```

After PyPI publishing:

```bash
pipx install sentinelprobe
```

## Quick Start

Check local setup:

```bash
sentinelprobe doctor
sentinelprobe doctor --target claude-code
sentinelprobe doctor --target browser
```

List bundled suites:

```bash
sentinelprobe list-suites
```

Run the local mock baseline:

```bash
sentinelprobe run --cases builtin --provider mock --verbose
```

Run Claude Code with response-only defaults:

```bash
sentinelprobe claude-code
```

Run file-based coding-agent prompt injection against Claude Code:

```bash
sentinelprobe claude-code --test agent-files --agent-files --verbose --only-findings --html-report
```

Limit cost during smoke tests:

```bash
sentinelprobe claude-code --test indirect --mutations --limit 5 --verbose --only-findings
```

Create HTML and trace artifacts:

```bash
sentinelprobe claude-code --test agent-files --agent-files --html-report --trace-file reports/agent_files_trace.txt
```

Compare two reports:

```bash
sentinelprobe compare --before reports/baseline.json --after reports/latest.json --html-report
```

Run source-tree regression checks during development:

```bash
python3 scripts/check.py
python3 scripts/check.py --build --wheel-smoke
```

## Test Suites

- `direct-basic`: basic direct prompt injection cases.
- `direct-advanced`: advanced direct prompt injection cases.
- `direct`: basic plus advanced direct prompt injection.
- `indirect`: inline retrieved-content prompt injection cases.
- `agent-files`: file-based coding-agent prompt injection cases.
- `builtin`: all bundled cases.

Use `--mutations` to expand suites that define deterministic variants.

## Providers

- `mock`: local safe baseline.
- `http`: approved API or internal test shim.
- `command`: local wrapper around a CLI agent.
- `browser`: Playwright-driven browser session for approved browser-based AI tools.

## Reports

SentinelProbe writes JSON reports by default. Add `--html-report` for a portable review artifact and `--trace-file` for full prompt and response evidence.

Findings use:

- `pass`: no deterministic issue found.
- `review`: suspicious output or incomplete safe handling that needs human triage.
- `fail`: deterministic unsafe behavior, including fake secret leakage.

## Documentation

Detailed usage, provider setup, case format, scoring behavior, browser workflow, and PyPI notes are in [docs/usage.md](docs/usage.md).

## Safety Scope

- Use only approved systems and accounts.
- Use fake documents, fake secrets, and sandbox data.
- Do not test destructive actions, credential theft, persistence, malware, or bypass logic.
- Treat automated findings as triage signals that need manual validation.
