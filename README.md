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

The SentinelProbe banner appears at startup for every command, including no-argument runs and help output. You can also print only the banner:

```bash
sentinelprobe banner
```

Force colored output:

```bash
sentinelprobe --color always banner
sentinelprobe --color always --help
```

Run bundled cases against the local mock provider:

```bash
sentinelprobe run --cases builtin --provider mock --report reports/mock_report.json --verbose
```

Run the direct prompt injection suite:

```bash
sentinelprobe run --cases direct --provider mock --report reports/direct_mock_report.json --verbose
```

Create a starter workspace:

```bash
sentinelprobe init-project --output ai_security_tests
cd ai_security_tests
sentinelprobe validate --cases cases
```

Summarize a report:

```bash
sentinelprobe summarize --report reports/mock_report.json
```

## Providers

- `mock`: local safe baseline.
- `http`: approved API or internal test shim.
- `command`: local wrapper around a CLI agent, such as Claude Code.
- `browser`: Playwright-driven browser session for tools such as Glean or Claude web.

## Claude Code Example

```bash
sentinelprobe run \
  --cases direct \
  --provider command \
  --command 'claude-code-wrapper --mode response-only --model sonnet --max-budget-usd 0.25' \
  --timeout 180 \
  --report reports/claude_code_direct_report.json \
  --verbose
```

## Safety Scope

- Use only approved systems and accounts.
- Use fake documents, fake secrets, and sandbox data.
- Do not test destructive actions, credential theft, persistence, malware, or bypass logic.
- Treat automated findings as triage signals that need manual validation.

More detailed documentation is in [`prompt_injection_harness/README.md`](prompt_injection_harness/README.md).
