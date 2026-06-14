# SentinelProbe Package Notes

This package contains the SentinelProbe CLI, bundled YAML cases, browser target templates, example targets, and Claude Code wrapper.

Main command:

```bash
sentinelprobe --help
```

Useful starting points:

```bash
sentinelprobe doctor
sentinelprobe list-suites
sentinelprobe run --cases builtin --provider mock --verbose
sentinelprobe claude-code --test agent-files --agent-files --verbose --only-findings --html-report
```

Detailed project documentation is in the repository root README and `docs/usage.md`.

Use SentinelProbe only with approved systems, approved accounts, fake documents, and fake secrets.
