# Privacy Proxy

## Overview

This repo adds a `PostToolUse` hook for Claude Code that redacts possible PII in MCP tool output before the output is passed back to the model.

This project is built on top of **OpenAI Privacy Filter (OPF)**, the model and CLI used here for PII detection and masking.

- OpenAI Privacy Filter repo: <https://github.com/openai/privacy-filter>
- OpenAI Privacy Filter docs in upstream repo: <https://github.com/openai/privacy-filter/blob/main/README.md>

In short:

- It runs for MCP tools (`matcher: mcp__.*`).
- It scans and redacts string values inside `tool_response` using OPF.
- It preserves canonical UUID strings.
- If redaction fails, it blocks the response (fail closed).

## How to setup the Claude Code hook

1. Clone this repo and install OPF from `privacy-filter` at the project root:

```bash
git clone <your-fork-or-repo-url> privacy_proxy
cd privacy_proxy
git clone https://github.com/openai/privacy-filter.git privacy-filter
cd privacy-filter
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
cd ..
```

2. Configure Claude hooks.

Project-level (`.claude/settings.json`):

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"$CLAUDE_PROJECT_DIR/claude_hooks/post_tool_use_pii_redact.py\""
          }
        ]
      }
    ]
  }
}
```

Global (`~/.claude/settings.json`, optional):

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"$HOME/.claude/privacy_proxy/claude_hooks/post_tool_use_pii_redact.py\""
          }
        ]
      }
    ]
  }
}
```

3. Restart Claude Code / Claude Desktop session after updating settings.

4. Quick check:

```bash
./privacy-filter/.venv/bin/opf --device cpu "Alice was born on 1990-01-02."
```

## Limitations of the current setup

- It only covers `PostToolUse` for MCP tool outputs (`mcp__.*`), not other hook events.
- Only string leaves are redacted; non-string values are passed through unchanged.
- UUID passthrough is allowlisted, but non-UUID identifiers are still scanned/redacted.
- Protection quality depends on OPF detection quality.
- If OPF is missing, times out, or errors, the hook blocks the model step.
- This is a guardrail, not a compliance guarantee.
- It does not stop data from being sent by MCP servers before output reaches Claude.
