#!/usr/bin/env python3
"""PostToolUse hook: redact PII from MCP tool output before model consumption."""

from __future__ import annotations

import sys

from pii_hook_common import (
    OPFHookError,
    OPFScanner,
    emit_json,
    load_hook_payload,
    redact_recursive,
)


def main() -> int:
    try:
        payload = load_hook_payload()
        if payload.get("hook_event_name") != "PostToolUse":
            return 0

        tool_response = payload.get("tool_response")
        if tool_response is None:
            return 0

        scanner = OPFScanner()
        redaction = redact_recursive(tool_response, scanner)

        if redaction.span_count <= 0:
            return 0

        emit_json(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "additionalContext": (
                        f"PII guard redacted {redaction.span_count} span(s) from MCP tool output before model use."
                    ),
                    "updatedMCPToolOutput": redaction.value,
                }
            }
        )
        return 0

    except OPFHookError as exc:
        # If post-redaction fails, block the next model step to avoid leaking raw output.
        emit_json(
            {
                "decision": "block",
                "reason": (
                    "PII guard failed to sanitize tool output, so the response is blocked to prevent leakage. "
                    f"Error: {exc}"
                ),
            }
        )
        return 0


if __name__ == "__main__":
    sys.exit(main())
