#!/usr/bin/env python3
"""Behavior checks for Claude PII post-tool hook scripts.

Runs the real post-hook entrypoint with synthetic payloads and validates:
- Output redaction behavior
- UUID-only passthrough
- Fail-closed behavior on OPF failure
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

ROOT_DIR = Path(__file__).resolve().parent.parent
POST_HOOK = ROOT_DIR / "claude_hooks" / "post_tool_use_pii_redact.py"
PYTHON_BIN = sys.executable
sys.path.insert(0, str(ROOT_DIR / "claude_hooks"))
import pii_hook_common


class TestFailure(RuntimeError):
    """Raised when a behavior assertion fails."""


@dataclass(frozen=True)
class HookRunResult:
    payload: dict[str, Any] | None
    stdout: str
    stderr: str


@dataclass(frozen=True)
class TestCase:
    name: str
    fn: Callable[[], None]


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise TestFailure(message)


def _run_hook(
    script_path: Path,
    payload: dict[str, Any],
    *,
    extra_env: dict[str, str] | None = None,
) -> HookRunResult:
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)

    completed = subprocess.run(
        [PYTHON_BIN, str(script_path)],
        input=json.dumps(payload, ensure_ascii=False),
        capture_output=True,
        text=True,
        env=env,
        cwd=str(ROOT_DIR),
        check=False,
    )

    if completed.returncode != 0:
        raise TestFailure(
            f"Hook {script_path.name} exited non-zero ({completed.returncode}). stderr={completed.stderr.strip()}"
        )

    stdout = completed.stdout.strip()
    if not stdout:
        return HookRunResult(payload=None, stdout=stdout, stderr=completed.stderr.strip())

    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise TestFailure(
            f"Hook {script_path.name} returned non-JSON stdout: {stdout}"
        ) from exc

    if not isinstance(parsed, dict):
        raise TestFailure(f"Hook {script_path.name} response is not a JSON object")

    return HookRunResult(payload=parsed, stdout=stdout, stderr=completed.stderr.strip())


def _test_posttool_mcp_redacts_pii_preserves_uuid() -> None:
    payload = {
        "hook_event_name": "PostToolUse",
        "tool_name": "mcp__supabase__execute_sql",
        "tool_response": {
            "target": "abcde12345xyz7890pq",
            "identity": "550e8400-e29b-41d4-a716-446655440000",
            "account_ref": "user_123456789",
            "email": "alice@example.com",
            "customer": "Alice",
        },
    }
    result = _run_hook(POST_HOOK, payload)
    _assert(result.payload is not None, "Expected PostToolUse response for PII output")

    hso = result.payload.get("hookSpecificOutput", {})
    redacted = hso.get("updatedMCPToolOutput")
    _assert(isinstance(redacted, dict), "updatedMCPToolOutput should be an object")
    _assert(
        redacted.get("identity") == "550e8400-e29b-41d4-a716-446655440000",
        "UUID should be preserved",
    )
    _assert(redacted.get("email") == "<PRIVATE_EMAIL>", "email should be redacted")
    _assert(redacted.get("customer") == "<PRIVATE_PERSON>", "name should be redacted")


def _test_posttool_normal_output_no_pii_no_output() -> None:
    payload = {
        "hook_event_name": "PostToolUse",
        "tool_name": "mcp__supabase__execute_sql",
        "tool_response": {
            "status": "ok",
            "rows": 3,
            "message": "operation complete",
        },
    }
    result = _run_hook(POST_HOOK, payload)
    _assert(result.payload is None, "Expected no PostToolUse output for no-PII response")


def _test_posttool_fail_closed_on_opf_failure() -> None:
    payload = {
        "hook_event_name": "PostToolUse",
        "tool_name": "mcp__supabase__execute_sql",
        "tool_response": {"email": "alice@example.com"},
    }
    result = _run_hook(POST_HOOK, payload, extra_env={"PII_HOOK_OPF_COMMAND": "does-not-exist"})
    _assert(result.payload is not None, "Expected block response when OPF fails in PostToolUse")
    _assert(result.payload.get("decision") == "block", "PostToolUse should block if OPF fails")


def _test_identifier_passthrough_is_uuid_only() -> None:
    should_not_allow = [
        "123-45-6789",
        "12-3456789",
        "ABCDE1234F",
        "A1234567",
        "AB12345678",
        "AB12CD34EF",
        "abcde12345xyz7890pq",
        "service_user_123456789",
    ]
    for value in should_not_allow:
        _assert(
            not pii_hook_common._should_passthrough_identifier(value=value),
            f"Expected non-UUID token to be scanned, not passthrough: {value}",
        )

    should_allow = [
        "550e8400-e29b-41d4-a716-446655440000",
    ]
    for value in should_allow:
        _assert(
            pii_hook_common._should_passthrough_identifier(value=value),
            f"Expected UUID passthrough: {value}",
        )


def main() -> int:
    cases = [
        TestCase("PostToolUse MCP redacts PII + preserves UUID", _test_posttool_mcp_redacts_pii_preserves_uuid),
        TestCase("PostToolUse normal response no PII returns no output", _test_posttool_normal_output_no_pii_no_output),
        TestCase("PostToolUse fails closed when OPF unavailable", _test_posttool_fail_closed_on_opf_failure),
        TestCase("Identifier passthrough is UUID-only", _test_identifier_passthrough_is_uuid_only),
    ]

    print(f"Running {len(cases)} hook behavior tests...\n")
    failures: list[str] = []

    for idx, case in enumerate(cases, start=1):
        try:
            case.fn()
            print(f"[{idx}/{len(cases)}] PASS - {case.name}")
        except Exception as exc:  # noqa: BLE001 - test harness intentionally captures failures
            failures.append(f"{case.name}: {exc}")
            print(f"[{idx}/{len(cases)}] FAIL - {case.name}")

    if failures:
        print("\nFailures:")
        for item in failures:
            print(f"- {item}")
        return 1

    print("\nAll hook behavior tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
