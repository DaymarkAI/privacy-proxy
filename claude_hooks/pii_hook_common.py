#!/usr/bin/env python3
"""Shared utilities for Claude hooks that enforce PII filtering with OPF."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class OPFHookError(RuntimeError):
    """Raised when OPF cannot be executed or parsed."""


@dataclass(frozen=True)
class ScanResult:
    """Result returned by a single OPF scan."""

    span_count: int
    redacted_text: str


@dataclass(frozen=True)
class RedactionResult:
    """Result for recursive redaction."""

    value: Any
    span_count: int


_UUID_PATTERN = re.compile(
    r"\b[0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}\b"
)


def _should_passthrough_identifier(*, value: str) -> bool:
    """Allowlist only canonical UUID identifiers."""
    return bool(_UUID_PATTERN.fullmatch(value))


def load_hook_payload() -> dict[str, Any]:
    """Read hook input JSON from stdin."""
    raw = os.sys.stdin.read()
    if not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise OPFHookError(f"Invalid hook JSON payload: {exc}") from exc
    if not isinstance(parsed, dict):
        raise OPFHookError("Hook JSON payload must be an object")
    return parsed


def emit_json(payload: dict[str, Any]) -> None:
    """Write hook output JSON to stdout."""
    print(json.dumps(payload, ensure_ascii=False))


def _candidate_opf_commands() -> list[list[str]]:
    """Return prioritized OPF command candidates."""
    candidates: list[list[str]] = []

    cmd_from_env = os.getenv("PII_HOOK_OPF_COMMAND")
    if cmd_from_env:
        parts = shlex.split(cmd_from_env)
        if parts:
            candidates.append(parts)

    script_dir = Path(__file__).resolve().parent
    repo_dir = script_dir.parent

    path_candidates = [
        repo_dir / "privacy-filter" / ".venv" / "bin" / "opf",
        repo_dir / "privacy_filter" / ".venv" / "bin" / "opf",
    ]
    for path in path_candidates:
        resolved = path.resolve()
        if resolved.exists() and os.access(resolved, os.X_OK):
            candidates.append([str(resolved)])

    opf_in_path = shutil.which("opf")
    if opf_in_path:
        candidates.append([opf_in_path])

    # Deduplicate while preserving order.
    unique: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()
    for cmd in candidates:
        key = tuple(cmd)
        if key in seen:
            continue
        seen.add(key)
        unique.append(cmd)
    return unique


def resolve_opf_command() -> list[str]:
    """Resolve an executable OPF command for this workspace."""
    candidates = _candidate_opf_commands()
    if not candidates:
        raise OPFHookError(
            "Unable to find `opf`. Set PII_HOOK_OPF_COMMAND or install OPF in ./privacy-filter or ./privacy_filter."
        )
    return candidates[0]


def _extract_first_json_object(text: str) -> dict[str, Any]:
    """Extract and parse the first JSON object embedded in text."""
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise OPFHookError("Could not parse JSON output from OPF")


def _split_uuid_segments(text: str) -> list[tuple[str, str]]:
    """Split into [("text"| "uuid", segment)] while preserving order."""
    segments: list[tuple[str, str]] = []
    cursor = 0
    for match in _UUID_PATTERN.finditer(text):
        start, end = match.span()
        if start > cursor:
            segments.append(("text", text[cursor:start]))
        segments.append(("uuid", match.group(0)))
        cursor = end
    if cursor < len(text):
        segments.append(("text", text[cursor:]))
    if not segments:
        segments.append(("text", text))
    return segments


class OPFScanner:
    """Small OPF wrapper with result caching per hook execution."""

    def __init__(self) -> None:
        self._opf_command = resolve_opf_command()
        timeout_raw = os.getenv("PII_HOOK_TIMEOUT_SEC", "60")
        try:
            timeout_sec = int(timeout_raw)
        except ValueError as exc:
            raise OPFHookError("PII_HOOK_TIMEOUT_SEC must be an integer") from exc
        self._timeout_sec = max(1, timeout_sec)
        self._cache: dict[str, ScanResult] = {}

    def _run_opf(self, text: str) -> ScanResult:
        """Run OPF on one plain-text segment."""
        if not text:
            return ScanResult(span_count=0, redacted_text=text)
        cmd = [
            *self._opf_command,
            "--device",
            "cpu",
            "--format",
            "json",
            "--json-indent",
            "0",
            "--no-print-color-coded-text",
            text,
        ]

        try:
            completed = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=self._timeout_sec,
            )
        except subprocess.TimeoutExpired as exc:
            raise OPFHookError(
                f"OPF timed out after {self._timeout_sec}s"
            ) from exc
        except OSError as exc:
            raise OPFHookError(f"Failed to execute OPF: {exc}") from exc

        if completed.returncode != 0:
            stderr = completed.stderr.strip() or "Unknown OPF error"
            raise OPFHookError(f"OPF failed with exit code {completed.returncode}: {stderr}")

        payload = _extract_first_json_object(completed.stdout)
        summary = payload.get("summary", {})
        if not isinstance(summary, dict):
            raise OPFHookError("OPF output missing summary object")

        span_count_raw = summary.get("span_count", 0)
        try:
            span_count = int(span_count_raw)
        except (TypeError, ValueError) as exc:
            raise OPFHookError("OPF output contained a non-numeric span_count") from exc

        redacted_text = payload.get("redacted_text")
        if not isinstance(redacted_text, str):
            raise OPFHookError("OPF output missing redacted_text")

        result = ScanResult(span_count=span_count, redacted_text=redacted_text)
        return result

    def scan_text(self, text: str) -> ScanResult:
        """Run OPF over text while preserving UUID values as allowlisted tokens."""
        if not text:
            return ScanResult(span_count=0, redacted_text=text)
        cached = self._cache.get(text)
        if cached is not None:
            return cached

        segments = _split_uuid_segments(text)
        redacted_parts: list[str] = []
        total_spans = 0
        for segment_type, segment_value in segments:
            if segment_type == "uuid":
                redacted_parts.append(segment_value)
                continue
            segment_result = self._run_opf(segment_value)
            redacted_parts.append(segment_result.redacted_text)
            total_spans += segment_result.span_count

        result = ScanResult(
            span_count=total_spans,
            redacted_text="".join(redacted_parts),
        )
        self._cache[text] = result
        return result


def normalize_for_scan(value: Any) -> str:
    """Convert arbitrary tool input/output into deterministic text for OPF scanning."""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def redact_recursive(
    value: Any,
    scanner: OPFScanner,
) -> RedactionResult:
    """Redact all string leaves in a nested JSON-like object."""
    if isinstance(value, str):
        if _should_passthrough_identifier(value=value):
            return RedactionResult(value=value, span_count=0)
        scan = scanner.scan_text(value)
        return RedactionResult(value=scan.redacted_text, span_count=scan.span_count)

    if isinstance(value, list):
        redacted_items: list[Any] = []
        total = 0
        for item in value:
            child = redact_recursive(item, scanner)
            redacted_items.append(child.value)
            total += child.span_count
        return RedactionResult(value=redacted_items, span_count=total)

    if isinstance(value, dict):
        redacted_map: dict[str, Any] = {}
        total = 0
        for key, item in value.items():
            child = redact_recursive(item, scanner)
            redacted_map[key] = child.value
            total += child.span_count
        return RedactionResult(value=redacted_map, span_count=total)

    return RedactionResult(value=value, span_count=0)


def truncate_text(text: str, limit: int = 240) -> str:
    """Truncate potentially long redacted previews for UI-safe messages."""
    if len(text) <= limit:
        return text
    return f"{text[:limit]}..."
