"""Canonical Serializer for Ghost Data Still Exists.

Enforces exact canonical sorting, step renumbering (1-based),
and compliant JSON serialization according to AGENTS.md contract.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

PHASE_ORDER = {
    "FINDING": 1,
    "REMEDIATION": 2,
    "VERIFICATION": 3,
}

OPERATION_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 4,
    "BLOCK_RESTORE": 5,
    "DELETE_RECORD": 6,
    "REDACT_RECORD": 7,
    "ANONYMIZE_RECORD": 8,
    "VERIFY_RECORD_ABSENT": 9,
    "VERIFY_RECORD_PRESENT": 10,
    "VERIFY_RECORD_REDACTED": 11,
    "VERIFY_RECORD_ANONYMIZED": 12,
    "VERIFY_DATA_FLOW_DISABLED": 13,
    "VERIFY_RESTORE_BLOCKED": 14,
}


def sort_steps(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sorts steps by (phase, operation, system_id, resource_id)."""
    return sorted(
        steps,
        key=lambda s: (
            PHASE_ORDER.get(s.get("phase", ""), 99),
            OPERATION_ORDER.get(s.get("operation", ""), 99),
            s.get("system_id", ""),
            s.get("resource_id", ""),
        ),
    )


def renumber_steps(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Assigns sequential 1-based step_no and ensures canonical field ordering."""
    renumbered = []
    for idx, s in enumerate(steps, start=1):
        renumbered.append({
            "step_no": idx,
            "phase": s.get("phase", ""),
            "system_id": s.get("system_id", ""),
            "resource_id": s.get("resource_id", ""),
            "operation": s.get("operation", ""),
            "state": s.get("state", ""),
            "evidence_id": s.get("evidence_id", ""),
        })
    return renumbered


def serialize_steps(steps: List[Dict[str, Any]]) -> str:
    """Sorts, renumbers, and serializes steps to a compact JSON string."""
    if not steps:
        return "[]"
    sorted_steps = sort_steps(steps)
    renumbered_steps = renumber_steps(sorted_steps)
    return json.dumps(renumbered_steps, ensure_ascii=False, separators=(",", ":"))
