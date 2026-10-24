"""Unit & Regression Test Suite for Phase 4 (Policy Planner, Serializer, Main Pipeline).

Validates:
1. Canonical serializer sorting precedence and 1-based numbering.
2. Remediation operation mapping from deletion_rules.csv.
3. Verification citation contract (evidence_id for COMPLETE vs empty string for INCOMPLETE).
4. Full pipeline execution against sample dataset achieving 100% accuracy.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
import unittest

code_dir = Path(__file__).resolve().parent.parent
repo_root = code_dir.parent
if str(code_dir) not in sys.path:
    sys.path.insert(0, str(code_dir))

from serializer import sort_steps, renumber_steps, serialize_steps
from policy_planner import PolicyPlanner


class TestPhase4(unittest.TestCase):
    def test_serializer_sorting_and_renumbering(self):
        """Test phase, operation, and tie-breaker sorting."""
        raw_steps = [
            {"phase": "VERIFICATION", "system_id": "security_service", "resource_id": "audit_01", "operation": "VERIFY_RECORD_PRESENT", "state": "PRESENT", "evidence_id": ""},
            {"phase": "FINDING", "system_id": "support_platform", "resource_id": "support_01", "operation": "REPORT_EXPOSED_PII", "state": "PRESENT", "evidence_id": "ev_01"},
            {"phase": "REMEDIATION", "system_id": "support_platform", "resource_id": "support_01", "operation": "REDACT_RECORD", "state": "REDACTED", "evidence_id": ""},
            {"phase": "FINDING", "system_id": "account_service", "resource_id": "account_01", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "ev_02"},
        ]
        sorted_steps = sort_steps(raw_steps)
        renumbered = renumber_steps(sorted_steps)
        serialized = serialize_steps(renumbered)
        self.assertIsInstance(serialized, str)
        self.assertTrue(serialized.startswith("["))

        # 1. REPORT_REMAINING_RECORD (account_01)
        self.assertEqual(renumbered[0]["step_no"], 1)
        self.assertEqual(renumbered[0]["phase"], "FINDING")
        self.assertEqual(renumbered[0]["operation"], "REPORT_REMAINING_RECORD")
        self.assertEqual(renumbered[0]["resource_id"], "account_01")

        # 2. REPORT_EXPOSED_PII (support_01)
        self.assertEqual(renumbered[1]["step_no"], 2)
        self.assertEqual(renumbered[1]["phase"], "FINDING")
        self.assertEqual(renumbered[1]["operation"], "REPORT_EXPOSED_PII")

        # 3. REDACT_RECORD
        self.assertEqual(renumbered[2]["step_no"], 3)
        self.assertEqual(renumbered[2]["phase"], "REMEDIATION")
        self.assertEqual(renumbered[2]["operation"], "REDACT_RECORD")

        # 4. VERIFY_RECORD_PRESENT
        self.assertEqual(renumbered[3]["step_no"], 4)
        self.assertEqual(renumbered[3]["phase"], "VERIFICATION")
        self.assertEqual(renumbered[3]["operation"], "VERIFY_RECORD_PRESENT")

    def test_sample_benchmark_100_percent(self):
        """Test end-to-end policy planner matching on all 32 sample cases."""
        planner = PolicyPlanner(str(repo_root / "dataset"))
        with open(repo_root / "dataset" / "sample_deletion_requests.csv", "r", encoding="utf-8") as f:
            requests = list(csv.DictReader(f))
        with open(repo_root / "dataset" / "sample_output.csv", "r", encoding="utf-8") as f:
            gt_outputs = {r["case_id"]: r for r in csv.DictReader(f)}

        for req in requests:
            cid = req["case_id"]
            status, steps = planner.plan_case(req)
            gt = gt_outputs[cid]
            gt_status = gt["deletion_status"]
            gt_steps = json.loads(gt["steps_json"])

            self.assertEqual(status, gt_status, f"Status mismatch for {cid}")
            self.assertEqual(steps, gt_steps, f"Steps mismatch for {cid}")


if __name__ == "__main__":
    unittest.main()
