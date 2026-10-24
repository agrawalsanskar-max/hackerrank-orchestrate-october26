#!/usr/bin/env python3
"""
verify_sample.py - Strict evaluation and verification script for HackerRank Orchestrate (Ghost Data Still Exists).
Evaluates prediction CSVs against dataset/sample_output.csv with comprehensive schema, order, and field-level scoring.
"""

import sys
import csv
import json
from pathlib import Path
from typing import Dict, List, Any, Tuple

OPERATION_ORDER = [
    # FINDING
    "REPORT_REMAINING_RECORD",
    "REPORT_EXPOSED_PII",
    "REPORT_ACTIVE_DATA_FLOW",
    "REPORT_RESTORE_RISK",
    # REMEDIATION
    "DISABLE_DATA_FLOW",
    "BLOCK_RESTORE",
    "DELETE_RECORD",
    "REDACT_RECORD",
    "ANONYMIZE_RECORD",
    # VERIFICATION
    "VERIFY_RECORD_ABSENT",
    "VERIFY_RECORD_PRESENT",
    "VERIFY_RECORD_REDACTED",
    "VERIFY_RECORD_ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED",
    "VERIFY_RESTORE_BLOCKED",
]

OP_TO_ORDER = {op: i for i, op in enumerate(OPERATION_ORDER)}

EXPECTED_STATE = {
    "REPORT_REMAINING_RECORD": "PRESENT",
    "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
    "REPORT_RESTORE_RISK": "ACTIVE",
    "DISABLE_DATA_FLOW": "DISABLED",
    "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED",
    "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT",
    "VERIFY_RECORD_PRESENT": "PRESENT",
    "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}

PHASE_ORDER = {
    "FINDING": 0,
    "REMEDIATION": 1,
    "VERIFICATION": 2,
}

VALID_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}


def validate_steps_contract(case_id: str, status: str, steps: List[Dict[str, Any]]) -> List[str]:
    """Validate steps array against challenge contract rules."""
    errors = []
    
    if status == "NOT_APPLICABLE":
        if len(steps) != 0:
            errors.append(f"{case_id}: NOT_APPLICABLE must have empty steps_json, got {len(steps)} steps")
        return errors

    if not isinstance(steps, list):
        errors.append(f"{case_id}: steps_json must be a JSON array")
        return errors

    if len(steps) == 0 and status in ("COMPLETE", "INCOMPLETE"):
        errors.append(f"{case_id}: {status} cannot have empty steps_json")
        return errors

    for i, step in enumerate(steps):
        expected_step_no = i + 1
        if step.get("step_no") != expected_step_no:
            errors.append(f"{case_id}: step {i} step_no is {step.get('step_no')}, expected {expected_step_no}")
        
        phase = step.get("phase")
        if phase not in PHASE_ORDER:
            errors.append(f"{case_id}: step {expected_step_no} invalid phase '{phase}'")

        op = step.get("operation")
        if op not in OP_TO_ORDER:
            errors.append(f"{case_id}: step {expected_step_no} invalid operation '{op}'")
        else:
            exp_state = EXPECTED_STATE[op]
            actual_state = step.get("state")
            if actual_state != exp_state:
                errors.append(f"{case_id}: step {expected_step_no} operation '{op}' requires state '{exp_state}', got '{actual_state}'")

        ev_id = step.get("evidence_id", "")
        if status == "COMPLETE":
            if phase != "VERIFICATION":
                errors.append(f"{case_id}: COMPLETE case has non-VERIFICATION step: {phase}")
            if not ev_id:
                errors.append(f"{case_id}: COMPLETE step {expected_step_no} must have non-empty evidence_id")
        elif status == "INCOMPLETE":
            if phase == "FINDING" and not ev_id:
                errors.append(f"{case_id}: FINDING step {expected_step_no} must have non-empty evidence_id")
            elif phase in ("REMEDIATION", "VERIFICATION") and ev_id != "":
                errors.append(f"{case_id}: {phase} step {expected_step_no} must have empty evidence_id, got '{ev_id}'")

    # Check phase and tie-breaking order
    for i in range(len(steps) - 1):
        s1 = steps[i]
        s2 = steps[i + 1]
        p1 = PHASE_ORDER.get(s1.get("phase"), -1)
        p2 = PHASE_ORDER.get(s2.get("phase"), -1)
        if p1 < p2:
            continue
        if p1 > p2:
            errors.append(f"{case_id}: phase out of order: step {i+1} ({s1.get('phase')}) before step {i+2} ({s2.get('phase')})")
            continue

        op1 = OP_TO_ORDER.get(s1.get("operation"), -1)
        op2 = OP_TO_ORDER.get(s2.get("operation"), -1)
        if op1 < op2:
            continue
        if op1 > op2:
            errors.append(f"{case_id}: operation out of order in phase {s1.get('phase')}: step {i+1} ({s1.get('operation')}) before step {i+2} ({s2.get('operation')})")
            continue

        sys1 = s1.get("system_id", "")
        sys2 = s2.get("system_id", "")
        if sys1 < sys2:
            continue
        if sys1 > sys2:
            errors.append(f"{case_id}: system_id out of order: step {i+1} ({sys1}) before step {i+2} ({sys2})")
            continue

        res1 = s1.get("resource_id", "")
        res2 = s2.get("resource_id", "")
        if res1 > res2:
            errors.append(f"{case_id}: resource_id out of order: step {i+1} ({res1}) before step {i+2} ({res2})")

    return errors


def evaluate(pred_file: Path, ground_truth_file: Path) -> Tuple[bool, Dict[str, Any]]:
    """Compare pred_file against ground_truth_file."""
    print(f"==================================================")
    print(f"EVALUATING: {pred_file}")
    print(f"GROUND TRUTH: {ground_truth_file}")
    print(f"==================================================")

    with open(ground_truth_file, "r", encoding="utf-8") as f:
        gt_reader = csv.DictReader(f)
        gt_rows = {row["case_id"]: row for row in gt_reader}

    if not pred_file.exists():
        print(f"ERROR: Prediction file not found at {pred_file}")
        return False, {}

    with open(pred_file, "r", encoding="utf-8") as f:
        pred_reader = csv.DictReader(f)
        pred_fieldnames = pred_reader.fieldnames or []
        expected_fields = ["case_id", "deletion_status", "steps_json"]
        if pred_fieldnames != expected_fields:
            print(f"SCHEMA ERROR: CSV columns must be {expected_fields}, got {pred_fieldnames}")
            return False, {}
        pred_rows = {row["case_id"]: row for row in pred_reader}

    total_gt = len(gt_rows)
    total_pred = len(pred_rows)

    print(f"Total Ground Truth Cases: {total_gt}")
    print(f"Total Predicted Cases:    {total_pred}")

    status_matches = 0
    step_count_matches = 0
    full_sequence_matches = 0
    total_steps_gt = 0
    total_steps_pred = 0
    step_field_matches = {
        "phase": 0,
        "system_id": 0,
        "resource_id": 0,
        "operation": 0,
        "state": 0,
        "evidence_id": 0,
    }
    contract_violations = 0

    discrepancies = []

    for case_id, gt_row in gt_rows.items():
        if case_id not in pred_rows:
            discrepancies.append(f"Missing case_id: {case_id}")
            continue

        p_row = pred_rows[case_id]
        gt_status = gt_row["deletion_status"]
        p_status = p_row["deletion_status"]

        # Parse JSON
        try:
            gt_steps = json.loads(gt_row["steps_json"])
        except Exception as e:
            gt_steps = []
        try:
            p_steps = json.loads(p_row["steps_json"])
        except Exception as e:
            discrepancies.append(f"{case_id}: Invalid JSON in steps_json: {e}")
            p_steps = []

        total_steps_gt += len(gt_steps)
        total_steps_pred += len(p_steps)

        # Validate contract on prediction
        c_errors = validate_steps_contract(case_id, p_status, p_steps)
        if c_errors:
            contract_violations += len(c_errors)
            for err in c_errors:
                discrepancies.append(f"Contract Violation -> {err}")

        # Check status
        if gt_status == p_status:
            status_matches += 1
        else:
            discrepancies.append(f"{case_id} Status Mismatch: Expected {gt_status}, got {p_status}")

        # Check step count
        if len(gt_steps) == len(p_steps):
            step_count_matches += 1
        else:
            discrepancies.append(f"{case_id} Step Count Mismatch: Expected {len(gt_steps)}, got {len(p_steps)}")

        # Check step by step
        seq_match = (gt_status == p_status and len(gt_steps) == len(p_steps))
        for i in range(min(len(gt_steps), len(p_steps))):
            g_step = gt_steps[i]
            p_step = p_steps[i]
            step_ok = True
            for field in ["phase", "system_id", "resource_id", "operation", "state", "evidence_id"]:
                if g_step.get(field) == p_step.get(field):
                    step_field_matches[field] += 1
                else:
                    step_ok = False
                    discrepancies.append(
                        f"{case_id} Step {i+1} Field '{field}' Mismatch: Expected '{g_step.get(field)}', got '{p_step.get(field)}'"
                    )
            if not step_ok:
                seq_match = False

        if seq_match and len(gt_steps) == len(p_steps):
            full_sequence_matches += 1

    status_acc = (status_matches / total_gt) * 100 if total_gt else 0
    step_count_acc = (step_count_matches / total_gt) * 100 if total_gt else 0
    seq_acc = (full_sequence_matches / total_gt) * 100 if total_gt else 0

    print("\n---------------- RESULTS ----------------")
    print(f"Case-Level Status Accuracy:     {status_matches}/{total_gt} ({status_acc:.2f}%)")
    print(f"Step Count Match Rate:          {step_count_matches}/{total_gt} ({step_count_acc:.2f}%)")
    print(f"Full Sequence Match Rate:       {full_sequence_matches}/{total_gt} ({seq_acc:.2f}%)")
    print(f"Total Steps (GT / Pred):        {total_steps_gt} / {total_steps_pred}")
    print("\nStep Field Match Rates (vs GT total steps):")
    for f, count in step_field_matches.items():
        rate = (count / total_steps_gt) * 100 if total_steps_gt else 0
        print(f"  - {f:12s}: {count}/{total_steps_gt} ({rate:.2f}%)")

    print(f"\nContract Violations Found:      {contract_violations}")

    if discrepancies:
        print(f"\nDiscrepancies Preview (First 10 of {len(discrepancies)}):")
        for d in discrepancies[:10]:
            print(f"  * {d}")
    else:
        print("\nPERFECT MATCH: All cases, statuses, steps, phases, and fields match ground truth exactly!")

    summary = {
        "status_accuracy": status_acc,
        "sequence_accuracy": seq_acc,
        "contract_violations": contract_violations,
        "perfect": len(discrepancies) == 0 and status_matches == total_gt,
    }
    return summary["perfect"], summary


if __name__ == "__main__":
    gt_path = Path("dataset/sample_output.csv")
    if len(sys.argv) > 1:
        target_path = Path(sys.argv[1])
    else:
        target_path = gt_path

    success, _ = evaluate(target_path, gt_path)
    sys.exit(0 if success else 1)
