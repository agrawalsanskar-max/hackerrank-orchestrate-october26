#!/usr/bin/env python3
"""
test_phase3.py - Verification script for Phase 3 Forensic Investigation Engine:
Demonstrates evidence extraction on distinct sample cases:
  Case A: COMPLETE (Clean verified deletion with audit log & anonymized analytics)
  Case B: INCOMPLETE (Replica drift / surviving record / exposed PII)
  Case C: INCOMPLETE (Active data flow / restore risk)

Compares findings directly against ground-truth findings from dataset/sample_output.csv.
"""

import csv
import json
import sys
from pathlib import Path

# Ensure code/ is in import path
sys.path.insert(0, str(Path(__file__).parent.parent))

from identity_resolver import IdentityResolver
from evidence_analyzer import EvidenceAnalyzer

# Ensure UTF-8 output
if sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def run_phase3_tests():
    root = Path(__file__).resolve().parent.parent.parent
    dataset_dir = root / "dataset"
    sample_requests_path = dataset_dir / "sample_deletion_requests.csv"
    sample_output_path = dataset_dir / "sample_output.csv"

    print("=" * 70)
    print("PHASE 3 VERIFICATION: FORENSIC INVESTIGATION & EVIDENCE EXTRACTION")
    print("=" * 70)

    resolver = IdentityResolver()
    analyzer = EvidenceAnalyzer(str(dataset_dir))

    with open(sample_requests_path, "r", encoding="utf-8") as f:
        sample_requests = {r["case_id"]: r for r in csv.DictReader(f)}

    with open(sample_output_path, "r", encoding="utf-8") as f:
        sample_outputs = {r["case_id"]: r for r in csv.DictReader(f)}

    # Selected Test Cases across all categories
    test_cases = [
        ("case_25", "Case A (COMPLETE - Clean Verified Deletion)"),
        ("case_05", "Case B1 (INCOMPLETE - Failover Replica Drift)"),
        ("case_16", "Case B2 (INCOMPLETE - Read Replica Drift & Search Hit)"),
        ("case_32", "Case B3 (INCOMPLETE - Tombstone Exposed PII)"),
        ("case_09", "Case C1 (INCOMPLETE - Backup Restore Risk)"),
        ("case_15", "Case C2 (INCOMPLETE - Active Data Flow Connector)"),
        ("case_11", "Case C3 (INCOMPLETE - Multi-Vector: Data Flow + Search + PII)"),
    ]

    total_tested = 0
    total_passed = 0

    for cid, label in test_cases:
        req = sample_requests[cid]
        expected_row = sample_outputs[cid]
        expected_steps = json.loads(expected_row["steps_json"])
        expected_status = expected_row["deletion_status"]

        print(f"\n--- Testing {cid}: {label} ---")
        print(f"Request: Email={req['email']} | ReqAt={req['requested_at']} | AuditAt={req['audit_at']}")
        print(f"Expected Status: {expected_status}")

        cluster = resolver.resolve(req["email"], req["audit_at"])
        assert cluster is not None, f"Failed to resolve identity cluster for {req['email']}"
        print(f"Resolved User ID: {cluster.primary_user_id} | Emails: {sorted(list(cluster.emails))}")

        # Extract forensic findings with temporal window
        findings = analyzer.analyze_case(cluster, req["audit_at"], requested_at=req["requested_at"])

        # Filter expected findings from sample_output
        expected_findings = [
            s for s in expected_steps if s["phase"] == "FINDING"
        ]

        print(f"\nDiscovered {len(findings)} forensic evidence items:")
        for f in findings:
            print(f"  [{f.phase}] {f.operation} on {f.system_id}/{f.resource_id} (State: {f.state}) via {f.evidence_id}")

        # Check match with expected findings
        expected_findings_keys = {
            (s["operation"], s["system_id"], s["resource_id"], s.get("evidence_id"))
            for s in expected_findings
        }
        discovered_findings_keys = {
            (f.operation, f.system_id, f.resource_id, f.evidence_id)
            for f in findings if f.phase == "FINDING"
        }

        print(f"\nGround Truth Findings ({len(expected_findings)} items):")
        for s in expected_findings:
            print(f"  [FINDING] {s['operation']} on {s['system_id']}/{s['resource_id']} via {s.get('evidence_id')}")

        if expected_status == "COMPLETE":
            assert len(expected_findings) == 0, f"Complete case {cid} should have 0 findings"
            has_finding_violations = len(discovered_findings_keys) > 0
            if not has_finding_violations:
                print(">>> PASSED: Clean deletion verified with 0 policy violations.")
                total_passed += 1
            else:
                print(f">>> FAILED: Unexpected finding in complete case: {discovered_findings_keys}")
        else:
            matched_findings = expected_findings_keys.intersection(discovered_findings_keys)
            match_rate = len(matched_findings) / len(expected_findings_keys) if expected_findings_keys else 1.0
            print(f"Findings Match Rate: {len(matched_findings)} / {len(expected_findings_keys)} ({match_rate * 100:.1f}%)")

            if match_rate == 1.0:
                print(f">>> PASSED: All {len(expected_findings_keys)} ground truth findings extracted exactly!")
                total_passed += 1
            else:
                missing = expected_findings_keys - discovered_findings_keys
                print(f">>> FAILED: Missing findings: {missing}")

        total_tested += 1

    print("\n" + "=" * 70)
    print(f"PHASE 3 VERIFICATION SUMMARY: {total_passed}/{total_tested} Cases Passed ({(total_passed / total_tested) * 100:.1f}%)")
    print("=" * 70)
    return total_passed == total_tested


if __name__ == "__main__":
    success = run_phase3_tests()
    sys.exit(0 if success else 1)
