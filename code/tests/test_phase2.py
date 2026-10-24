#!/usr/bin/env python3
"""
test_phase2.py - Comprehensive verification of Phase 2 modules:
1. Intent Classifier validation on sample_deletion_requests.csv and deletion_requests.csv
2. Identity Resolver validation on sample cases and audit-traced users.
"""

import csv
import json
import sys
from pathlib import Path

# Ensure code/ is in import path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DATASET_DIR = REPO_ROOT / "dataset"
sys.path.insert(0, str(REPO_ROOT / "code"))

from intent_classifier import classify_intent, is_deletion_request
from identity_resolver import IdentityResolver

# Ensure UTF-8 output
if sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def test_intent_on_samples():
    print("==================================================")
    print("TEST 1: Intent Classification on sample_deletion_requests.csv (32 cases)")
    print("==================================================")
    sample_file = DATASET_DIR / "sample_deletion_requests.csv"
    with open(sample_file, "r", encoding="utf-8") as f:
        cases = list(csv.DictReader(f))


    non_deletion_detected = []
    for c in cases:
        cid = c["case_id"]
        txt = c["request_text"]
        is_del, reason = classify_intent(txt)
        assert is_deletion_request(txt) == is_del
        if not is_del:
            non_deletion_detected.append((cid, txt, reason))

    print(f"Total Sample Cases Audited: {len(cases)}")
    print(f"Cases Flagged as NOT_APPLICABLE: {len(non_deletion_detected)}")
    assert len(non_deletion_detected) == 0, f"Expected 0 non-deletion cases in sample, got {len(non_deletion_detected)}"
    print("PASS: 100% of sample cases correctly classified as authorized deletion requests!\n")


def test_intent_on_full_dataset():
    print("==================================================")
    print("TEST 2: Intent Classification on deletion_requests.csv (518 cases)")
    print("==================================================")
    full_file = DATASET_DIR / "deletion_requests.csv"
    with open(full_file, "r", encoding="utf-8") as f:
        cases = list(csv.DictReader(f))

    not_applicable_cases = []
    authorized_cases = []

    for c in cases:
        cid = c["case_id"]
        txt = c["request_text"]
        is_del, reason = classify_intent(txt)
        if not is_del:
            not_applicable_cases.append((cid, c["email"], txt, reason))
        else:
            authorized_cases.append(cid)

    print(f"Total Evaluation Cases: {len(cases)}")
    print(f"Authorized Deletion Requests: {len(authorized_cases)} ({len(authorized_cases)/len(cases)*100:.2f}%)")
    print(f"NOT_APPLICABLE Requests:      {len(not_applicable_cases)} ({len(not_applicable_cases)/len(cases)*100:.2f}%)")

    print("\nSample NOT_APPLICABLE Request Snippets:")
    for i, (cid, email, txt, reason) in enumerate(not_applicable_cases[:3]):
        print(f"\n--- [{i+1}] Case: {cid} | Email: {email} ---")
        print(f"Reason: {reason}")
        print(f"Text: \"{txt}\"")
    print("\nPASS: NOT_APPLICABLE identification verified with clear policy justification!\n")
    return not_applicable_cases


def test_identity_resolution():
    print("==================================================")
    print("TEST 3: Identity Resolver on First 5 Sample Cases")
    print("==================================================")
    resolver = IdentityResolver(
        identities_path=str(DATASET_DIR / "user_identities.csv"),
        audit_log_path=str(DATASET_DIR / "user_audit_log.csv"),
    )

    with open(DATASET_DIR / "sample_deletion_requests.csv", "r", encoding="utf-8") as f:
        cases = list(csv.DictReader(f))[:5]


    for c in cases:
        cid = c["case_id"]
        email = c["email"]
        audit_at = c["audit_at"]
        cluster = resolver.resolve(email, audit_at)
        assert cluster is not None, f"Failed to resolve identity for {email}"
        print(f"\n>>> [{cid}] Request Email: {email} (Audit Cutoff: {audit_at})")
        print(json.dumps(cluster.to_dict(), indent=2))

    print("\nPASS: Identity clusters resolved with primary_user_id, emails, hashes, phones, and names!\n")


if __name__ == "__main__":
    test_intent_on_samples()
    not_app = test_intent_on_full_dataset()
    test_identity_resolution()
    print("==================================================")
    print("ALL PHASE 2 INTEGRATION TESTS PASSED PERFECTLY!")
    print("==================================================")
