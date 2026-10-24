import csv, json, sys
from pathlib import Path

output_path = Path("output.csv")
if not output_path.exists():
    output_path = Path(__file__).resolve().parent.parent.parent / "output.csv"
if not output_path.exists():
    print(f"FAIL: output.csv does not exist at {output_path}!")
    sys.exit(1)

with open(output_path, "r", encoding="utf-8") as f:
    lines = f.readlines()

print(f"Total lines in output.csv: {len(lines)}")
assert len(lines) == 519, f"Expected 519 lines, got {len(lines)}"

reader = list(csv.DictReader(lines))
assert len(reader) == 518, f"Expected 518 data rows, got {len(reader)}"

# Check headers
headers = list(reader[0].keys())
assert headers == ["case_id", "deletion_status", "steps_json"], f"Headers mismatch: {headers}"

valid_statuses = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
status_counts = {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0}
total_steps = 0

prev_case_num = 32
for i, row in enumerate(reader, start=1):
    cid = row["case_id"]
    status = row["deletion_status"]
    steps_raw = row["steps_json"]

    # Check case_id sequence
    assert cid.startswith("case_"), f"Invalid case_id: {cid}"
    cnum = int(cid.split("_")[1])
    assert cnum == prev_case_num + 1, f"case_id out of order or gap: expected {prev_case_num + 1}, got {cnum}"
    prev_case_num = cnum

    # Check status
    assert status in valid_statuses, f"[{cid}] Invalid status: {status}"
    status_counts[status] += 1

    # Check steps_json
    try:
        steps = json.loads(steps_raw)
    except Exception as e:
        assert False, f"[{cid}] Invalid JSON in steps_json: {e}"

    assert isinstance(steps, list), f"[{cid}] steps_json must be a list"

    if status == "NOT_APPLICABLE":
        assert len(steps) == 0, f"[{cid}] NOT_APPLICABLE must have empty steps_json, got {len(steps)}"
    else:
        assert len(steps) > 0, f"[{cid}] {status} must have > 0 steps, got {len(steps)}"

    # Validate step structure
    for expected_step_no, step in enumerate(steps, start=1):
        total_steps += 1
        assert step.get("step_no") == expected_step_no, f"[{cid}] Step numbering error: expected {expected_step_no}, got {step.get('step_no')}"
        assert step.get("phase") in {"FINDING", "REMEDIATION", "VERIFICATION"}, f"[{cid}] Invalid phase: {step.get('phase')}"
        assert step.get("system_id"), f"[{cid}] Missing system_id in step {expected_step_no}"
        assert step.get("resource_id"), f"[{cid}] Missing resource_id in step {expected_step_no}"
        assert step.get("operation"), f"[{cid}] Missing operation in step {expected_step_no}"
        assert step.get("state"), f"[{cid}] Missing state in step {expected_step_no}"

        # Evidence rule
        if status == "COMPLETE":
            assert step.get("evidence_id") != "", f"[{cid}] COMPLETE step must have evidence_id, got empty!"
        elif step.get("phase") == "FINDING":
            assert step.get("evidence_id") != "", f"[{cid}] FINDING step must have evidence_id, got empty!"
        else:
            assert step.get("evidence_id") == "", f"[{cid}] Remediation/post-verification step must have empty evidence_id, got {step.get('evidence_id')}"

print("==================================================")
print("SUCCESS: ALL 518 CASES PASS CONTRACT VERIFICATION!")
print(f"  Total Data Rows:    {len(reader)}")
print(f"  Case ID Range:      case_{reader[0]['case_id'].split('_')[1]} to case_{reader[-1]['case_id'].split('_')[1]}")
print(f"  COMPLETE:           {status_counts['COMPLETE']}")
print(f"  INCOMPLETE:         {status_counts['INCOMPLETE']}")
print(f"  NOT_APPLICABLE:     {status_counts['NOT_APPLICABLE']}")
print(f"  Total Steps:        {total_steps}")
print("==================================================")
