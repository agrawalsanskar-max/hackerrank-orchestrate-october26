"""Main CLI Driver for Ghost Data Still Exists.

Executes the deletion audit pipeline:
1. Intent Classification
2. Temporal Identity Resolution
3. Multi-Modal Evidence Forensics
4. Policy Remediation Planning
5. Canonical Serialization
"""

from __future__ import annotations

import argparse
import csv
import sys
import time
from pathlib import Path

# Add script directory to python path
code_dir = Path(__file__).parent.resolve()
if str(code_dir) not in sys.path:
    sys.path.insert(0, str(code_dir))

from policy_planner import PolicyPlanner
from serializer import serialize_steps


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ghost Data Still Exists: AI-powered Deletion Audit Agent"
    )
    parser.add_argument(
        "--input",
        type=str,
        default="dataset/deletion_requests.csv",
        help="Path to input deletion requests CSV file.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="output.csv",
        help="Path to destination output predictions CSV file.",
    )
    parser.add_argument(
        "--dataset-dir",
        type=str,
        default="dataset",
        help="Path to repository dataset directory.",
    )
    return parser.parse_args()


def run_pipeline(input_path: str, output_path: str, dataset_dir: str = "dataset"):
    start_time = time.time()
    input_file = Path(input_path)
    output_file = Path(output_path)

    if not input_file.exists():
        print(f"Error: Input file {input_path} does not exist.", file=sys.stderr)
        sys.exit(1)

    print(f"Initializing Ghost Data Still Exists Deletion Audit Agent...")
    print(f"  Input:       {input_file}")
    print(f"  Output:      {output_file}")
    print(f"  Dataset dir: {dataset_dir}")

    planner = PolicyPlanner(dataset_dir=dataset_dir)

    with open(input_file, "r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))

    total_cases = len(reader)
    print(f"\nProcessing {total_cases} requests...")

    status_counts = {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0}
    total_steps = 0
    output_rows = []

    for idx, req in enumerate(reader, start=1):
        case_id = req.get("case_id", f"case_{idx}")
        status, steps = planner.plan_case(req)
        status_counts[status] = status_counts.get(status, 0) + 1
        total_steps += len(steps)
        steps_json = serialize_steps(steps)

        output_rows.append({
            "case_id": case_id,
            "deletion_status": status,
            "steps_json": steps_json,
        })

        if idx % 10 == 0 or idx == total_cases:
            print(f"  Processed {idx}/{total_cases} cases ({(idx/total_cases)*100:.1f}%)...")

    # Ensure parent directory exists
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["case_id", "deletion_status", "steps_json"],
            quoting=csv.QUOTE_MINIMAL,
        )
        writer.writeheader()
        writer.writerows(output_rows)

    elapsed = time.time() - start_time
    print(f"\nAudit Execution Finished in {elapsed:.2f}s ({elapsed/total_cases*1000:.1f}ms/case):")
    print(f"  Total Cases:         {total_cases}")
    print(f"  COMPLETE:            {status_counts.get('COMPLETE', 0)}")
    print(f"  INCOMPLETE:          {status_counts.get('INCOMPLETE', 0)}")
    print(f"  NOT_APPLICABLE:      {status_counts.get('NOT_APPLICABLE', 0)}")
    print(f"  Total Steps:         {total_steps}")
    print(f"  Output written to:   {output_file.resolve()}\n")


def main():
    args = parse_args()
    run_pipeline(args.input, args.output, args.dataset_dir)


if __name__ == "__main__":
    main()
