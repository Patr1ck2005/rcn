"""Execute the fixed synthetic worker locally, with no SSH, solver or user code."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, required=True, help="A new, dedicated directory; outputs are retained")
    args = parser.parse_args()
    root = args.output_root.absolute()
    root.mkdir(parents=True, exist_ok=False)
    result = root / "output/safe-fake-result.json"
    request = {"schema_version": 1, "profile_id": "rcn-safe-fake-v1",
               "acceptance_nonce": "rcn-public-fixed-worker", "duration_seconds": 0.1,
               "out_manifest": str(result)}
    job = root / "job.json"
    job.write_text(json.dumps(request), encoding="utf-8")
    subprocess.run([sys.executable, "-m", "research_compute_network.remote_agent.fake_worker",
                    "--job", str(job)], cwd=root, check=True, capture_output=True)
    value = json.loads(result.read_text(encoding="utf-8"))
    assert value["profile_id"] == request["profile_id"]
    assert value["acceptance_nonce"] == request["acceptance_nonce"]
    assert value["iterations"] > 0
    receipt = {"kind": "fixed-worker-local-smoke", "verified": True,
               "profile_id": value["profile_id"], "size_bytes": result.stat().st_size,
               "sha256": hashlib.sha256(result.read_bytes()).hexdigest(),
               "remote_execution_tested": False, "scientific_solver_used": False}
    (root / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
