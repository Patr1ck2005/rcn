"""Build a fresh Windows x64 public member Setup from reviewed offline inputs."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from research_compute_network.member_client_installer import build_member_client_installer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--python-archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    digest = hashlib.sha256(args.wheel.read_bytes()).hexdigest()
    print(json.dumps(build_member_client_installer(wheel_path=args.wheel,
        wheelhouse_dir=args.wheelhouse, embeddable_zip=args.python_archive,
        output_exe=args.output, expected_wheel_sha256=digest), indent=2))


if __name__ == "__main__":
    main()
