"""Build public web assets and a wheel/sdist from this source checkout."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-web", action="store_true", help="Use already-built public assets")
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT / "src"))
    from research_compute_network.release_identity import source_metadata, stamp
    import tomllib
    identity = source_metadata(ROOT)
    if identity.get("source_commit") is None or identity.get("source_dirty") is not False:
        raise SystemExit("Public release requires a clean committed tree or verified clean export")
    if not args.skip_web:
        npm = shutil.which("npm.cmd") or shutil.which("npm")
        if not npm:
            raise SystemExit("Node.js 20.19+ or 22.12+ is required to build the dashboard")
        subprocess.run([npm, "ci"], cwd=ROOT / "web", check=True)
        subprocess.run([npm, "run", "build"], cwd=ROOT / "web", check=True)
    assets = ROOT / "src/research_compute_network/web_dist/index.html"
    if not assets.is_file():
        raise SystemExit("Build dashboard assets before packaging")
    from collect_web_notices import collect
    collect()
    package = ROOT / "src/research_compute_network"
    if list((package / "acceptance_fixtures").glob("*.zip")):
        raise SystemExit("Scientific runtime archives cannot be included in a public build")
    if source_metadata(ROOT) != identity:
        raise SystemExit("Public source changed during build")
    stamp(package, package_version=tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"], metadata=identity)
    import setuptools.build_meta
    output = ROOT / "dist"
    output.mkdir(exist_ok=True)
    print(json.dumps({"wheel": setuptools.build_meta.build_wheel(str(output)),
                      "sdist": setuptools.build_meta.build_sdist(str(output))}))


if __name__ == "__main__":
    main()
