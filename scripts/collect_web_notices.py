"""Carry upstream license texts into the generated browser distribution."""
from __future__ import annotations

import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]


def collect():
    destination = ROOT / "src/research_compute_network/web_dist/licenses"
    destination.mkdir(parents=True, exist_ok=True)
    lock = json.loads((ROOT / "web/package-lock.json").read_text(encoding="utf-8"))
    inventory = []
    for relative, metadata in sorted(lock["packages"].items()):
        if not relative.startswith("node_modules/") or metadata.get("dev"):
            continue
        source = ROOT / "web" / relative
        files = [path for path in source.iterdir() if path.is_file() and
                 path.name.lower().startswith(("license", "licence", "copying", "notice", "copyright"))] if source.is_dir() else []
        identifier = relative.removeprefix("node_modules/").replace("/", "__")
        saved = []
        for path in files:
            target = destination / identifier / path.name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
            saved.append(target.relative_to(destination).as_posix())
        inventory.append({"package": relative.removeprefix("node_modules/"),
                          "version": metadata.get("version"), "license": metadata.get("license"),
                          "notice_files": saved})
    (destination / "inventory.json").write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
    return inventory


if __name__ == "__main__":
    print(json.dumps({"packages": len(collect())}))
