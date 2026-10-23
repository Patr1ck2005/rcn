"""Check or explicitly copy reviewed common files, then verify release payloads.

Standard library only. The manifest is an allowlist, never a whole-tree exporter.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from fnmatch import fnmatchcase
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import zipfile


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "research_compute_network/"
SOURCE_PACKAGE = "src/" + PACKAGE
RUNTIME_PACKAGE = "runtime/python/Lib/site-packages/" + PACKAGE


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def file_sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def relative_name(name):
    if (not isinstance(name, str) or not name or "\\" in name or ":" in name
            or PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts
            or PurePosixPath(name).as_posix() != name):
        raise ValueError("unsafe relative path: " + str(name))
    return name


def load_manifest(path):
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if value.get("schema_version") != 1 or not value.get("common_files"):
        raise ValueError("invalid public export manifest")
    common = value["common_files"]
    if not isinstance(common, list) or len(set(common)) != len(common):
        raise ValueError("common_files must be a unique list")
    for name in common:
        relative_name(name)
        if name.startswith(("config/", "src/research_compute_network/help_content/protected/")):
            raise ValueError("private path cannot be common: " + name)
        if excluded(name, value):
            raise ValueError("excluded path cannot be common: " + name)
    for difference in value.get("intentional_differences", []):
        if not difference.get("reason") or not difference.get("paths"):
            raise ValueError("intentional differences require paths and a reason")
        if set(common).intersection(difference["paths"]):
            raise ValueError("common file also declared intentionally different")
    for name in value.get("required_files", []):
        relative_name(name)
        if name in common or excluded(name, value):
            raise ValueError("required file overlaps common or excluded files")
    return value


def excluded(name, manifest):
    return any(fnmatchcase(name, pattern) for pattern in manifest["excluded_public"])


def source_path(root, name):
    path = Path(root) / relative_name(name)
    # Do not follow links/reparse points into unrelated private trees on copy.
    for item in (path, *path.parents):
        info = item.lstat() if item.exists() else None
        if (item.is_symlink() or (info and getattr(info, "st_file_attributes", 0) & 0x400)
                or (info and item.is_file() and info.st_nlink > 1)):
            raise ValueError("linked source path: " + name)
        if item == Path(root):
            break
    if not path.resolve().is_relative_to(Path(root).resolve()):
        raise ValueError("source path escapes root: " + name)
    return path


def text_bytes(data):
    """Git text checkouts may differ only by LF/CRLF; artifact hashes stay raw."""
    return data.replace(b"\r\n", b"\n")


def check_sources(internal, public, manifest, *, copy_common=False):
    errors, changed = [], []
    # Only tracked names are inspected for the public source boundary. Never
    # recursively walk a workspace containing state, credentials or .scratch.
    environment = {k: v for k, v in os.environ.items()
                   if k not in {"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"}}
    names = subprocess.check_output(["git", "-C", str(public), "ls-files", "-z"], env=environment).decode("utf-8").split("\0")
    for name in filter(None, names):
        if excluded(name, manifest):
            errors.append("public source contains excluded file: " + name)
    # Preflight the whole allowlist before writing anything.
    copies = []
    for name in manifest["common_files"]:
        source, target = source_path(internal, name), source_path(public, name)
        if not source.is_file():
            errors.append("internal source missing: " + name)
        elif not target.is_file() or text_bytes(source.read_bytes()) != text_bytes(target.read_bytes()):
            if copy_common:
                copies.append((source, target, name))
            else:
                errors.append(("public source missing: " if not target.is_file() else "common source differs: ") + name)
    for name in manifest.get("required_files", []):
        for label, root in (("internal", internal), ("public", public)):
            if not source_path(root, name).is_file():
                errors.append(label + " source missing: " + name)
    if not errors and copy_common:
        for source, target, name in copies:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
            changed.append(name)
    return errors, changed


def zip_inventory(archive):
    names = [info.filename for info in archive.infolist() if not info.is_dir()]
    for name in names:
        relative_name(name)
    if len(set(names)) != len(names):
        raise ValueError("duplicate archive member")
    return set(names)


def read_member(archive, names, name, label, errors):
    if name not in names:
        errors.append(label + " missing: " + name)
        return None
    return archive.read(name)


def verify_runtime(wheel_path, runtime_path, manifest_path, stack, errors, label, *, setup_path=None):
    release = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if release.get("kind") != "rcn-public-member-client-v1" or release.get("schema_version") != 1:
        raise ValueError(label + " invalid Setup manifest")
    if release.get("wheel_sha256") != file_sha256(wheel_path):
        errors.append(label + " Setup wheel checksum differs")
    if release.get("runtime_zip_sha256") != file_sha256(runtime_path):
        errors.append(label + " Setup runtime ZIP checksum differs")
    if setup_path is not None and release.get("setup_sha256") != file_sha256(setup_path):
        errors.append(label + " Setup EXE checksum differs")
    runtime = stack.enter_context(zipfile.ZipFile(runtime_path))
    names = zip_inventory(runtime)
    embedded = read_member(runtime, names, "member-software-release.json", label + " runtime ZIP", errors)
    if embedded is None:
        return runtime, names
    embedded = json.loads(embedded)
    for key in ("kind", "schema_version", "payload_id", "package_version", "wheel_sha256", "runtime_files", "member_runtime"):
        if embedded.get(key) != release.get(key):
            errors.append(label + " embedded/Setup manifest differs: " + key)
    files = release.get("runtime_files")
    if not isinstance(files, dict) or not files:
        raise ValueError(label + " runtime_files missing")
    for name, expected in files.items():
        relative_name(name)
        if not isinstance(expected, str) or not re.fullmatch("[0-9a-f]{64}", expected):
            raise ValueError(label + " invalid runtime digest")
    actual_names = {name.removeprefix("runtime/") for name in names if name.startswith("runtime/")}
    if actual_names != set(files) or names != {"member-software-release.json", *("runtime/" + n for n in files)}:
        errors.append(label + " runtime ZIP inventory differs from Setup manifest")
    for name, expected in files.items():
        data = read_member(runtime, names, "runtime/" + name, label + " runtime ZIP", errors)
        if data is not None and sha256(data) != expected:
            errors.append(label + " runtime payload checksum differs: " + name)
    payload_id = "member-" + sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode())[:24]
    if payload_id != release.get("payload_id"):
        errors.append(label + " payload identity differs")
    return runtime, names


def check_artifacts(internal, public, manifest, *, internal_wheel, public_wheel,
                    internal_runtime, public_runtime, internal_setup_manifest,
                    public_setup_manifest, internal_setup=None, public_setup=None,
                    internal_web_root=None, public_web_root=None):
    errors, common_hashes = [], {}
    with ExitStack() as stack:
        archives = {}
        for label, root, wheel_path, runtime_path, setup_manifest, setup, web_root in (
            ("internal", internal, internal_wheel, internal_runtime, internal_setup_manifest, internal_setup, internal_web_root),
            ("public", public, public_wheel, public_runtime, public_setup_manifest, public_setup, public_web_root),
        ):
            wheel = stack.enter_context(zipfile.ZipFile(wheel_path))
            wheel_names = zip_inventory(wheel)
            runtime, runtime_names = verify_runtime(wheel_path, runtime_path, setup_manifest, stack, errors, label, setup_path=setup)
            archives[label] = (wheel, wheel_names)
            # Check every RCN payload file, including intentional differences,
            # against the wheel actually used by that side's installer.
            wheel_package = {n for n in wheel_names if n.startswith(PACKAGE)}
            runtime_package = {n.removeprefix("runtime/python/Lib/site-packages/")
                               for n in runtime_names if n.startswith(RUNTIME_PACKAGE) and not n.endswith(".pyc")}
            if wheel_package != runtime_package:
                errors.append(label + " wheel/runtime package inventory differs")
            for name in sorted(wheel_package):
                data = read_member(runtime, runtime_names, "runtime/python/Lib/site-packages/" + name, label + " runtime ZIP", errors)
                if data is not None and sha256(data) != sha256(wheel.read(name)):
                    errors.append(label + " wheel/runtime payload differs: " + name)
            for name in manifest["common_files"] + manifest.get("required_files", []):
                if name.startswith(SOURCE_PACKAGE):
                    data = read_member(wheel, wheel_names, name.removeprefix("src/"), label + " wheel", errors)
                    source = source_path(root, name)
                    if data is not None and source.is_file() and text_bytes(data) != text_bytes(source.read_bytes()):
                        errors.append(label + " wheel/source payload differs: " + name)
            # Frontend builds can differ across distributions. Each wheel must
            # contain the exact assets from its own reviewed frontend build.
            web_root = Path(web_root) if web_root else Path(root) / SOURCE_PACKAGE / "web_dist"
            web_files = {p.relative_to(web_root).as_posix(): p for p in web_root.rglob("*") if p.is_file()}
            if ("index.html" not in web_files or not any(n.endswith(".js") for n in web_files)
                    or not any(n.endswith(".css") for n in web_files)):
                errors.append(label + " built web assets missing (index, JS and CSS required)")
            wheel_web = {n.removeprefix(PACKAGE + "web_dist/") for n in wheel_names if n.startswith(PACKAGE + "web_dist/")}
            if set(web_files) != wheel_web:
                errors.append(label + " wheel/built web inventory differs")
            for name, path in web_files.items():
                data = read_member(wheel, wheel_names, PACKAGE + "web_dist/" + name, label + " wheel", errors)
                if data is not None and sha256(data) != file_sha256(path):
                    errors.append(label + " wheel/built web asset differs: " + name)
            if label == "public":
                for name in wheel_package | runtime_package:
                    if excluded("src/" + name, manifest):
                        errors.append("public artifact contains excluded file: " + name)
                # The embedded interpreter's standard-library ZIP is the only
                # archive in the generic member payload. Scientific archives
                # cannot bypass the package boundary by moving under worker/.
                for name in sorted(wheel_names):
                    if name.lower().endswith((".zip", ".mph")) and not name.startswith(PACKAGE):
                        errors.append("public wheel contains excluded scientific asset: " + name)
                for name in sorted(runtime_names):
                    if name.lower().endswith((".zip", ".mph")) and name != "runtime/python/python311.zip":
                        errors.append("public runtime contains excluded scientific asset: " + name)
        a, an = archives["internal"]
        b, bn = archives["public"]
        for source_name in manifest["common_files"]:
            if not source_name.startswith(SOURCE_PACKAGE):
                continue
            name = source_name.removeprefix("src/")
            if name in an and name in bn:
                digest = sha256(a.read(name))
                if digest != sha256(b.read(name)):
                    errors.append("common wheel payload differs: " + name)
                common_hashes[name] = digest
    return errors, common_hashes


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--internal-root", type=Path, required=True)
    parser.add_argument("--public-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=ROOT / "manifests/public-export.json")
    parser.add_argument("--copy-common", action="store_true", help="Copy only common allowlisted source files, internal to public")
    for side in ("internal", "public"):
        for option in ("wheel", "runtime", "setup-manifest", "setup", "web-root"):
            parser.add_argument(f"--{side}-{option}", type=Path)
    args = parser.parse_args(argv)
    required = [f"{side}_{option}" for side in ("internal", "public")
                for option in ("wheel", "runtime", "setup_manifest")]
    artifacts = any(getattr(args, key) is not None for key in required)
    if artifacts and (args.copy_common or not all(getattr(args, key) is not None for key in required)):
        parser.error("artifact checks require both wheels, runtime ZIPs and Setup manifests; run copy separately")
    if not artifacts and any(getattr(args, f"{side}_{option}") for side in ("internal", "public") for option in ("setup", "web_root")):
        parser.error("Setup/web inputs require the complete artifact check")
    try:
        manifest = load_manifest(args.manifest)
        errors, copied = check_sources(args.internal_root.resolve(), args.public_root.resolve(), manifest, copy_common=args.copy_common)
        hashes = {}
        if artifacts:
            additional, hashes = check_artifacts(args.internal_root, args.public_root, manifest,
                **{f"{side}_{option}": getattr(args, f"{side}_{option}") for side in ("internal", "public")
                   for option in ("wheel", "runtime", "setup_manifest", "setup", "web_root")})
            errors.extend(additional)
        print(json.dumps({"ok": not errors, "scope": "source-and-artifacts" if artifacts else "source-only",
                          "common_files": len(manifest["common_files"]),
                          "required_files": len(manifest.get("required_files", [])), "copied": copied,
                          "setup_exe_checked": {side: getattr(args, side + "_setup") is not None for side in ("internal", "public")},
                          "common_payload_sha256": hashes, "errors": errors}, indent=2))
        return int(bool(errors))
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        print(json.dumps({"ok": False, "errors": [str(error)]}, indent=2))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
