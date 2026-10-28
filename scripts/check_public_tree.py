"""Check the Git export boundary; never inspect local credentials or state."""
import argparse
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_PARTS = {".local", ".scratch", ".state", "node_modules", "__pycache__", "web_dist"}
FORBIDDEN_SUFFIXES = {".zip", ".exe", ".whl", ".mph", ".db", ".sqlite3", ".png", ".jpg", ".webp", ".pyc"}
SECRET = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|github_pat_[A-Za-z0-9_]{30,}|gh[pousr]_[A-Za-z0-9]{30,}")

_BUNDLE_SOURCE = "src/research_compute_network/member_connection_bundle.py"
_VALIDATION_PREFIX = b'    if (not key.startswith(b"'
_VALIDATION_SUFFIX = (
    b'\\n")\n'
    b'            or not key.rstrip().endswith(b"-----END OPENSSH PRIVATE KEY-----") or len(key) > 16384):\n'
    b'        _fail("invalid_ssh_identity")\n'
)
_VALIDATION_HEADER_WORDS = (b"-----BEGIN", b"OPENSSH", b"PRIVATE", b"KEY-----")


def contains_secret(name: str, data: bytes) -> bool:
    """Exclude one exact validator literal, then apply the unchanged secret rule.

    This is a source-code false positive, not permission to publish key data.
    Only this path and the complete known three-line validation block qualify.
    Additional key headers, fields, blocks and tokens remain subject to SECRET.
    """
    scan = data.replace(b"\r\n", b"\n")
    if name == _BUNDLE_SOURCE:
        exclusions = []
        for match in SECRET.finditer(scan):
            prefix_start = match.start() - len(_VALIDATION_PREFIX)
            if (tuple(match.group().split()) == _VALIDATION_HEADER_WORDS
                    and prefix_start >= 0
                    and (prefix_start == 0 or scan[prefix_start - 1:prefix_start] == b"\n")
                    and scan[prefix_start:match.start()] == _VALIDATION_PREFIX
                    and scan[match.end():].startswith(_VALIDATION_SUFFIX)):
                exclusions.append(match.span())
        # Ambiguous or duplicated validator text gets no exception.
        if len(exclusions) == 1:
            start, end = exclusions[0]
            scan = scan[:start] + scan[end:]
    return SECRET.search(scan) is not None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--include-untracked", action="store_true",
                        help="Also check non-ignored candidate source files without staging them")
    args = parser.parse_args(argv)
    command = ["git", "ls-files", "-z"]
    if args.include_untracked:
        command.extend(["--cached", "--others", "--exclude-standard"])
    names = subprocess.check_output(command, cwd=ROOT).decode().split("\0")
    if not any(names):
        raise SystemExit("Public source inventory is empty; select a Git source checkout")
    failures = []
    for name in filter(None, names):
        path = Path(name)
        if (FORBIDDEN_PARTS.intersection(path.parts) or path.suffix.lower() in FORBIDDEN_SUFFIXES
                or name.startswith("src/research_compute_network/tests/")):
            failures.append((name, "not a public source artifact"))
        data = (ROOT / path).read_bytes()
        if contains_secret(name, data):
            failures.append((name, "credential-shaped content"))
    if failures:
        for name, reason in failures:
            print(f"{name}: {reason}")
        raise SystemExit(1)
    print(f"Public source boundary: {sum(bool(name) for name in names)} files checked")


if __name__ == "__main__":
    main()
