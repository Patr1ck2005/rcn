"""Check the Git export boundary; never inspect local credentials or state."""
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_PARTS = {".local", ".scratch", ".state", "node_modules", "__pycache__", "web_dist"}
FORBIDDEN_SUFFIXES = {".zip", ".exe", ".whl", ".mph", ".db", ".sqlite3", ".png", ".jpg", ".webp", ".pyc"}
SECRET = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|github_pat_[A-Za-z0-9_]{30,}|gh[pousr]_[A-Za-z0-9]{30,}")


def main():
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
    if not any(names):
        raise SystemExit("Stage the reviewed public source export before checking")
    failures = []
    for name in filter(None, names):
        path = Path(name)
        if (FORBIDDEN_PARTS.intersection(path.parts) or path.suffix.lower() in FORBIDDEN_SUFFIXES
                or name.startswith("src/research_compute_network/tests/")):
            failures.append((name, "not a public source artifact"))
        data = (ROOT / path).read_bytes()
        if SECRET.search(data):
            failures.append((name, "credential-shaped content"))
    if failures:
        for name, reason in failures:
            print(f"{name}: {reason}")
        raise SystemExit(1)
    print(f"Public source boundary: {sum(bool(name) for name in names)} files checked")


if __name__ == "__main__":
    main()
