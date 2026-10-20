"""Bounded, non-command failure evidence for persisted operational state."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Iterator


_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~-]{12,}")
_TOKEN_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(RCN_TOKEN|TOKEN|PASSWORD|SECRET)\s*[:=]\s*[^\s,;]+"
)
_ENCODED_COMMAND_RE = re.compile(
    r"(?i)(?:-EncodedCommand|EncodedCommand)\s*[,=:]?\s*['\"]?[A-Za-z0-9+/=]{32,}"
)
_LONG_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{160,}={0,2}")
_WINDOWS_PATH_RE = re.compile(r"(?i)\b[A-Z]:\\[^\r\n\t\"']+")
_CLIXML_MARKERS = ("#< CLIXML", "<Objs Version=")

# These markers identify deterministic model/input evaluation failures. Keep
# the predicate deliberately narrow: a generic COMSOL FlException can also be
# caused by runtime or deployment regressions and must remain diagnosable.
_SCIENTIFIC_EVALUATION_MARKERS = (
    "division by zero",
    "divide by zero",
    "zero division",
    "除零",
    "unable to evaluate expression",
    "cannot evaluate expression",
    "无法计算表达式",
)

_STORAGE_EXHAUSTION_MARKERS = (
    "no space left", "disk full", "disk quota", "not enough space on the disk",
    "insufficient disk space", "磁盘空间不足", "磁盘已满", "磁碟空間不足",
)
_NATIVE_FILE_IO_MARKERS = (
    "cannot open native file", "could not open native file", "unable to open native file",
    "无法打开原生文件", "無法開啟原生檔案",
)

# Known SSH/SCP diagnostics are machine-scoped only without contradictory
# integrity evidence. Unknown diagnostics remain conservative; exit 255 alone
# is ambiguous because ssh also returns the remote command's exit status.
_SSH_TRANSPORT_MARKERS = (
    "server not responding",
    "connection timed out",
    "connection refused",
    "connection closed by",
    "connection reset by peer",
    "could not resolve hostname",
    "ssh: connect to host",
    "host key verification failed",
    "permission denied (publickey",
    "broken pipe",
)


def is_collection_integrity_failure(value: str) -> bool:
    normalized = " ".join(str(value).lower().split())
    return any(marker in normalized for marker in (
        "manifest", "hash mismatch", "checksum", "content conflict", "integrity",
        "unsafe path", "identity mismatch", "root mismatch", "path traversal",
    ))


def is_ssh_transport_failure(value: str) -> bool:
    """Return whether bounded evidence proves an SSH/SCP connection failure."""
    normalized = " ".join(str(value).lower().split())
    return not is_collection_integrity_failure(normalized) and any(
        marker in normalized for marker in _SSH_TRANSPORT_MARKERS
    )


def is_memory_exhaustion_failure(value: str) -> bool:
    normalized = " ".join(str(value).lower().split())
    return any(marker in normalized for marker in (
        "out of memory", "not enough memory", "insufficient memory", "memory limit exceeded",
        "java.lang.outofmemoryerror", "内存不足", "記憶體不足", "內存不足", "无法分配内存",
        "could not allocate memory", "cannot allocate memory",
    ))


def is_comsol_disconnect_failure(value: str) -> bool:
    normalized = " ".join(str(value).lower().split())
    return "disconnect while not connected" in normalized or "disconnect when not connected" in normalized


def is_storage_exhaustion_failure(value: str) -> bool:
    return any(marker in str(value).lower() for marker in _STORAGE_EXHAUSTION_MARKERS)


def is_native_file_io_failure(value: str) -> bool:
    """File I/O evidence does not establish a bad model or a full disk."""
    return any(marker in str(value).lower() for marker in _NATIVE_FILE_IO_MARKERS)


def _exception_chain(error: BaseException) -> Iterator[BaseException]:
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = current.__cause__ or current.__context__


def timeout_evidence(error: BaseException) -> tuple[str, float | None] | None:
    """Return the timeout type and duration without retaining command argv."""

    for candidate in _exception_chain(error):
        if isinstance(candidate, subprocess.TimeoutExpired):
            value = candidate.timeout
            return type(candidate).__name__, float(value) if value is not None else None
        if isinstance(candidate, TimeoutError):
            return type(candidate).__name__, None
    return None


def sanitize_failure_text(
    value: str,
    *,
    fallback: str = "remote_error",
    max_length: int = 320,
) -> str:
    """Bound already-persisted failure text for safe operational display."""
    detail = str(value)
    for marker in _CLIXML_MARKERS:
        detail = detail.split(marker, 1)[0]
    detail = _BEARER_RE.sub("Bearer <redacted>", detail)
    detail = _TOKEN_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}=<redacted>", detail)
    detail = _ENCODED_COMMAND_RE.sub("EncodedCommand <redacted>", detail)
    detail = _LONG_BASE64_RE.sub("<encoded-command-redacted>", detail)
    detail = _WINDOWS_PATH_RE.sub("<remote-path>", detail)
    detail = " ".join(detail.replace("\x00", " ").split()).strip(" :;,.-")

    command_markers = ("Command '[", 'Command "[', "powershell -EncodedCommand")
    if not detail or any(marker.lower() in detail.lower() for marker in command_markers):
        detail = fallback
    return detail[:max_length].rstrip()


def safe_failure_reason(
    error: BaseException | str,
    *,
    action: str,
    default_timeout_s: float | None = None,
    max_length: int = 320,
) -> str:
    """Describe an operational failure without commands, secrets, or CLIXML."""

    if isinstance(error, BaseException):
        timeout = timeout_evidence(error)
        if timeout is not None:
            duration = timeout[1] if timeout[1] is not None else default_timeout_s
            if duration is not None:
                rendered = int(duration) if float(duration).is_integer() else round(duration, 1)
                return f"{action} timed out after {rendered} seconds"
            return f"{action} timed out"
        detail = str(error)
        error_type = type(error).__name__
    else:
        detail = str(error)
        error_type = "remote_error"

    detail = sanitize_failure_text(
        detail,
        fallback=error_type,
        max_length=max_length,
    )
    prefix = f"{action} failed"
    if detail.lower().startswith(prefix.lower()):
        message = detail
    else:
        message = f"{prefix}: {detail}"
    return message[:max_length].rstrip()


# Windows console-termination exit codes observed when a worker's transport
# session is torn down underneath it (reverse-tunnel flap, SSH session death,
# interactive logoff). The worker dies before any diagnostic can be written,
# so the persisted evidence is exactly this exit code, never a traceback.
# STATUS_CONTROL_C_EXIT (0xC000013A) is the documented signature of a closed
# console. Keep the set narrow and extend it only with equally deterministic
# termination codes; generic nonzero exits must stay diagnosable as unknown.
_WORKER_TERMINATION_EXIT_CODES = frozenset({3221225786})  # 0xC000013A
_WORKER_EXIT_CODE_RE = re.compile(r"\bworker exit code (-?\d+)\b")


def normalized_worker_exit_code(value: str) -> int | None:
    """Extract a worker exit code from persisted failure text as unsigned 32-bit."""
    match = _WORKER_EXIT_CODE_RE.search(str(value))
    if match is None:
        return None
    code = int(match.group(1))
    return code if code >= 0 else code + (1 << 32)


def is_worker_termination_failure(value: str) -> bool:
    """Return whether bounded evidence proves the worker console was torn down."""
    code = normalized_worker_exit_code(value)
    return code is not None and code in _WORKER_TERMINATION_EXIT_CODES


def is_deterministic_scientific_failure(value: str) -> bool:
    """Return whether bounded worker evidence proves a scientific input failure."""

    normalized = " ".join(str(value).lower().split())
    if (is_memory_exhaustion_failure(normalized) or is_storage_exhaustion_failure(normalized)
            or is_native_file_io_failure(normalized)):
        return False
    return any(marker in normalized for marker in _SCIENTIFIC_EVALUATION_MARKERS)
