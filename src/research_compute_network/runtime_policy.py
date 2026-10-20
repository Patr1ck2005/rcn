"""Immutable identities and compatibility policy for Network deployments."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
import re


PROTOCOL_VERSION = "1"
PACKAGE_VERSION = "0.15.0a1"
# A public, non-executable identity marker, never a bundled scientific runtime.
UNCONFIGURED_RUNTIME_VERSION = "f2a0851b1fcdf782e5c5c063"
STABLE_RUNTIME_VERSION = UNCONFIGURED_RUNTIME_VERSION
PREVIOUS_STABLE_RUNTIME_VERSION = UNCONFIGURED_RUNTIME_VERSION
LEGACY_SEALED_RUNTIME_VERSION = UNCONFIGURED_RUNTIME_VERSION
RUNTIME_FINGERPRINT_PATTERN = re.compile(r"[0-9a-f]{24}")


def _validate_fingerprints(values: frozenset[str], *, label: str) -> None:
    invalid = sorted(value for value in values if not RUNTIME_FINGERPRINT_PATTERN.fullmatch(value))
    if invalid:
        raise ValueError(f"{label} must be 24-character lowercase fingerprints")


@dataclass(frozen=True)
class RuntimePolicy:
    """Worker-runtime policy injected once at process startup."""

    stable_runtime_version: str = STABLE_RUNTIME_VERSION
    legacy_runtime_versions: frozenset[str] = field(default_factory=frozenset)
    candidate_runtime_versions: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        _validate_fingerprints(
            frozenset({self.stable_runtime_version}),
            label="stable runtime",
        )
        _validate_fingerprints(self.legacy_runtime_versions, label="legacy runtimes")
        _validate_fingerprints(self.candidate_runtime_versions, label="candidate runtimes")
        reserved = frozenset({self.stable_runtime_version}) | self.legacy_runtime_versions
        if self.candidate_runtime_versions & reserved:
            raise ValueError("candidate runtime must be distinct from stable and legacy runtimes")

    @classmethod
    def with_candidates(
        cls,
        versions: list[str] | tuple[str, ...] | set[str] | frozenset[str],
    ) -> "RuntimePolicy":
        normalized = frozenset(str(value).strip() for value in versions if str(value).strip())
        return cls(candidate_runtime_versions=normalized)

    @property
    def worker_runtime_versions(self) -> frozenset[str]:
        return frozenset({self.stable_runtime_version, *self.legacy_runtime_versions,
                          *self.candidate_runtime_versions}) - {UNCONFIGURED_RUNTIME_VERSION}

    @property
    def approval_runtime_versions(self) -> frozenset[str]:
        return frozenset({self.stable_runtime_version, *self.candidate_runtime_versions}) - {UNCONFIGURED_RUNTIME_VERSION}

    def accepts_worker_runtime(self, version: str | None) -> bool:
        return bool(version and version in self.worker_runtime_versions)

    def accepts_new_approval(self, version: str | None) -> bool:
        return bool(version and version in self.approval_runtime_versions)


@dataclass(frozen=True)
class ControlPlaneIdentity:
    """Names the independently versioned control and worker layers."""

    package_version: str
    protocol_version: str
    deployment_id: str
    worker_runtime_version: str

    @classmethod
    def current(cls, policy: RuntimePolicy) -> "ControlPlaneIdentity":
        return cls(
            package_version=PACKAGE_VERSION,
            protocol_version=PROTOCOL_VERSION,
            deployment_id=os.environ.get("RCN_CONTROL_PLANE_DEPLOYMENT_ID", PACKAGE_VERSION),
            worker_runtime_version=policy.stable_runtime_version,
        )


DEFAULT_RUNTIME_POLICY = RuntimePolicy()


def runtime_policy_from_environment() -> RuntimePolicy:
    """External archive approval is separate from per-machine execution approval."""
    from .member_release_catalog import selected_center_release
    release = selected_center_release()
    candidates = frozenset(value.strip() for value in
        os.environ.get("RCN_CANARY_RUNTIME_VERSIONS", "").split(",") if value.strip())
    return RuntimePolicy(stable_runtime_version=release.runtime_version,
                         candidate_runtime_versions=candidates - {release.runtime_version})
