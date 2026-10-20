"""Bounded conditional admission. No runtime/protocol or remote command changes.

A project approval alone must never expand an invited machine to another Profile.
These limits remain in its policy and are applied again at every placement.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ID_PATTERN = r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}$'


def canonical_digest(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=True, sort_keys=True,
        separators=(',', ':')).encode('ascii')).hexdigest()


class AdmissionScope(BaseModel):
    model_config = ConfigDict(extra='forbid', hide_input_in_errors=True)
    project_profiles: dict[str, list[str]] = Field(default_factory=dict)
    person_profiles: dict[str, list[str]] = Field(default_factory=dict, exclude_if=lambda value: not value)
    max_cpus: int = Field(strict=True, ge=1, le=256)
    max_memory_mb: int = Field(strict=True, ge=256, le=1048576)
    max_concurrent_units: Literal[1] = 1

    @field_validator('max_concurrent_units', mode='before')
    @classmethod
    def one_slot(cls, value):
        if type(value) is not int or value != 1:
            raise ValueError('initial_admission_requires_one_slot')
        return value

    @field_validator('project_profiles', 'person_profiles', mode='before')
    @classmethod
    def scope(cls, value):
        if not isinstance(value, dict) or not 0 <= len(value) <= 16:
            raise ValueError('explicit_project_scope_required')
        for project, profiles in value.items():
            if (not isinstance(project, str) or not re.fullmatch(ID_PATTERN, project)
                    or not isinstance(profiles, list) or not 1 <= len(profiles) <= 16
                    or any(not isinstance(p, str) or not re.fullmatch(ID_PATTERN, p) for p in profiles)
                    or profiles != sorted(set(profiles))):
                raise ValueError('invalid_project_profile_scope')
        return dict(sorted(value.items()))

    @model_validator(mode="after")
    def explicit_scope(self):
        if not self.project_profiles and not self.person_profiles:
            raise ValueError("explicit_member_or_project_scope_required")
        return self


class ConditionalAdmissionRequest(AdmissionScope):
    admission_policy: Literal['trust_first', 'acceptance_required'] = 'trust_first'
    valid_for_days: int | None = Field(strict=True, ge=1, le=365, default=None)
    acknowledge_project_trust: bool = Field(strict=True, default=False)


class MemberExecutionLimit(AdmissionScope):
    """An additional AND gate, never an alternative to existing approvals."""
    schema_version: Literal[1] = 1
    enrollment_id: str = Field(pattern=ID_PATTERN)
    runtime_version: str = Field(pattern=r'^[a-f0-9]{24}$')
    offer_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    consent_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    expires_at: datetime | None
    active: bool = Field(strict=True, default=True)
    project_trust_labels: dict[str, list[str]] = Field(default_factory=dict)

    @model_validator(mode='after')
    def bounded_trust(self):
        if not set(self.project_trust_labels).issubset(self.project_profiles):
            raise ValueError('trust_outside_project_scope')
        for labels in self.project_trust_labels.values():
            if (len(labels)>32 or labels!=sorted(set(labels))
                    or any(not re.fullmatch(ID_PATTERN,label) for label in labels)):
                raise ValueError('invalid_project_trust_snapshot')
        return self

    @field_validator('expires_at')
    @classmethod
    def aware(cls, value):
        if value is not None and value.tzinfo is None:
            raise ValueError('admission_expiry_requires_timezone')
        return value

    def is_active(self, now: datetime | None = None) -> bool:
        at = now or datetime.now(timezone.utc)
        return self.active and (self.expires_at is None or self.expires_at > at)

    def permits(self, project_id: str, profile_id: str, runtime_version: str | None,
                *, now: datetime | None = None, user_id: str | None = None) -> bool:
        return bool(self.is_active(now)
            and (profile_id in self.project_profiles.get(project_id, [])
                 or (user_id is not None and profile_id in self.person_profiles.get(user_id, [])))
            and runtime_version == self.runtime_version)
