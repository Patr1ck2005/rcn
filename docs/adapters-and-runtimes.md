# Origin adapters and scientific runtimes

[Home](../README.md) · [Architecture](architecture.md) · [Member guide](member-guide.md)

RCN provides the coordination layer. A functioning scientific deployment connects **an origin adapter, a registered execution profile, and an approved runtime on an admitted machine**. Installing RCN or registering a profile supplies only part of that chain.

## What comes from where

| Included in this repository | Supplied by the deploying group |
|---|---|
| Typed job, resource, manifest, and approval contracts | Project-specific inputs, templates, and scientific definitions |
| Planning, placement, scheduling, and dispatch machinery | Origin adapter that produces valid packages and imports results |
| Supervisor, transport, admission, and runtime-management code | Tested transport endpoints, machine identity, and owner authorization |
| Member client and personal Agent CLI | Group-issued credentials, grants, and invitations |
| Scientific profile schemas and compatibility gates | Approved sealed scientific runtime matching those contracts |
| Synthetic local demo | Solver installation, licenses, and any runtime dependencies |

No sealed scientific runtime archive, COMSOL installer, licensed solver, or scientific project dataset is distributed with this source. A wheel containing RCN is not a complete scientific worker environment.

## Adapter contract

An origin adapter translates a project's own scientific definition into RCN's data contracts. It should:

1. Create stable atomic-item identities and a structured request for a registered profile.
2. Declare resources and outputs, construct an input manifest, and seal the package.
3. Preserve the confirmed plan, request hash, job ID, and operation ID across interruptions.
4. Collect the original result manifest, check expected coverage and file hashes, then import through the project's own data rules.
5. Keep scientific interpretation and acceptance in the origin project.

RCN includes profile contracts named `workbench-comsol-*` for integration with the originating research workflow. They describe versioned data and execution semantics. They do not embed that workflow's private projects or provide a universal importer.

Profiles are approved executors with bounded schemas. User-provided shell commands, arbitrary Python entrypoints, and general-purpose remote shells are not a supported submission API. When adding an integration, implement and review a new executor/profile path rather than adding a command field to a job.

## Runtime and operator preparation

Before inviting a member to contribute compute, the operator needs to establish:

- An authenticated center endpoint, scoped personal access, and explicit machine-owner consent.
- A supported host environment, approved runtime fingerprint, and relevant solver/template compatibility approval.
- Transport identity and connectivity, supervised process execution, telemetry, and result transfer.
- Resource and storage policies, retention/custody handling, and a tested drain/recovery procedure.
- A bounded end-to-end acceptance run: submit, execute, collect, verify hashes and coverage, and import at the origin.

The Windows member path contains COMSOL 6.4 and managed-account integration. That route requires the corresponding software and a compatible, operator-provided runtime. Other profiles and platforms require their own implementation and acceptance; the Python API being portable does not make every worker path portable.

Runtime approval records a specific identity. Changing a runtime's content requires a new fingerprint and the applicable approval/admission process. Changing the control plane does not by itself deploy or approve a scientific runtime on machines.

## Configure the operator runtime catalogue

A fresh installation has `state: "runtime_not_configured"` at `/v1/execution-runtime`. Its public marker fingerprint is not an executable runtime approval. No scientific archive is bundled, and setting a runtime hash in a job or API request cannot enable one.

Prepare and review a compatible archive locally, then create an operator-owned JSON descriptor outside the source checkout:

```json
{
  "format": "rcn-public-runtime-approval-v1",
  "runtime_version": "<24 lowercase hexadecimal characters>",
  "archive_sha256": "<SHA-256 of the complete ZIP, 64 lowercase hexadecimal characters>",
  "supervisor_sha256": "<SHA-256 of remote-agent/supervisor.py inside the ZIP>",
  "archive_path": "C:/RCN/operator-runtime/approved-runtime.zip",
  "actor_id": "group-operator",
  "reason": "Reviewed runtime for this group's registered profiles",
  "owner_session_required": true
}
```

Replace the placeholder hashes with actual values and set the descriptor's absolute path before starting the center:

```powershell
$env:RCN_RUNTIME_DESCRIPTOR = 'C:/RCN/operator-runtime/approval.json'
# Start the center with the deployment's normal command and state root.
```

The descriptor must be a regular file of at most 16 KiB; paths must be absolute, contain no traversal, and traverse no symbolic links or reparse points. Only the eight shown fields are accepted; actor and reason must be nonempty, and owner-session enforcement must be `true`. The selected fingerprint must differ from the public unconfigured marker. If `RCN_MEMBER_RELEASE_RUNTIME` is also set, it must match the descriptor.

The ZIP is limited to 8 MiB, 2,048 files, 32 MiB expanded, and 256 KiB per file. Entries must be ordinary files with safe, unique, case-insensitive paths. Its `runtime-manifest.json` must contain integer `schema_version: 1`, a `version` matching the descriptor, and a `files` mapping with `"__runtime_layout_version__": "2"`. The remaining mapping entries pin Python sources by SHA-256:

- `remote-agent/name.py` maps directly to that archive path.
- `workbench/name.py` maps to `workbench-src/research_agent_workbench/name.py` for a separately supplied compatible adapter module.

The required supervisor, metrics, Windows job, storage, and owner-session gate modules must be present and manifested as `remote-agent/supervisor.py`, `remote-agent/remote_metrics.py`, `remote-agent/windows_job.py`, `remote-agent/worker_storage.py`, and `remote-agent/member_session_gate.py`. Additional declared modules are allowed within these namespaces. Every Python file must be declared and match its manifest hash. Additional resources in those namespaces are pinned by the complete ZIP hash. The supervisor must also match the descriptor's independent supervisor hash. The center validates these bytes without executing or installing the archive.

This catalogue enables selection of the approved runtime; machine admission, owner consent, exact solver/template approvals, pause/logout gates, and execution acceptance still apply. It does not infer scientific equivalence or create successor solver approvals. Changes to archive content require a new fingerprint, hashes, and the corresponding approvals. Member installation starts disabled at zero target capacity.

## Practical readiness checks

Use `/health` for API readiness, `/v1/operations/summary` and `/v1/overview` for operational state, and `/v1/jobs/{job_id}/placement-diagnostics` for a particular job's gates. Authenticated endpoints require the appropriate group permissions.

Check runtime attestation, an actual attempt, and verified collection separately. A visible machine, accepted invitation, successful frontend build, or HTTP 200 is not a substitute for that end-to-end acceptance. Begin with the [synthetic demo](quickstart.md); move to real execution only after the group has configured this chain.
