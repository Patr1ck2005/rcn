"""Registered execution profiles.

Profiles describe allowed executors. They intentionally do not accept a user
provided command string.
"""

from .models import ExecutionProfile, ResourceRequest


WORKBENCH_COMSOL_SCAN_V1 = ExecutionProfile(
    profile_id="workbench-comsol-scan-v1",
    version="1.0.0",
    executor_kind="workbench_comsol_scan",
    platforms={"windows"},
    required_capabilities={"comsol-6.4", "python-mph"},
    output_schema="workbench-raw-dataset-v1",
    default_resources=ResourceRequest(cpus=4, memory_mb=8192, disk_mb=32768),
)

WORKBENCH_COMSOL_EIGEN_V2 = ExecutionProfile(
    profile_id="workbench-comsol-eigen-v2",
    version="2.0.0",
    executor_kind="workbench_comsol_eigen",
    platforms={"windows"},
    required_capabilities={"comsol-6.4", "python-mph"},
    output_schema="workbench-eigen-atoms-v2",
    default_resources=ResourceRequest(cpus=4, memory_mb=8192, disk_mb=32768),
)

# v3 records the explicit MeshPolicy carried by Scan Spec v2.  Keep v2
# registered for previously confirmed Jobs; changing its semantics would make
# existing solver approvals and provenance ambiguous.
WORKBENCH_COMSOL_EIGEN_V3 = ExecutionProfile(
    profile_id="workbench-comsol-eigen-v3",
    version="3.0.0",
    executor_kind="workbench_comsol_eigen",
    platforms={"windows"},
    required_capabilities={"comsol-6.4", "python-mph"},
    output_schema="workbench-eigen-atoms-v3",
    default_resources=ResourceRequest(cpus=4, memory_mb=8192, disk_mb=32768),
)

# v4 adds a capability-selected, canonical per-mode result contract.  It is a
# new immutable Profile rather than a change to v3: template layout adapters
# and radiation validity gates are part of scientific provenance.
WORKBENCH_COMSOL_EIGEN_V4 = ExecutionProfile(
    profile_id="workbench-comsol-eigen-v4",
    version="4.0.0",
    executor_kind="workbench_comsol_eigen",
    platforms={"windows"},
    required_capabilities={"comsol-6.4", "python-mph"},
    output_schema="workbench-eigen-atoms-v4",
    default_resources=ResourceRequest(cpus=4, memory_mb=8192, disk_mb=32768),
)

WORKBENCH_COMSOL_FREQUENCY_V1 = ExecutionProfile(
    profile_id="workbench-comsol-frequency-v1",
    version="1.0.0",
    executor_kind="workbench_comsol_frequency",
    platforms={"windows"},
    required_capabilities={"comsol-6.4", "python-mph"},
    output_schema="workbench-frequency-atoms-v1",
    default_resources=ResourceRequest(cpus=4, memory_mb=8192, disk_mb=32768),
)

# v2 makes the runner's mesh policy and expression profile explicit.  It does
# not replace v1 because Profile IDs are immutable execution contracts.
WORKBENCH_COMSOL_FREQUENCY_V2 = ExecutionProfile(
    profile_id="workbench-comsol-frequency-v2",
    version="2.0.0",
    executor_kind="workbench_comsol_frequency",
    platforms={"windows"},
    required_capabilities={"comsol-6.4", "python-mph"},
    output_schema="workbench-frequency-atoms-v2",
    default_resources=ResourceRequest(cpus=4, memory_mb=8192, disk_mb=32768),
)


# The generic Study Profile carries a declarative, data-only Study and output
# request.  It never accepts an entrypoint, command, package, or remote path.
WORKBENCH_COMSOL_STUDY_V1 = ExecutionProfile(
    profile_id="workbench-comsol-study-v1",
    version="1.0.0",
    executor_kind="workbench_comsol_study",
    platforms={"windows"},
    required_capabilities={"comsol-6.4", "python-mph"},
    output_schema="workbench-comsol-raw-study-v1",
    default_resources=ResourceRequest(cpus=4, memory_mb=8192, disk_mb=32768),
)

# v2 adds bounded periodic-port excitation and explicit sparse frequency lists.
# v1 remains immutable for every already-approved generic Study job.
WORKBENCH_COMSOL_STUDY_V2 = ExecutionProfile(
    profile_id="workbench-comsol-study-v2",
    version="2.0.0",
    executor_kind="workbench_comsol_study",
    platforms={"windows"},
    required_capabilities={"comsol-6.4", "python-mph"},
    output_schema="workbench-comsol-raw-study-v2",
    default_resources=ResourceRequest(cpus=4, memory_mb=8192, disk_mb=32768),
)


# A separate immutable contract constructs one reviewed template and executes
# zero Studies. It does not extend the existing Study profile semantics.
WORKBENCH_COMSOL_TEMPLATE_BUILD_V1 = ExecutionProfile(
    profile_id="workbench-comsol-template-build-v1",
    version="1.0.0",
    executor_kind="workbench_comsol_template_build",
    platforms={"windows"},
    required_capabilities={"comsol-6.4", "python-mph"},
    output_schema="workbench-comsol-template-build-v1",
    default_resources=ResourceRequest(cpus=4, memory_mb=8192, disk_mb=256),
)


# Read one registered saved solution without geometry, mesh, Study or solver runs.
WORKBENCH_COMSOL_SAVED_READOUT_V1 = ExecutionProfile(
    profile_id="workbench-comsol-saved-readout-v1",
    version="1.0.0",
    executor_kind="workbench_comsol_saved_readout",
    platforms={"windows"},
    required_capabilities={"comsol-6.4", "python-mph"},
    output_schema="workbench-comsol-saved-readout-v1",
    default_resources=ResourceRequest(cpus=4, memory_mb=8192, disk_mb=256),
)


SAFE_FAKE_TASK_V1 = ExecutionProfile(
    profile_id="rcn-safe-fake-v1",
    version="1.0.0",
    executor_kind="safe_fake_task",
    platforms={"windows"},
    required_capabilities=set(),
    output_schema="rcn-safe-fake-result-v1",
    default_resources=ResourceRequest(cpus=1, memory_mb=256, disk_mb=16),
)

PROJECT_WORKER_V1 = ExecutionProfile(
    profile_id="project-worker-v1",
    version="1.0.0",
    executor_kind="project_worker",
    platforms={"windows"},
    required_capabilities={"python-project-worker"},
    output_schema="project-worker-result-v1",
    default_resources=ResourceRequest(cpus=1, memory_mb=1024, disk_mb=1024),
)

# Only platform-generic contracts are registered in the public distribution.
BUILTIN_PROFILES = {
    profile.profile_id: profile for profile in (
        WORKBENCH_COMSOL_SCAN_V1, WORKBENCH_COMSOL_STUDY_V1,
        WORKBENCH_COMSOL_STUDY_V2, SAFE_FAKE_TASK_V1, PROJECT_WORKER_V1,
    )
}
