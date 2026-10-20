"""Compatibility boundary for research-owned construction profiles.

The public platform ships no reviewed project construction presets.
"""
TEMPLATE_BUILD_PROFILE_ID = "workbench-comsol-template-build-v1"
TEMPLATE_BUILD_RECIPE_KIND = "comsol_template_build"
TEMPLATE_BUILD_PRESETS = frozenset()
TEMPLATE_BUILD_MESH_POLICY = {"mode": "template_features", "mesh_tag": "mesh1"}


def template_build_preset_contract(preset):
    raise ValueError("private_profile_not_available")


def template_build_setup_fingerprint(payload):
    raise ValueError("private_profile_not_available")


def validate_template_build_items(*, solver_variant, items):
    raise ValueError("private_profile_not_available")


def validate_template_build_envelope(envelope, items):
    if envelope.execution_profile_id == TEMPLATE_BUILD_PROFILE_ID:
        raise ValueError("private_profile_not_available")


def validate_template_build_runtime_envelope(job):
    raise ValueError("private_profile_not_available")
