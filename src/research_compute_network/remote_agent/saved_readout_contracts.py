"""Compatibility boundary; saved-solution research contracts are private."""
SAVED_READOUT_PROFILE_ID = "workbench-comsol-saved-readout-v1"
SAVED_READOUT_RECIPE_KIND = SAVED_READOUT_PROFILE_ID
SAVED_READOUT_DIAGNOSTIC = "unavailable"
PX1050_SAVED_READOUT_DIAGNOSTIC = "unavailable-secondary"
SAVED_READOUT_DIAGNOSTICS = frozenset()


def saved_readout_contract(diagnostic=None):
    raise ValueError("private_profile_not_available")


def saved_readout_source_contract(template_role, template_sha256):
    raise ValueError("private_profile_not_available")


def saved_readout_setup_fingerprint(payload):
    raise ValueError("private_profile_not_available")


def validate_saved_readout_items(*, solver_variant, items):
    raise ValueError("private_profile_not_available")


def validate_saved_readout_envelope(envelope, items):
    if envelope.execution_profile_id == SAVED_READOUT_PROFILE_ID:
        raise ValueError("private_profile_not_available")


def validate_saved_readout_runtime_envelope(job):
    raise ValueError("private_profile_not_available")
