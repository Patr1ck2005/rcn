"""Origin-owned scientific probes are supplied independently of the platform."""
from .member_release_catalog import RuntimeNotConfigured


class NumericalProbeRunner:
    def __init__(self, harness):
        self.harness = harness
        self.service = harness.service

    def run_gamma_local(self, *, actor_id, timeout_s=1800):
        raise RuntimeNotConfigured()
