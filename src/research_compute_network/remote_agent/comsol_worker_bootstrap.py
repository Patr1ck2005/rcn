"""Fixed COMSOL entrypoint with process-local storage routing (no science edits)."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import runpy
import subprocess
import sys

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

try:
    from .worker_storage import validated_worker_scratch, await_worker_start
    from .comsol_recipe_contracts import FIXED_COMSOL_RECIPE_CONTRACTS
except ImportError:
    from worker_storage import validated_worker_scratch, await_worker_start
    from comsol_recipe_contracts import FIXED_COMSOL_RECIPE_CONTRACTS


def bind_comsol_storage(scratch):
    """MPh's convenience start omits the public Server.arguments parameter.

    Adapt its local Server factory and Windows process launch; leave version,
    cores, solver, prefs, template and model settings unchanged. Unsupported
    session modes fail shut.
    """
    import mph
    import mph.server
    import mph.session
    import jpype

    if mph.option("session") != "client-server":
        raise RuntimeError("managed COMSOL scratch requires the client-server session")
    if mph.session.client is not None or mph.session.server is not None:
        raise RuntimeError("COMSOL storage must be bound before session startup")
    if sys.platform == "win32":
        original_start = mph.server.start

        def managed_start(*args, **kwargs):
            kwargs["creationflags"] = kwargs.get("creationflags", 0) | subprocess.CREATE_NO_WINDOW
            return original_start(*args, **kwargs)

        # MPh aliases Popen in its server module; keep this worker-local.
        mph.server.start = managed_start
    original = mph.session.Server
    original_jvm = jpype.startJVM
    original_client = mph.session.Client
    storage_flags = {"-tmpdir": "comsol-temp", "-recoverydir": "recovery",
                     "-configuration": "configuration", "-data": "data"}

    def managed_server(*args, **kwargs):
        if len(args) > 5 or kwargs.get("arguments"):
            raise ValueError("COMSOL storage arguments must be supervisor-controlled")
        kwargs["arguments"] = [value for flag, name in storage_flags.items()
                               for value in (flag, str(scratch / name))]
        return original(*args, **kwargs)

    def managed_jvm(*args, **kwargs):
        if any(str(arg).startswith("-Djava.io.tmpdir=") for arg in args):
            raise ValueError("COMSOL client temporary directory must be supervisor-controlled")
        return original_jvm(*args, "-Djava.io.tmpdir=" + str(scratch / "temp"), **kwargs)

    def managed_client(*args, **kwargs):
        client = original_client(*args, **kwargs)
        actual = str(jpype.JClass("java.lang.System").getProperty("java.io.tmpdir"))
        if Path(actual).resolve() != (scratch / "temp").resolve():
            raise RuntimeError("COMSOL client JVM did not accept managed temporary storage")
        # Keep positive routing evidence beside results, with no user paths.
        (scratch.parent / "storage-routing.json").write_text(json.dumps({
            "schema_version": 1, "server_storage_flags": sorted(storage_flags),
            "client_java_temp_managed": True, "preferences_redirected": False,
        }, sort_keys=True), encoding="utf-8")
        return client

    mph.session.Server = managed_server
    mph.session.Client = managed_client
    jpype.startJVM = managed_jvm


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--job", required=True)
    args = parser.parse_args(argv)
    job_path = Path(args.job)
    job = json.loads(job_path.read_text(encoding="utf-8"))
    # Historical scan job.json has no profile field. Its sealed request does;
    # never infer an allowlisted command merely from a missing input field.
    request = json.loads((job_path.parent.parent / "request.json").read_text(encoding="utf-8"))
    profile = request.get("profile_id")
    if profile not in FIXED_COMSOL_RECIPE_CONTRACTS and profile != "workbench-comsol-scan-v1":
        raise ValueError("COMSOL bootstrap profile is not allowlisted")
    if job.get("profile_id", profile) != profile or (
        profile in FIXED_COMSOL_RECIPE_CONTRACTS and job.get("profile_id") != profile
    ):
        raise ValueError("COMSOL bootstrap profile differs from sealed request")
    scratch = validated_worker_scratch(job_path)
    await_worker_start(job_path)
    bind_comsol_storage(scratch)
    if profile in FIXED_COMSOL_RECIPE_CONTRACTS:
        try:
            from .comsol_recipe_worker import main as recipe_main
        except ImportError:
            from comsol_recipe_worker import main as recipe_main
        return recipe_main(["--job", str(job_path)])
    sys.argv = ["batch_worker", "--job", str(job_path)]
    runpy.run_module("research_agent_workbench.backends.comsol_mph.batch_worker", run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
