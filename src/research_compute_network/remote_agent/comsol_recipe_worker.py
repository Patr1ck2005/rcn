"""Fixed COMSOL recipe dispatcher for Workbench Campaign WorkUnits."""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from pathlib import Path

# The embeddable worker Python uses a locked ``python311._pth`` file and can
# ignore PYTHONPATH.  Make this sealed sibling directory explicit before the
# recipe contracts are imported.
_REMOTE_AGENT_DIR = str(Path(__file__).resolve().parent)
if _REMOTE_AGENT_DIR not in sys.path:
    sys.path.insert(0, _REMOTE_AGENT_DIR)

try:
    from .comsol_recipe_contracts import (
        fixed_comsol_recipe_contract,
        validate_fixed_recipe_items,
    )
except ImportError:  # Executed as a sealed standalone remote-agent script.
    try:
        from comsol_recipe_contracts import (
            fixed_comsol_recipe_contract,
            validate_fixed_recipe_items,
        )
    except ImportError as exc:
        raise RuntimeError(
            "sealed COMSOL runtime is incomplete: comsol_recipe_contracts.py is missing"
        ) from exc


def _load_job(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") != 2:
        raise ValueError("COMSOL recipe job must use schema version 2")
    items = value.get("items")
    validate_fixed_recipe_items(
        profile_id=value.get("profile_id"),
        recipe_kind=value.get("recipe_kind"),
        solver_variant=value.get("solver_variant", "mumps"),
        items=items,
    )
    if value.get("profile_id") == "workbench-comsol-saved-readout-v1":
        try:
            from .saved_readout_contracts import validate_saved_readout_runtime_envelope
        except ImportError:
            from saved_readout_contracts import validate_saved_readout_runtime_envelope
        validate_saved_readout_runtime_envelope(value)
    if value.get("profile_id") == "workbench-comsol-template-build-v1":
        try:
            from .template_build_contracts import validate_template_build_runtime_envelope
        except ImportError:
            from template_build_contracts import validate_template_build_runtime_envelope
        validate_template_build_runtime_envelope(value)
    setups = {item.get("setup_fingerprint") for item in items if isinstance(item, dict)}
    if None in setups or len(setups) != 1 or len(setups) != len({item.get("setup_fingerprint") for item in items}):
        raise ValueError("COMSOL recipe WorkUnit must contain one valid setup fingerprint")
    ordinals = [item.get("ordinal") for item in items]
    if not all(isinstance(value, int) and not isinstance(value, bool) for value in ordinals):
        raise ValueError("COMSOL recipe atomic ordinals are invalid")
    if ordinals != sorted(ordinals) or len(ordinals) != len(set(ordinals)):
        raise ValueError("COMSOL recipe atomic ordinals must be unique and ordered")
    # Bundles produced by 0.12.3 always carry frozen Network resources.  Keep
    # accepted pre-0.12.3 recipe jobs readable so an already persisted unit can
    # finish; the core binding is applied only when that evidence is present.
    resolved = value.get("resolved_resources")
    if resolved is not None:
        resources = resolved.get("resources") if isinstance(resolved, dict) else None
        cpus = resources.get("cpus") if isinstance(resources, dict) else None
        if not isinstance(cpus, int) or isinstance(cpus, bool) or cpus < 1:
            raise ValueError("COMSOL recipe job requires a positive resolved CPU count")
    return value


def _enforce_resolved_cores(job: dict) -> int:
    """Bind legacy Workbench workers to Network's sealed CPU decision."""

    resolved = job.get("resolved_resources")
    if not isinstance(resolved, dict):
        return 0
    resources = resolved.get("resources")
    cpus = resources.get("cpus") if isinstance(resources, dict) else None
    if not isinstance(cpus, int) or isinstance(cpus, bool) or cpus < 1:
        raise ValueError("COMSOL recipe job requires a positive resolved CPU count")
    from research_agent_workbench.backends.comsol_mph.client import ComsolClient

    original_start = ComsolClient.start

    @classmethod
    def controlled_start(cls, version="6.3", cores=None):
        if cores is not None and int(cores) != cpus:
            raise ValueError("Workbench COMSOL core request differs from sealed Network resources")
        return original_start(version=version, cores=cpus)

    ComsolClient.start = controlled_start
    return cpus


_DIRECT_JONES_STATES = frozenset({
    "basis_1", "basis_2", "diag_plus", "diag_minus", "circ_plus", "circ_minus",
})
_DIRECT_JONES_PORTS = {
    "port1": ("above_n", "-1", "port2"),
    "port2": ("substrate_n", "1", "port1"),
}


def _scale_jones(vector: tuple[str, str, str], coefficient: str) -> tuple[str, str, str]:
    return tuple(f"({coefficient})*({value})" for value in vector)  # type: ignore[return-value]


def _add_jones(
    left: tuple[str, str, str], right: tuple[str, str, str],
) -> tuple[str, str, str]:
    return tuple(f"({a})+({b})" for a, b in zip(left, right))  # type: ignore[return-value]


def _direct_jones_vectors(active_port_tag: str) -> dict[str, tuple[str, str, str]]:
    """Return the registered P/S mapping; no payload expression enters here."""

    try:
        refractive_index, direction, _ = _DIRECT_JONES_PORTS[active_port_tag]
    except KeyError as exc:
        raise ValueError("direct Jones excitation requires port1 or port2") from exc
    q = "sqrt(kx^2+ky^2)"
    k = f"({refractive_index}*ewfd.k0)"
    kz = f"sqrt(({k})^2-kx^2-ky^2)"
    nonzero = f"({q}>1e-9[1/m])"
    # COMSOL convention: p cross s points along the incident wave vector.
    # At Gamma the port's fixed t1/t2 gauge is retained in the result receipt.
    p = (
        f"if({nonzero},{direction}*kx*({kz})/(({q})*({k})),t1x)",
        f"if({nonzero},{direction}*ky*({kz})/(({q})*({k})),t1y)",
        f"if({nonzero},-({q})/({k}),t1z)",
    )
    s = (
        f"if({nonzero},-ky/({q}),t2x)",
        f"if({nonzero},kx/({q}),t2y)",
        f"if({nonzero},0,t2z)",
    )
    inv_sqrt2 = "1/sqrt(2)"
    return {
        "basis_1": p,
        "basis_2": s,
        "diag_plus": _scale_jones(_add_jones(p, s), inv_sqrt2),
        "diag_minus": _scale_jones(_add_jones(p, _scale_jones(s, "-1")), inv_sqrt2),
        "circ_plus": _scale_jones(_add_jones(p, _scale_jones(s, "i")), inv_sqrt2),
        "circ_minus": _scale_jones(_add_jones(p, _scale_jones(s, "-i")), inv_sqrt2),
    }


def _apply_direct_jones_port_excitation(java, study_descriptor: dict) -> dict:
    """Apply one closed-enum direct Jones state and verify complete readback."""

    declared = study_descriptor.get("port_excitation") or {}
    if not declared:
        return {}
    active_tag = declared.get("active_port_tag")
    state = declared.get("state")
    if declared.get("physics_tag") != "ewfd" or active_tag not in _DIRECT_JONES_PORTS:
        raise ValueError("direct Jones excitation is restricted to ewfd port1/port2")
    _, _, inactive_tag = _DIRECT_JONES_PORTS[active_tag]
    if declared.get("inactive_port_tags") != [inactive_tag]:
        raise ValueError("direct Jones excitation requires the opposite physical port to be inactive")
    if declared.get("input_power_w") != 1.0 or state not in _DIRECT_JONES_STATES:
        raise ValueError("direct Jones excitation received an invalid power or state")

    component_tag = study_descriptor.get("component_tag", "comp1")
    physics = java.component(component_tag).physics("ewfd")
    actual_port_tags: set[str] = set()
    for tag_obj in physics.feature().tags():
        tag = str(tag_obj)
        if str(physics.feature(tag).getType()).lower() == "port":
            actual_port_tags.add(tag)
    if actual_port_tags != set(_DIRECT_JONES_PORTS):
        raise ValueError(
            "direct Jones template must expose exactly the two fixed physical ports"
        )

    for tag in sorted(actual_port_tags):
        port = physics.feature(tag)
        port.set("PortExcitation", "on" if tag == active_tag else "off")
        try:
            for child_tag_obj in port.feature().tags():
                child = port.feature(str(child_tag_obj))
                if str(child.getType()).lower() == "orthogonalpolarization":
                    child.set("PortExcitation", "off")
        except Exception:
            pass

    import jpype

    active = physics.feature(active_tag)
    vector = _direct_jones_vectors(active_tag)[state]
    java_vector = jpype.JArray(jpype.JString)(list(vector))
    active.set("Pin", "1[W]")
    active.set("Polarization", "UserDefined")
    active.set("InputType", "E")
    active.set("E0", java_vector)
    active.set("Eampl", jpype.JArray(jpype.JString)(list(vector)))
    e0_readback = [str(value) for value in active.getStringArray("E0")]
    amplitude_readback = [str(value) for value in active.getStringArray("Eampl")]
    if e0_readback != list(vector) or amplitude_readback != list(vector):
        raise RuntimeError("direct Jones three-component E0/Eampl readback mismatch")
    if str(active.getString("PortExcitation")) != "on":
        raise RuntimeError("direct Jones active physical port did not read back as on")
    if str(active.getString("Pin")).replace(" ", "") not in {"1[W]", "1.0[W]"}:
        raise RuntimeError("direct Jones input power did not read back as 1 W")
    if str(active.getString("Polarization")) != "UserDefined":
        raise RuntimeError("direct Jones polarization did not read back as UserDefined")
    if str(active.getString("InputType")) != "E":
        raise RuntimeError("direct Jones input type did not read back as E")
    return {
        "physics_tag": "ewfd",
        "active_port_tag": active_tag,
        "inactive_port_tags": [inactive_tag],
        "input_power_w": 1.0,
        "state": state,
        "basis_gauge": "port_t1_t2_at_gamma",
        "effective_properties": {
            "PortExcitation": "on",
            "Pin": str(active.getString("Pin")),
            "Polarization": "UserDefined",
            "InputType": "E",
            "E0": e0_readback,
            "Eampl": amplitude_readback,
        },
    }


def _validated_output(job: dict) -> Path:
    output_root = (Path.cwd() / "output").resolve()
    output = Path(job["output_path"]).resolve()
    output.relative_to(output_root)
    return output


def _write_json_atomic(path: Path, payload: dict, *, timeout_s: float = 15.0) -> None:
    """Publish worker metadata despite transient Windows reader locks."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(
        "%s.tmp-%s-%s-%s"
        % (path.name, os.getpid(), threading.get_ident(), time.time_ns())
    )
    try:
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                os.replace(temporary, path)
                return
            except OSError as exc:
                if (
                    getattr(exc, "winerror", None) not in {5, 32}
                    or time.monotonic() >= deadline
                ):
                    raise
                time.sleep(0.25)
    finally:
        temporary.unlink(missing_ok=True)


def _eigen_job(job: dict) -> dict:
    items = job["items"]
    payloads = [item["payload"] for item in items]
    coordinates = [item["coordinates"] for item in items]
    if any(payload.get("recipe_kind") != "comsol_eigenfrequency" for payload in payloads):
        raise ValueError("Eigen Profile received a non-eigen atomic item")
    setup = payloads[0]
    fixed = setup.get("fixed_parameters")
    recipe = setup.get("recipe_config")
    expression_profile = setup.get("expression_profile")
    if not isinstance(fixed, dict) or not isinstance(recipe, dict):
        raise ValueError("Eigen atomic item lacks fixed parameters or recipe configuration")
    contract = fixed_comsol_recipe_contract(job.get("profile_id"))
    if expression_profile not in contract.expression_profiles:
        raise ValueError("Eigen atomic item uses an unregistered expression profile")
    if any(
        payload.get("fixed_parameters") != fixed
        or payload.get("recipe_config") != recipe
        or payload.get("expression_profile") != expression_profile
        for payload in payloads
    ):
        raise ValueError("Eigen WorkUnit changed setup inside one Unit")
    try:
        m1 = [float(point["m1"]) for point in coordinates]
        m2 = [float(point["m2"]) for point in coordinates]
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Eigen recipe coordinates require numeric m1 and m2") from exc
    output = _validated_output(job)
    return {
        "template_path": job["template_path"],
        "comsol_version": job.get("comsol_version", "6.4"),
        "mesh_tag": recipe.get("mesh_tag", "mesh1"),
        # v3/v4 adopt the structured geometry/mesh lifecycle.  v2 is an
        # immutable historical Profile and must retain its original runner
        # behavior even when a newer Workbench parser can read its Spec.
        "mesh_policy": (
            recipe.get("mesh_policy")
            if job.get("profile_id") in {
                "workbench-comsol-eigen-v3",
                "workbench-comsol-eigen-v4",
            }
            else None
        ),
        "m1": m1,
        "m2": m2,
        "k_indices": [int(item["ordinal"]) for item in items],
        "chunk_start": int(items[0]["ordinal"]),
        "chunk_index": int(items[0]["ordinal"]),
        "neigs": int(recipe.get("neigs", 21)),
        "shift": recipe.get("shift"),
        "mesh": recipe.get("mesh", "fine"),
        "path_label": recipe.get("path_label", "campaign"),
        "expression_profile": expression_profile,
        "execution_profile_id": job.get("profile_id"),
        "attempt_id": job.get("attempt_id"),
        "run_id": job.get("campaign_id") or "",
        "param_overrides": fixed,
        "solver_variant": job.get("solver_variant", "mumps"),
        "progress_path": job["progress_path"],
        "out_csv": str(output.with_suffix(".csv")),
        "out_manifest": str(output.with_name(output.stem + "_manifest.json")),
    }


def run_job(job_path: Path) -> Path:
    job = _load_job(job_path)
    _enforce_resolved_cores(job)
    output = _validated_output(job)
    output.parent.mkdir(parents=True, exist_ok=True)
    if job["recipe_kind"] == "workbench-comsol-saved-readout-v1":
        from research_agent_workbench.runtime.saved_readout_worker import run_saved_readout_job

        result = Path(run_saved_readout_job(job)).resolve()
        if result != output or not result.is_file():
            raise RuntimeError("saved readout did not publish its managed result")
        return result
    if job["recipe_kind"] == "comsol_template_build":
        from research_agent_workbench.runtime.template_build_worker import run_template_build_job

        result = Path(run_template_build_job(job)).resolve()
        if result != output or not result.is_file():
            raise RuntimeError("template construction did not publish its managed result")
        return result
    if job["recipe_kind"] == "comsol_study":
        from research_agent_workbench.backends.comsol_mph import generic_study_worker

        generic_study_worker._write_json_atomic = _write_json_atomic
        if job.get("profile_id") == "workbench-comsol-study-v2":
            generic_study_worker._apply_port_excitation = _apply_direct_jones_port_excitation
        return generic_study_worker.run_generic_study(job)
    if job["recipe_kind"] == "comsol_eigenfrequency":
        from research_agent_workbench.backends.comsol_mph import batch_worker

        batch_worker._write_progress = _write_json_atomic
        csv_path, manifest_path = batch_worker.run_chunk(_eigen_job(job))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        result = {
            "schema_version": 1,
            "recipe_kind": job["recipe_kind"],
            "campaign_id": job.get("campaign_id"),
            "campaign_task_id": job.get("campaign_task_id"),
            "source_spec_sha256": job.get("source_spec_sha256"),
            "setup_fingerprint": job["items"][0]["setup_fingerprint"],
            "items": [
                {
                    "item_id": item["item_id"],
                    "ordinal": item["ordinal"],
                    "coordinates": item["coordinates"],
                    "actual_solver": point["solver_variant"],
                    "duration_s": point.get("duration_s"),
                }
                for item, point in zip(job["items"], manifest["point_solver_variants"], strict=True)
            ],
            "outputs": [csv_path.name, manifest_path.name],
        }
        _write_json_atomic(output, result)
        return output
    from research_agent_workbench.backends.comsol_mph import frequency_worker

    frequency_worker._write_json_atomic = _write_json_atomic
    return frequency_worker.run_frequency_recipe(job)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--job", required=True)
    args = parser.parse_args(argv)
    output = run_job(Path(args.job))
    print(json.dumps({"result": str(output)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
