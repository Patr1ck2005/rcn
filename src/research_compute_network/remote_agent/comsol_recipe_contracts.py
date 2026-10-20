"""Immutable, data-only contracts for the fixed COMSOL recipe runtime."""

from __future__ import annotations

from dataclasses import dataclass
import math
import re

# Keep the new validator lazy: historical sealed Study/Recipe scripts remain
# readable without importing a construction implementation they never use.
TEMPLATE_BUILD_PROFILE_ID = "workbench-comsol-template-build-v1"
TEMPLATE_BUILD_RECIPE_KIND = "comsol_template_build"

SAVED_READOUT_PROFILE_ID = "workbench-comsol-saved-readout-v1"
SAVED_READOUT_RECIPE_KIND = SAVED_READOUT_PROFILE_ID


@dataclass(frozen=True)
class FixedComsolRecipeContract:
    profile_id: str
    recipe_kind: str
    coordinate_names: tuple[str, ...]
    expression_profiles: frozenset[str]
    mesh_modes: frozenset[str]
    solver_variants: frozenset[str]
    output_schema: str
    template_selector: str = "project_named_role"
    field_export_policy: str = "metadata_only"


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_SCALAR = (str, int, float, bool)
_MESH_SIZES = frozenset({
    "extremely_fine", "extra_fine", "finer", "fine", "normal",
    "coarse", "coarser", "extra_coarse", "extremely_coarse",
})
_RECIPE_CONFIG_KEYS = {
    "comsol_eigenfrequency": frozenset({
        "neigs", "shift", "mesh_policy", "path_label",
    }),
    "comsol_frequency_response": frozenset({
        "component_tag", "geometry_tag", "study_tag", "dataset_tag",
        "m1_parameter", "m2_parameter", "frequency_parameter",
        "polarization", "physics_tag", "mesh_policy",
    }),
}
_LEGACY_RECIPE_CONFIG_KEYS = {
    "workbench-comsol-eigen-v2": frozenset({
        "neigs", "shift", "mesh", "mesh_tag", "path_label",
    }),
    "workbench-comsol-frequency-v1": frozenset({
        "component_tag", "geometry_tag", "mesh_tag", "study_tag",
        "dataset_tag", "m1_parameter", "m2_parameter",
        "frequency_parameter", "polarization", "physics_tag",
    }),
}
_ATOMIC_PAYLOAD_KEYS = frozenset({
    "kind", "project_id", "scan_spec", "scan_spec_sha256", "recipe_kind",
    "template_role", "expression_profile", "fixed_parameters",
    "recipe_config", "template_sha256", "capability_id",
})
GENERIC_STUDY_PROFILE_ID = "workbench-comsol-study-v1"
GENERIC_STUDY_PROFILE_V2_ID = "workbench-comsol-study-v2"
GENERIC_STUDY_PROFILE_IDS = frozenset({GENERIC_STUDY_PROFILE_ID, GENERIC_STUDY_PROFILE_V2_ID})
GENERIC_STUDY_RECIPE_KIND = "comsol_study"
GENERIC_STUDY_KINDS = frozenset({
    "eigenfrequency", "frequency_domain", "stationary", "time_dependent",
})
_GENERIC_PAYLOAD_KEYS = frozenset({
    "kind", "project_id", "scan_spec", "scan_spec_sha256", "template_role",
    "template_sha256", "study", "parameters", "setup_parameters",
    "sweep_parameters", "output_request", "output_contract_sha256",
    "template_inspection_sha256", "requested_eigen_solver",
    "effective_eigen_solver", "eigen_solver_source",
    "eigen_solver_inherited_fields",
})
_STUDY_KEYS = frozenset({
    "tag", "kind", "feature_tag", "solution_tag", "dataset_tag", "component_tag",
    "geometry_tag", "mesh_policy", "eigen_solver", "frequency_solver",
})
_STUDY_V2_KEYS = _STUDY_KEYS | {"port_excitation"}
_PORT_STATES = frozenset({
    "basis_1", "basis_2", "diag_plus", "diag_minus", "circ_plus", "circ_minus",
})
_OUTPUT_KEYS = frozenset({
    "schema_version", "semantic_outputs", "expressions", "fields",
    "solution_archive", "archive_granularity", "temporary_solution_retention", "readout_adapter_id",
})


FIXED_COMSOL_RECIPE_CONTRACTS = {
    profile_id: FixedComsolRecipeContract(
        profile_id=profile_id,
        recipe_kind=GENERIC_STUDY_RECIPE_KIND,
        coordinate_names=(), expression_profiles=frozenset(),
        mesh_modes=frozenset({"auto_size", "template_features"}),
        solver_variants=frozenset({"mumps", "cudss"}),
        output_schema="workbench-comsol-raw-study-v" + profile_id[-1],
        field_export_policy="request_defined",
    )
    for profile_id in GENERIC_STUDY_PROFILE_IDS
}


# Research-specific capabilities are registered only in private distributions.
RECIPE_CAPABILITIES = {}


def fixed_comsol_recipe_contract(profile_id: object) -> FixedComsolRecipeContract:
    try:
        return FIXED_COMSOL_RECIPE_CONTRACTS[str(profile_id)]
    except KeyError as exc:
        raise ValueError("execution Profile is not a registered COMSOL recipe") from exc


def recipe_capability(capability_id):
    raise ValueError("COMSOL recipe capability is not registered")


def _valid_id(value: object) -> bool:
    return bool(_ID.fullmatch(str(value or "")))


def _validate_mesh_policy(value: object) -> None:
    if not isinstance(value, dict) or set(value) - {"mode", "mesh_tag", "size"}:
        raise ValueError("generic COMSOL Study MeshPolicy is invalid")
    mode = value.get("mode")
    if mode not in {"auto_size", "template_features"} or not _valid_id(value.get("mesh_tag")):
        raise ValueError("generic COMSOL Study MeshPolicy is invalid")
    size = value.get("size")
    if mode == "auto_size" and size not in _MESH_SIZES:
        raise ValueError("generic COMSOL auto-size MeshPolicy requires a registered size")
    if mode == "template_features" and size is not None:
        raise ValueError("generic COMSOL template-feature MeshPolicy cannot set a size")


def _validate_eigen_solver(value: object) -> None:
    """Validate the optional, resolved eigen solver descriptor.

    The field remains optional for legacy Jobs.  When present it must be a
    concrete, bounded descriptor so an origin adapter can materialize a
    template-inherited value without turning the Study payload into an
    unvalidated extension bag.
    """
    if value is None:
        return
    if not isinstance(value, dict) or set(value) - {"shift", "neigs"}:
        raise ValueError("generic COMSOL eigen_solver is invalid")
    shift = value.get("shift")
    neigs = value.get("neigs")
    if shift is None and neigs is None:
        raise ValueError("generic COMSOL eigen_solver requires shift or neigs")
    if shift is not None and (not isinstance(shift, str) or not shift.strip()):
        raise ValueError("generic COMSOL eigen_solver shift must be a non-empty unit string")
    if neigs is not None and (
        isinstance(neigs, bool) or not isinstance(neigs, int) or neigs < 1
    ):
        raise ValueError("generic COMSOL eigen_solver neigs must be a positive integer")


def _validate_frequency_solver(value: object) -> None:
    """Validate a bounded direct Frequency-study range descriptor."""
    if value is None:
        return
    if not isinstance(value, dict):
        raise ValueError("generic COMSOL frequency_solver is invalid")
    has_range = set(value) == {"start", "stop", "step"}
    has_values = set(value) == {"values"}
    if not has_range and not has_values:
        raise ValueError("generic COMSOL frequency_solver is invalid")
    entries = value["values"] if has_values else [value[key] for key in ("start", "stop", "step")]
    if has_values and (not isinstance(entries, list) or not entries or len(entries) > 4096):
        raise ValueError("generic COMSOL frequency_solver values list is invalid")
    for item in entries:
        if not isinstance(item, str) or not item.strip() or len(item) > 128:
            raise ValueError("generic COMSOL frequency_solver values must be non-empty unit strings")
        if any(ord(character) < 32 for character in item):
            raise ValueError("generic COMSOL frequency_solver values contain control characters")


def _validate_port_excitation(value: object) -> None:
    keys = {"physics_tag", "active_port_tag", "inactive_port_tags", "input_power_w", "state"}
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("generic COMSOL port_excitation is invalid")
    if not _valid_id(value["physics_tag"]) or not _valid_id(value["active_port_tag"]):
        raise ValueError("generic COMSOL port_excitation tags are invalid")
    inactive = value["inactive_port_tags"]
    if (
        not isinstance(inactive, list)
        or not inactive
        or len(inactive) != len(set(inactive))
        or any(not _valid_id(tag) for tag in inactive)
        or value["active_port_tag"] in inactive
    ):
        raise ValueError("generic COMSOL inactive port tags are invalid")
    power = value["input_power_w"]
    if isinstance(power, bool) or not isinstance(power, (int, float)) or float(power) != 1.0:
        raise ValueError("generic COMSOL port input power must be exactly 1 W")
    if value["state"] not in _PORT_STATES:
        raise ValueError("generic COMSOL port polarization state is invalid")
    if value["physics_tag"] != "ewfd":
        raise ValueError("generic COMSOL port excitation requires the fixed ewfd physics")
    expected_inactive = {
        "port1": ["port2"],
        "port2": ["port1"],
    }
    if (
        value["active_port_tag"] not in expected_inactive
        or inactive != expected_inactive[value["active_port_tag"]]
    ):
        raise ValueError(
            "generic COMSOL port excitation requires exactly one of the fixed physical ports"
        )


def _validate_expression_text(value: object) -> None:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ValueError("COMSOL expression must be a non-empty string")
    if any(ord(character) < 32 for character in value):
        raise ValueError("COMSOL expression contains control characters")


def _validate_domain_output_entry(entry, *, schema_version, forbid_pml=False):
    allowed = {"name", "expression", "unit", "evaluation", "table_tag", "dataset_tag",
               "inner", "outer", "selection", "expression_semantics", "max_volume"}
    if schema_version != 2 or not isinstance(entry, dict) or set(entry) - allowed:
        raise ValueError("typed domain output requires schema2 and declared keys")
    if not _valid_id(entry.get("name")):
        raise ValueError("domain output name is invalid")
    _validate_expression_text(entry.get("expression"))
    for key in ("selection", "dataset_tag"):
        value = entry.get(key)
        if key == "selection" and value is None:
            raise ValueError("named volume selection is required")
        if value is not None and (not isinstance(value,str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*",value)):
            raise ValueError("domain selection/dataset must be a native tag")
    if entry.get("table_tag") is not None:
        raise ValueError("domain output cannot select a table")
    unit = entry.get("unit")
    if unit is not None and (not isinstance(unit,str) or len(unit)>128):
        raise ValueError("domain output unit is invalid")
    inner = entry.get("inner")
    if (not isinstance(inner,list) or not 1<=len(inner)<=4096
            or any(type(index) is not int or index<1 for index in inner)
            or len(set(inner)) != len(inner)):
        raise ValueError("domain output needs explicit strict inner coverage")
    outer = entry.get("outer")
    if outer is not None and (type(outer) is not int or outer<1):
        raise ValueError("domain outer must be a strict single positive index")
    if forbid_pml and "pml" in str(entry).lower():
        raise ValueError("frequency-domain spectrum must not request PML outputs")
    evaluation, semantics = entry.get("evaluation"), entry.get("expression_semantics","complex_scalar")
    if evaluation == "intvolume":
        if semantics not in {"real_scalar","complex_scalar"} or entry.get("max_volume") is not None:
            raise ValueError("IntVolume requires real_scalar or complex_scalar and no maximum settings")
    elif evaluation == "maxvolume":
        expected = dict(points="lagrange",refine=5,include_position=True,
                        obj="real",dataseries="none",normalization="none")
        actual=entry.get("max_volume")
        if (semantics != "real_intensity" or not isinstance(actual,dict) or actual != expected
                or any(type(actual[key]) is not type(value) for key,value in expected.items())):
            raise ValueError("MaxVolume requires real intensity and verified typed defaults")
    else:
        raise ValueError("unknown domain evaluation")


def _validate_output_request(value: object, *, forbid_pml: bool = False) -> None:
    if not isinstance(value, dict) or set(value) - _OUTPUT_KEYS:
        raise ValueError("generic COMSOL output request is invalid")
    if value.get("schema_version") not in {1, 2} or type(value.get("schema_version")) is not int:
        raise ValueError("generic COMSOL output request must use schema version 1 or 2")
    aliases = value.get("semantic_outputs", [])
    if not isinstance(aliases, list) or any(not _valid_id(alias) for alias in aliases):
        raise ValueError("generic COMSOL semantic output aliases are invalid")
    if forbid_pml and any("pml" in str(alias).lower() for alias in aliases):
        raise ValueError("frequency-domain spectrum must not request PML outputs")
    names: list[str] = []
    expressions = value.get("expressions", [])
    if not isinstance(expressions, list):
        raise ValueError("generic COMSOL expressions must be a list")
    for entry in expressions:
        if isinstance(entry, dict) and entry.get("evaluation") in {"intvolume", "maxvolume"}:
            _validate_domain_output_entry(entry, schema_version=value["schema_version"], forbid_pml=forbid_pml)
            names.append(str(entry["name"]))
            continue
        if not isinstance(entry, dict) or set(entry) - {
            "name", "expression", "unit", "evaluation", "table_tag", "dataset_tag",
            "inner", "outer",
        }:
            raise ValueError("generic COMSOL expression request is invalid")
        if not _valid_id(entry.get("name")):
            raise ValueError("generic COMSOL output name is invalid")
        _validate_expression_text(entry.get("expression"))
        if forbid_pml and any(
            "pml" in str(entry.get(key, "")).lower() for key in ("name", "expression")
        ):
            raise ValueError("frequency-domain spectrum must not request PML outputs")
        evaluation = entry.get("evaluation", "global")
        if evaluation not in {"global", "table"}:
            raise ValueError("generic COMSOL expression evaluation is invalid")
        if evaluation == "table" and not _valid_id(entry.get("table_tag")):
            raise ValueError("COMSOL table output requires a valid table tag")
        if evaluation == "global" and entry.get("table_tag") is not None:
            raise ValueError("COMSOL global output cannot select a table")
        if entry.get("dataset_tag") is not None and not _valid_id(entry["dataset_tag"]):
            raise ValueError("COMSOL expression dataset tag is invalid")
        _validate_solution_selectors(entry)
        names.append(str(entry["name"]))
    fields = value.get("fields", [])
    if not isinstance(fields, list):
        raise ValueError("generic COMSOL field requests must be a list")
    for entry in fields:
        if not isinstance(entry, dict) or set(entry) - {
            "name", "expressions", "dataset_tag", "selection", "grid", "inner", "outer",
        }:
            raise ValueError("generic COMSOL field request is invalid")
        if not _valid_id(entry.get("name")):
            raise ValueError("generic COMSOL field output name is invalid")
        requested = entry.get("expressions")
        if not isinstance(requested, list) or not requested or len(requested) > 128:
            raise ValueError("generic COMSOL field expressions are invalid")
        for expression in requested:
            _validate_expression_text(expression)
        if forbid_pml and "pml" in str(entry).lower():
            raise ValueError("frequency-domain spectrum must not request PML outputs")
        if entry.get("dataset_tag") is not None and not _valid_id(entry["dataset_tag"]):
            raise ValueError("COMSOL field dataset tag is invalid")
        if entry.get("selection") is not None and not _valid_id(entry["selection"]):
            raise ValueError("COMSOL field selection is invalid")
        _validate_solution_selectors(entry)
        grid = entry.get("grid", {"mode": "native", "axes": {}})
        if not isinstance(grid, dict) or set(grid) - {"mode", "axes", "coordinate_unit"}:
            raise ValueError("generic COMSOL field grid is invalid")
        mode, axes = grid.get("mode", "native"), grid.get("axes", {})
        if "coordinate_unit" in grid and mode != "regular":
            raise ValueError("coordinate units require the schema2 global regular route")
        if mode not in {"native", "regular"} or not isinstance(axes, dict):
            raise ValueError("generic COMSOL field grid is invalid")
        if mode == "native" and axes:
            raise ValueError("native COMSOL fields cannot define grid axes")
        if mode == "regular":
            if not 1 <= len(axes) <= 3:
                raise ValueError("regular COMSOL fields require one to three grid axes")
            for axis, points in axes.items():
                if axis not in {"x", "y", "z"} or not isinstance(points, list) or not points:
                    raise ValueError("regular COMSOL field grid axes are invalid")
                if any(
                    not isinstance(point, (int, float))
                    or isinstance(point, bool)
                    or not math.isfinite(point)
                    for point in points
                ):
                    raise ValueError("regular COMSOL field grid values must be numeric")
            if "coordinate_unit" in grid:
                if value["schema_version"] != 2 or mode != "regular" or set(axes) != {"x","y","z"}:
                    raise ValueError("unit-aware regular output requires schema2 and global xyz")
                if grid["coordinate_unit"] not in {"m","cm","mm","um","nm"}:
                    raise ValueError("invalid regular coordinate unit")
                inner=entry.get("inner")
                if not isinstance(inner,list) or not inner or len(set(inner))!=len(inner) or any(type(index) is not int or index<1 for index in inner):
                    raise ValueError("unit-aware field requires explicit inner coverage")
                if entry.get("outer") is not None and type(entry["outer"]) is not int:
                    raise ValueError("unit-aware outer selector must be single strict integer")
        names.append(str(entry["name"]))
    if len(names) != len(set(names)):
        raise ValueError("generic COMSOL output names must be unique")
    if value.get("readout_adapter_id") is not None:
        raise ValueError("generic COMSOL readout adapter is unregistered")
    if value.get("temporary_solution_retention") not in {None, "recovery"}:
        raise ValueError("generic COMSOL temporary solution retention is invalid")
    archive = value.get("solution_archive", "none")
    granularity = value.get("archive_granularity", "unit")
    if archive not in {"none", "structured", "mph", "both"}:
        raise ValueError("generic COMSOL solution archive mode is invalid")
    if granularity not in {"atom", "unit"}:
        raise ValueError("generic COMSOL archive granularity is invalid")
    if granularity == "atom" and archive == "none":
        raise ValueError("atom archive granularity requires an archive")
    if not aliases and not expressions and not fields and archive == "none" and value.get("readout_adapter_id") is None:
        raise ValueError("generic COMSOL output request is empty")


def _validate_solution_selectors(entry: dict) -> None:
    inner = entry.get("inner")
    if inner is not None:
        if isinstance(inner, str) and inner not in {"first", "last"}:
            raise ValueError("COMSOL inner solution selector is invalid")
        if isinstance(inner, list) and (
            not inner
            or any(not isinstance(value, int) or isinstance(value, bool) or value < 1 for value in inner)
        ):
            raise ValueError("COMSOL inner solution selector is invalid")
        if not isinstance(inner, (str, list)):
            raise ValueError("COMSOL inner solution selector is invalid")
    outer = entry.get("outer")
    values = [outer] if isinstance(outer, int) and not isinstance(outer, bool) else outer
    if values is not None and (
        not isinstance(values, list)
        or not values
        or any(not isinstance(value, int) or isinstance(value, bool) or value < 1 for value in values)
    ):
        raise ValueError("COMSOL outer solution selector is invalid")


def validate_generic_study_items(
    *, profile_id: str = GENERIC_STUDY_PROFILE_ID, solver_variant: object, items: object,
) -> FixedComsolRecipeContract:
    """Validate the declarative Study contract without restricting scientific parameters."""
    contract = FIXED_COMSOL_RECIPE_CONTRACTS[profile_id]
    if solver_variant not in contract.solver_variants:
        raise ValueError("COMSOL solver is not registered for the generic Study Profile")
    if not isinstance(items, list) or not items:
        raise ValueError("generic COMSOL Study job requires atomic items")
    setup_fingerprints: set[str] = set()
    output_fingerprints: set[str] = set()
    study_descriptor: dict | None = None
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("generic COMSOL Study atomic item is invalid")
        payload = item.get("payload")
        coordinates = item.get("coordinates")
        if not isinstance(coordinates, dict) or any(
            not isinstance(value, _SCALAR) or value is None for value in coordinates.values()
        ):
            raise ValueError("generic COMSOL coordinates must be scalar metadata")
        if not isinstance(payload, dict) or set(payload) - _GENERIC_PAYLOAD_KEYS:
            raise ValueError("generic COMSOL Study payload contains unsupported fields")
        if payload.get("kind") != "workbench_comsol_study_point":
            raise ValueError("generic COMSOL Study payload kind is invalid")
        if not _valid_id(payload.get("template_role")):
            raise ValueError("generic COMSOL template role is invalid")
        for hash_key in (
            "scan_spec_sha256", "template_sha256", "output_contract_sha256",
            "template_inspection_sha256",
        ):
            if not re.fullmatch(r"[0-9a-f]{64}", str(payload.get(hash_key, ""))):
                raise ValueError(f"generic COMSOL {hash_key} is invalid")
        study = payload.get("study")
        allowed_study_keys = _STUDY_V2_KEYS if profile_id == GENERIC_STUDY_PROFILE_V2_ID else _STUDY_KEYS
        if not isinstance(study, dict) or set(study) - allowed_study_keys:
            raise ValueError("generic COMSOL Study descriptor is invalid")
        if study.get("kind") not in GENERIC_STUDY_KINDS or not _valid_id(study.get("tag")):
            raise ValueError("generic COMSOL Study kind or tag is invalid")
        for tag_key in (
            "feature_tag", "solution_tag", "dataset_tag", "component_tag", "geometry_tag",
        ):
            if study.get(tag_key) is not None and not _valid_id(study[tag_key]):
                raise ValueError(f"generic COMSOL {tag_key} is invalid")
        _validate_mesh_policy(study.get("mesh_policy"))
        if study.get("kind") == "frequency_domain":
            _validate_frequency_solver(study.get("frequency_solver"))
            if (
                profile_id == GENERIC_STUDY_PROFILE_ID
                and isinstance(study.get("frequency_solver"), dict)
                and "values" in study["frequency_solver"]
            ):
                raise ValueError("generic COMSOL Study v1 cannot receive sparse frequency values")
        elif study.get("frequency_solver") is not None:
            raise ValueError("generic COMSOL frequency_solver is only valid for frequency_domain")
        port_excitation = study.get("port_excitation")
        if profile_id == GENERIC_STUDY_PROFILE_V2_ID:
            if port_excitation is not None:
                if study.get("kind") != "frequency_domain":
                    raise ValueError("generic COMSOL port_excitation is only valid for frequency_domain")
                _validate_port_excitation(port_excitation)
        elif port_excitation is not None:
            raise ValueError("generic COMSOL Study v1 cannot receive port_excitation")
        if study.get("kind") == "eigenfrequency":
            _validate_eigen_solver(study.get("eigen_solver"))
            for key in ("requested_eigen_solver", "effective_eigen_solver"):
                if payload.get(key) is not None:
                    _validate_eigen_solver(payload[key])
            source = payload.get("eigen_solver_source")
            if source is not None and source not in {"explicit", "template-inherited", "mixed"}:
                raise ValueError("generic COMSOL eigen_solver source is invalid")
            inherited_fields = payload.get("eigen_solver_inherited_fields", [])
            if not isinstance(inherited_fields, list) or any(
                field not in {"shift", "neigs"} for field in inherited_fields
            ):
                raise ValueError("generic COMSOL inherited eigen_solver fields are invalid")
        if study_descriptor is None:
            study_descriptor = study
        elif study != study_descriptor:
            raise ValueError("generic COMSOL WorkUnit cannot mix Study descriptors")
        parameters = payload.get("parameters")
        setup = payload.get("setup_parameters")
        sweep = payload.get("sweep_parameters")
        if not all(isinstance(value, dict) for value in (parameters, setup, sweep)):
            raise ValueError("generic COMSOL parameters must be mappings")
        if set(setup) & set(sweep) or set(parameters) != set(setup) | set(sweep):
            raise ValueError("generic COMSOL setup and sweep parameters must partition all parameters")
        if any(not _valid_id(name) or not isinstance(value, _SCALAR) or value is None for name, value in parameters.items()):
            raise ValueError("generic COMSOL parameters must be named scalar values")
        _validate_output_request(
            payload.get("output_request"),
            forbid_pml=study.get("kind") == "frequency_domain",
        )
        setup_fingerprint = str(item.get("setup_fingerprint", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", setup_fingerprint):
            raise ValueError("generic COMSOL setup fingerprint is invalid")
        setup_fingerprints.add(setup_fingerprint)
        output_fingerprints.add(str(payload.get("output_contract_sha256")))
    if len(setup_fingerprints) != 1:
        raise ValueError("generic COMSOL WorkUnit cannot mix setup fingerprints")
    if len(output_fingerprints) != 1:
        raise ValueError("generic COMSOL WorkUnit cannot mix output contracts")
    return contract


def validate_fixed_recipe_items(*, profile_id, recipe_kind, solver_variant, items):
    """Only generic data-only Study requests are registered publicly."""
    fixed_comsol_recipe_contract(profile_id)
    if recipe_kind != GENERIC_STUDY_RECIPE_KIND:
        raise ValueError("generic COMSOL Study recipe does not match its Profile")
    return validate_generic_study_items(profile_id=str(profile_id),
        solver_variant=solver_variant, items=items)
