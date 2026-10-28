"""Public bootstrap serialization regressions; synthetic config only, no SSH."""
from copy import deepcopy

import pytest

from research_compute_network import member_ssh_bootstrap as bootstrap
from research_compute_network.models import MachineExecutionConfig

@pytest.mark.parametrize('missing', [set(), {'ssh_connect_timeout_s'}, {'ssh_status_timeout_s'},
                                    {'ssh_connect_timeout_s', 'ssh_status_timeout_s'}])
def test_bootstrap_accepts_optional_none_deadline_serialization_without_inventing_fields(missing):
    config = MachineExecutionConfig(machine_id='fixture-serialized').model_dump(mode='json')
    config.update(ssh_connect_timeout_s=None, ssh_status_timeout_s=None)
    for name in missing:
        config.pop(name)
    before = deepcopy(config)
    assert bootstrap._bootstrap_config_shape(config)
    assert config == before


@pytest.mark.parametrize('include', [False, True])
def test_bootstrap_accepts_only_neutral_retirement_serialization(include):
    config = MachineExecutionConfig(machine_id='fixture-serialized').model_dump(mode='json')
    assert 'scientific_model_retirement_enabled' not in config
    if include:
        config['scientific_model_retirement_enabled'] = False
    before = deepcopy(config)
    assert bootstrap._bootstrap_config_shape(config)
    assert config == before


@pytest.mark.parametrize('value', [True, 0, None, 'false'])
def test_bootstrap_cannot_enable_or_coerce_model_retirement(value):
    config = MachineExecutionConfig(machine_id='fixture-serialized').model_dump(mode='json')
    config['scientific_model_retirement_enabled'] = value
    assert not bootstrap._bootstrap_config_shape(config)


@pytest.mark.parametrize('change', ['required_missing', 'unknown', 'connect_nondefault', 'status_nondefault'])
def test_bootstrap_shape_never_accepts_missing_identity_or_new_timeout(change):
    config = MachineExecutionConfig(machine_id='fixture-serialized').model_dump(mode='json')
    if change == 'required_missing':
        config.pop('root_uuid')
    elif change == 'unknown':
        config['arbitrary_extension'] = None
    elif change == 'connect_nondefault':
        config['ssh_connect_timeout_s'] = 5
    else:
        config['ssh_status_timeout_s'] = 60
    assert not bootstrap._bootstrap_config_shape(config)
