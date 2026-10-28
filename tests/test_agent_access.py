from io import BytesIO
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from research_compute_network import agent_access
from research_compute_network.client import RcnClient
from research_compute_network.member_client import Login, MemberBroker
from test_member_client import Credentials
from test_member_submission_operations import package


class Broker:
    def __init__(self, root):
        self.root = root
        self.login = None
        self.closed = False
        self.calls = []
        self.receipt = {"operation_id": str(uuid4()), "phase": "planned", "job": {"status": "queued"}}
    def session(self, **kwargs):
        return {"center_url": "https://center.example", "online": False, "actor": {"actor_id": "person"}}
    def sign_in(self, payload):
        self.calls.append(("sign_in", payload))
        return self.session()
    def import_package(self, path):
        self.calls.append(("import", path))
        return {"package_id": "a" * 64, "operation_id": self.receipt["operation_id"]}
    def refresh(self, operation_id):
        self.calls.append(("refresh", operation_id))
        return self.receipt
    def plan(self, operation_id, options):
        self.calls.append(("plan", operation_id, options))
        return self.receipt
    def confirm(self, operation_id):
        self.calls.append(("confirm", operation_id))
    def start_transfer(self, operation_id, **kwargs):
        self.calls.append(("transfer", operation_id, kwargs))
    def close(self, **kwargs):
        self.closed = True
        self.calls.append(("close", kwargs))
    def read_operation(self, operation_id):
        assert self.closed
        return self.receipt
    def present(self, value):
        return value


def args(action, **updates):
    return SimpleNamespace(action=action, **updates)


def test_configure_reads_hidden_environment_not_token_argument(tmp_path, monkeypatch, capsys):
    broker = Broker(tmp_path)
    monkeypatch.setenv("PERSONAL_TOKEN_TEST", "synthetic-secret")
    agent_access.execute(args("configure", center_url="https://center.example", token_env="PERSONAL_TOKEN_TEST"), broker)
    assert broker.calls[0][1].token == "synthetic-secret"
    assert "synthetic-secret" not in capsys.readouterr().out
    with pytest.raises(SystemExit):
        agent_access.parser().parse_args(["configure", "--center-url", "https://center.example", "--token", "secret"])


def test_instruction_artifacts_are_agent_neutral_and_secret_free(tmp_path):
    broker = Broker(tmp_path)
    result = agent_access.instruction_artifacts(broker, tmp_path / "config")
    config = json.loads(Path(result["config"]).read_text(encoding="utf-8"))
    assert config["command_prefix"][1:4] == ["-B", "-m", agent_access.MODULE]
    assert config["token_argv_supported"] is False
    assert "token" not in {k for k in config if k != "token_argv_supported"}
    assert "same UUID" in Path(result["instructions"]).read_text(encoding="utf-8")


def test_plan_recovers_same_package_operation_unless_new_uuid_explicit(tmp_path):
    broker = Broker(tmp_path)
    options = args("plan", package=tmp_path / "data.zip", operation_id=None, unit_count=None,
                   estimated_seconds_per_item=None)
    agent_access.execute(options, broker)
    assert broker.calls[-1] == ("refresh", broker.receipt["operation_id"])
    options.operation_id = str(uuid4())
    agent_access.execute(options, broker)
    assert broker.calls[-1][0:2] == ("plan", options.operation_id)


@pytest.mark.parametrize("action, collect", [("submit", False), ("collect", True)])
def test_transfers_wait_for_original_operation_receipt(tmp_path, action, collect):
    broker = Broker(tmp_path)
    operation_id = broker.receipt["operation_id"]
    assert agent_access.execute(args(action, operation_id=operation_id), broker) == 0
    assert ("transfer", operation_id, {"collect": collect}) in broker.calls
    assert broker.closed
    assert ("close", {"cancel_active": False}) in broker.calls


def test_watch_returns_terminal_without_new_submission(tmp_path, capsys):
    broker = Broker(tmp_path)
    broker.receipt["job"]["status"] = "completed"
    assert agent_access.execute(args("watch", operation_id=broker.receipt["operation_id"], timeout_s=1, interval_s=1), broker) == 0
    assert [c[0] for c in broker.calls] == ["refresh"]
    assert json.loads(capsys.readouterr().out)["job"]["status"] == "completed"


def test_watch_cancelled_intent_waits_for_original_remote_confirmation(tmp_path, capsys, monkeypatch):
    broker = Broker(tmp_path)
    broker.receipt["job"] = {"status": "cancelled", "work_units": [
        {"attempts": [{"attempt_id": "original", "state": "cancel_pending"}]}]}
    moments = iter((0.0, 1.0))
    monkeypatch.setattr(agent_access.time, "monotonic", lambda: next(moments))
    assert agent_access.execute(args("watch", operation_id=broker.receipt["operation_id"],
                                    timeout_s=0.01, interval_s=0.01), broker) == 3
    observations = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert observations[-1]["resume_same_operation"]
    assert observations[0]["job"]["work_units"][0]["attempts"][0]["state"] == "cancel_pending"


@pytest.mark.parametrize("action", ["cancel", "diagnostics"])
def test_cancel_and_diagnostics_keep_original_operation_and_job(tmp_path, capsys, action):
    broker = Broker(tmp_path)
    broker.receipt["job_id"] = "original-job"
    requests = []
    api = SimpleNamespace(cancel=lambda job, **kwargs: requests.append(("cancel", job, kwargs)),
                          _request=lambda method, path: requests.append((method, path)) or {"blockers": []})
    broker.client = lambda: api
    operation_id = broker.receipt["operation_id"]
    assert agent_access.execute(args(action, operation_id=operation_id, reason="human cancelled"), broker) == 0
    assert all(call[0] == "refresh" for call in broker.calls)
    if action == "cancel":
        assert requests == [("cancel", "original-job", {"reason": "human cancelled"})]
    else:
        assert requests == [("GET", "/v1/jobs/original-job/placement-diagnostics")]
    assert json.loads(capsys.readouterr().out)


def test_pool_configuration_requires_both_owner_choices_and_preserves_machine_identity(tmp_path, capsys):
    broker = Broker(tmp_path)
    requests = []
    broker.client = lambda: SimpleNamespace(_request=lambda *args: requests.append(args) or {"free_idle_enabled": True})
    with pytest.raises(ValueError, match="both pool choices"):
        agent_access.execute(args("pool", machine_id="own-node", free_idle="on", mutual=None), broker)
    assert not requests
    agent_access.execute(args("pool", machine_id="own-node", free_idle="on", mutual="off"), broker)
    assert requests == [("PUT", "/v1/machines/own-node/compute-pool-consent",
                         {"free_idle_enabled": True, "mutual_enabled": False})]
    assert json.loads(capsys.readouterr().out)["free_idle_enabled"]


def test_broker_package_import_preserves_source_and_reuses_private_hash_copy(tmp_path):
    package(tmp_path)
    source = tmp_path / "request-user-a-demo-analysis-2.zip"
    before = source.read_bytes()
    class API:
        def __init__(self, *args, **kwargs):
            pass
        def current_actor(self):
            return {"actor_id": "user-a"}
    broker = MemberBroker(tmp_path / "member", credential_store=Credentials(), api_factory=API)
    try:
        broker.sign_in(Login(center_url="https://center.example", token="synthetic-token"))
        receipt = broker.import_package(source)
        assert broker.package_path(receipt["package_id"]).read_bytes() == before
        assert source.read_bytes() == before
        assert broker.import_package(source)["package_id"] == receipt["package_id"]
    finally:
        broker.close()


def test_custom_opener_carries_json_and_sse_without_global_urlopen(monkeypatch):
    class Opener:
        def __init__(self):
            self.requests = []
        def open(self, request, **kwargs):
            self.requests.append(request)
            return BytesIO(b'event: state\ndata: {"sequence": 1}\n\n' if request.full_url.endswith("stream") else b'{"ok":true}')
    opener = Opener()
    monkeypatch.setattr("research_compute_network.client.urlopen", lambda *a, **k: pytest.fail("ambient opener used"))
    client = RcnClient("https://center.example", token="synthetic-token", opener=opener)
    assert client._request("GET", "/v1/me") == {"ok": True}
    assert list(client.iter_events()) == [{"sequence": 1}]
    assert all(r.get_header("Authorization") == "Bearer synthetic-token" for r in opener.requests)
