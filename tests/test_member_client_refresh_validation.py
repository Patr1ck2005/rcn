"""Fresh per-request connection checks without duplicate session inspection."""
from contextlib import contextmanager
import json
from pathlib import Path

import pytest

from research_compute_network import member_client as client
from research_compute_network import member_client_connection as connection
from research_compute_network.client import RcnApiError
from test_member_client_connection import fake_processes, local_metadata


class Credentials:
    def __init__(self, reference):
        self.value = {"center_url": reference, "token": "synthetic-personal-token",
                      "actor": {"actor_id": "original-person"}}

    def load(self):
        return self.value


def configured_broker(local_metadata, monkeypatch, *, native=False, status=None, startup=False):
    root, spec, save = local_metadata
    if not startup:
        spec["legacy"]["startup"] = None
    reference = save()
    clients = []

    def actor_result(api):
        if status is not None:
            raise RcnApiError(status, "synthetic center failure")
        return {"actor_id": "original-person"}

    if native:
        original_init = client.RcnClient.__init__

        def init(api, *args, **kwargs):
            original_init(api, *args, **kwargs)
            clients.append(api)

        monkeypatch.setattr(client.RcnClient, "__init__", init)
        monkeypatch.setattr(client.RcnClient, "current_actor", actor_result)
        factory = client.member_api_client
    else:
        # The injected API need not permit attaching a cached descriptor.
        class API:
            __slots__ = ()

            def __init__(self, url, token):
                assert url == "http://127.0.0.1:28765"
                assert token == "synthetic-personal-token"
                clients.append(self)

            current_actor = actor_result
        factory = API
    broker = client.MemberBroker(root, credential_store=Credentials(reference), api_factory=factory)
    return broker, reference, clients


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize("startup", [False, True])
def test_refresh_checks_every_request_once_without_independent_public_lookup(
        local_metadata, fake_processes, monkeypatch, native, startup):
    broker, reference, clients = configured_broker(local_metadata, monkeypatch, native=native, startup=startup)
    try:
        assert broker.session(refresh=True)["online"]
        checks = []
        private_directory = connection.storage._private_directory
        private_file = connection.storage._check_private_file

        def directory(path, **kwargs):
            checks.append(("directory", Path(path)))
            return private_directory(path, **kwargs)

        def file(path):
            if Path(path).exists():
                checks.append(("file", Path(path)))
            return private_file(path)

        monkeypatch.setattr(connection.storage, "_private_directory", directory)
        monkeypatch.setattr(connection.storage, "_check_private_file", file)
        monkeypatch.setattr(connection, "public_connection", lambda *a: pytest.fail("duplicate public lookup"))
        for _ in range(2):
            checks.clear()
            value = broker.session(refresh=True)
            assert value["configured_connection"] == {"mode": "managed-ssh", "center_reference": reference}
            assert value["online"] and value["remote_actions_available"]
            assert len(checks) == (15 if startup else 13)
            key = Path(local_metadata[1]["ssh"]["identity"]["path"])
            assert checks.count(("file", key)) == 1
        assert len(clients) == 3 and len({id(api) for api in clients}) == 3
        assert len(fake_processes[3]) == 1 and fake_processes[2] == []
    finally:
        broker.close()


@pytest.mark.parametrize("failure", ["malformed-json", "invalid-spec", "permission-error"])
def test_invalid_local_metadata_is_reported_offline_without_exposing_details(
        local_metadata, fake_processes, monkeypatch, failure):
    broker, reference, clients = configured_broker(local_metadata, monkeypatch)
    root, spec, _ = local_metadata
    path = root / connection.SPEC_NAME
    original_bytes = path.read_bytes()
    try:
        assert broker.session(refresh=True)["online"]
        with monkeypatch.context() as broken:
            if failure == "malformed-json":
                path.write_bytes(b"private invalid JSON")
            elif failure == "invalid-spec":
                spec["ssh"]["port"] = "private invalid port"
                path.write_text(json.dumps(spec), encoding="utf8")
            else:
                def denied(path):
                    raise PermissionError("private ACL details")
                broken.setattr(connection.storage, "_check_private_file", denied)
            value = broker.session(refresh=True)
            assert value["configured_connection"] is None
            assert value["connected"] and not value["online"] and not value["remote_actions_available"]
            assert value["center_url"] == reference and len(clients) == 1
            assert "private" not in json.dumps(value["connection_error"])
        path.write_bytes(original_bytes)
        assert broker.session(refresh=True)["online"]
        assert len(clients) == 2
    finally:
        path.write_bytes(original_bytes)
        broker.close()


def test_cached_actor_inspection_does_not_start_channel_without_refresh(local_metadata, monkeypatch):
    broker, reference, clients = configured_broker(local_metadata, monkeypatch)
    monkeypatch.setattr(connection, "_ensure_ssh", lambda *a: pytest.fail("inspection must not start SSH"))
    try:
        value = broker.session()
        assert value["configured_connection"] == {"mode": "managed-ssh", "center_reference": reference}
        assert value["connected"] and not value["online"] and clients == []
    finally:
        broker.close()


@pytest.mark.parametrize("change", ["key-content", "key-acl"])
def test_next_refresh_rejects_changed_key_or_acl_without_reusing_previous_validation(
        local_metadata, fake_processes, monkeypatch, change):
    broker, reference, clients = configured_broker(local_metadata, monkeypatch)
    try:
        assert broker.session(refresh=True)["online"]
        key = Path(local_metadata[1]["ssh"]["identity"]["path"])
        if change == "key-content":
            key.write_bytes(b"changed pinned key")
        else:
            original = connection.storage._check_private_file

            def check(path):
                if Path(path) == key:
                    raise connection.storage.MemberRegistrationError("registration_file_permissions")
                return original(path)

            monkeypatch.setattr(connection.storage, "_check_private_file", check)
        value = broker.session(refresh=True)
        assert value["connected"] and not value["online"] and not value["remote_actions_available"]
        assert value["configured_connection"] is None
        assert value["center_url"] == reference
        assert value["connection_error"]["reason_code"] == "center_unavailable"
        assert len(clients) == 1
        assert len(fake_processes[3]) == 1 and fake_processes[2] == []
    finally:
        broker.close()


def test_spec_is_reloaded_after_channel_lock_before_key_validation_or_launch(local_metadata, monkeypatch):
    root, spec, save = local_metadata
    reference = save()
    original = connection.storage._exclusive

    @contextmanager
    def changed_inside_lock(lock_root):
        with original(lock_root):
            (root / connection.SPEC_NAME).write_text(json.dumps(spec, indent=2), encoding="utf8")
            yield

    monkeypatch.setattr(connection.storage, "_exclusive", changed_inside_lock)
    monkeypatch.setattr(connection, "_ensure_ssh_locked", lambda *a: pytest.fail("changed spec must stop before channel action"))
    with pytest.raises(RuntimeError, match="channel_spec_changed"):
        connection.resolve_center(root, reference)


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize("status", [0, 401])
def test_resolved_descriptor_remains_available_when_center_is_offline_or_login_expired(
        local_metadata, fake_processes, monkeypatch, native, status):
    broker, reference, _ = configured_broker(local_metadata, monkeypatch, native=native, status=status)
    try:
        value = broker.session(refresh=True)
        assert value["configured_connection"] == {"mode": "managed-ssh", "center_reference": reference}
        assert value["center_url"] == reference
        assert value["connected"] and not value["online"] and not value["remote_actions_available"]
        assert value["connection_error"]["reason_code"] == ("center_login_required" if status == 401 else "center_unavailable")
    finally:
        broker.close()


@pytest.mark.parametrize("mode", ["https", "unselected", "absent"])
def test_signed_out_session_and_https_resolution_never_start_ssh(local_metadata, monkeypatch, mode):
    root, spec, save = local_metadata
    spec.update(mode="https" if mode == "https" else "unselected", https_url="https://center.example")
    spec.pop("ssh")
    reference = save()
    if mode == "absent":
        (root / connection.SPEC_NAME).unlink()
    monkeypatch.setattr(connection, "_ensure_ssh", lambda *a: pytest.fail("must not start SSH"))
    credentials = Credentials(reference)
    credentials.value = None
    broker = client.MemberBroker(root, credential_store=credentials)
    try:
        value = broker.session(refresh=True)
        expected = {"mode": "https", "center_reference": reference} if mode == "https" else None
        assert value["configured_connection"] == expected
        assert not value["connected"]
        if mode != "unselected":
            api, descriptor = broker._api_with_connection("https://center.example", "synthetic")
            assert api.base_url == "https://center.example" and descriptor == expected
    finally:
        broker.close()


def test_sign_in_reuses_resolved_descriptor_without_second_key_acl_check(local_metadata, fake_processes, monkeypatch):
    broker, reference, clients = configured_broker(local_metadata, monkeypatch)
    checks = []
    original = connection.storage._check_private_file
    key = Path(local_metadata[1]["ssh"]["identity"]["path"])
    def check(path):
        if Path(path) == key:
            checks.append(path)
        return original(path)
    monkeypatch.setattr(connection.storage, "_check_private_file", check)
    monkeypatch.setattr(connection, "public_connection", lambda *a: pytest.fail("duplicate sign-in lookup"))
    monkeypatch.setattr(broker.credentials, "save", lambda **kwargs: None, raising=False)
    try:
        value = broker.sign_in(client.Login(center_url=reference, token="synthetic-personal-token"))
        assert value["online"] and value["configured_connection"]["center_reference"] == reference
        assert len(checks) == 1 and len(clients) == 1
    finally:
        broker.close()
