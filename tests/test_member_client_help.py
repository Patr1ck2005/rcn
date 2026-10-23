from fastapi.testclient import TestClient
import pytest

from research_compute_network.client import RcnApiError
from research_compute_network.help import HelpCatalog
from research_compute_network.member_client import create_member_app


GUIDE = "member-task-package"


class Credentials:
    def __init__(self):
        self.value = None

    def load(self):
        return self.value

    def save(self, **value):
        self.value = value

    def clear(self):
        self.value = None


class Center:
    def __init__(self):
        self.calls = []
        self.failure = None
        self.catalog = {
            "public": [{"slug": "center-only-old-guide", "title": "Old center guidance"}],
            "protected": [{"slug": "center-member-guide", "audience": "protected", "access": "allowed"}],
        }
        self.article = {"slug": "member-runbook", "html": "<p>Authorized center content</p>"}

    def api(self, endpoint, token=None):
        center = self

        class API:
            def current_actor(self):
                return {"actor_id": "member-alice", "roles": ["member"]}

            def _request(self, method, path, payload=None):
                center.calls.append((method, path, payload, token))
                if center.failure:
                    raise center.failure
                if path == "/v1/help/catalog":
                    return center.catalog
                if path == "/v1/help/protected":
                    return center.catalog["protected"]
                if path.startswith("/v1/help/protected/"):
                    return center.article
                if path == "/v1/profiles":
                    return [{"profile_id": "center-profile"}]
                raise AssertionError(f"unexpected center route: {path}")

        return API()


@pytest.fixture
def help_client(tmp_path):
    center = Center()
    app = create_member_app(state_root=tmp_path / "member", credential_store=Credentials(),
                            api_factory=center.api)
    with TestClient(app) as browser:
        assert browser.get("/local/v1/capabilities").status_code == 200
        yield browser, center


def sign_in(browser):
    response = browser.post("/local/v1/session", json={
        "center_url": "https://center.example", "token": "personal-help-fixture",
    })
    assert response.status_code == 200


def test_packaged_public_help_is_readable_without_center_login(help_client):
    browser, center = help_client
    index = browser.get("/v1/help/public")
    assert index.status_code == 200
    guide = next(article for article in index.json() if article["slug"] == GUIDE)
    assert guide["audience"] == "public" and guide["access"] == "allowed"
    assert "Agent" in " ".join([guide["summary"], *guide["keywords"]])
    assert guide["source_refs"]
    assert all(ref["document"] == "docs/member-task-package-guide.zh.md"
               for ref in guide["source_refs"])
    article = browser.get(f"/v1/help/public/{GUIDE}")
    assert article.status_code == 200 and "Agent" in article.json()["html"]
    assert article.json()["source_refs"] == guide["source_refs"]
    assert browser.get("/v1/help/catalog").json() == {"public": index.json(), "protected": []}
    assert center.calls == []


def test_public_help_does_not_expose_packaged_protected_content(help_client):
    browser, center = help_client
    for slug in ("admin-runbook", "member-runbook", "does-not-exist"):
        response = browser.get(f"/v1/help/public/{slug}")
        assert response.status_code == 404
        assert "html" not in response.json()
    assert browser.get("/v1/help/protected").status_code == 401
    assert browser.get("/v1/help/protected/admin-runbook").status_code == 401
    assert center.calls == []


def test_help_catalog_combines_installed_public_with_center_authorized_protected(help_client):
    browser, center = help_client
    sign_in(browser)
    # The installed guide remains discoverable with an older center catalog.
    response = browser.get("/v1/help/catalog")
    assert response.status_code == 200
    catalog = response.json()
    assert catalog["public"] == browser.get("/v1/help/public").json()
    assert GUIDE in {item["slug"] for item in catalog["public"]}
    assert "center-only-old-guide" not in {item["slug"] for item in catalog["public"]}
    assert catalog["protected"] == center.catalog["protected"]
    assert center.calls == [("GET", "/v1/help/catalog", None, "personal-help-fixture")]
    assert browser.get(f"/v1/help/public/{GUIDE}").json() == HelpCatalog().public(GUIDE)


@pytest.mark.parametrize("status", [0, 404, 401, 403])
def test_help_catalog_failure_never_reuses_protected_metadata(help_client, status):
    browser, center = help_client
    sign_in(browser)
    assert browser.get("/v1/help/catalog").json()["protected"]
    center.failure = RcnApiError(status, "synthetic unavailable or unauthorized center")
    response = browser.get("/v1/help/catalog")
    assert response.status_code == 200
    assert response.json()["protected"] == []
    assert GUIDE in {item["slug"] for item in response.json()["public"]}
    assert browser.get(f"/v1/help/public/{GUIDE}").status_code == 200
    protected = browser.get("/v1/help/protected/admin-runbook")
    assert protected.status_code == (503 if status == 0 else status)
    assert "html" not in protected.json()
    # Offline help fallback must not absorb failures from unrelated API routes.
    assert browser.get("/v1/profiles").status_code == (503 if status == 0 else status)


def test_protected_help_still_uses_center_authorization_and_payload(help_client):
    browser, center = help_client
    sign_in(browser)
    assert browser.get("/v1/help/protected").json() == center.catalog["protected"]
    assert browser.get("/v1/help/protected/member-runbook").json() == center.article
    assert center.calls[-1] == ("GET", "/v1/help/protected/member-runbook", None, "personal-help-fixture")
    browser.delete("/local/v1/session")
    assert browser.get("/v1/help/catalog").json()["protected"] == []
    assert browser.get("/v1/help/protected/member-runbook").status_code == 401


def test_local_help_keeps_browser_session_origin_and_write_boundaries(help_client):
    browser, center = help_client
    browser.cookies.clear()
    assert browser.get("/v1/help/public").status_code == 403
    browser.get("/local/v1/capabilities")
    for path in ("/v1/help/public", f"/v1/help/public/{GUIDE}", "/v1/help/catalog"):
        assert browser.get(path, headers={"Origin": "https://foreign.example"}).status_code == 403
        assert browser.post(path, json={}).status_code == 403
    assert browser.put("/v1/help/protected/member-runbook", json={}).status_code == 403
    assert center.calls == []
