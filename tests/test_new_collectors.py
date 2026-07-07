"""Tests for the collectors added in the Privacy-Reclaim integration phases.

Network collectors are exercised against a fake context that returns canned
JSON, so the suite stays offline and deterministic.
"""

from __future__ import annotations

import asyncio

import pytest

from argus_osint.collectors import (
    BreachCollector,
    CollectorRegistry,
    GravatarCollector,
    HackerNewsCollector,
    KeybaseCollector,
)


class FakeContext:
    """Minimal CollectorContext stand-in: canned get_json + secret store."""

    def __init__(self, responses: dict | None = None, secrets: dict | None = None):
        self._responses = responses or {}
        self._secrets = secrets or {}
        self.requested: list[str] = []

    def secret(self, name: str) -> str:
        return self._secrets.get(name, "")

    async def get_json(self, url, *, headers=None, params=None, cache_ttl=None):
        self.requested.append(url)
        for fragment, payload in self._responses.items():
            if fragment in url:
                return payload
        return {}


def _run(coro):
    return asyncio.run(coro)


def test_all_new_collectors_registered():
    ids = {c.id for c in CollectorRegistry().all()}
    for expected in {"data_broker", "gravatar", "keybase", "hackernews"}:
        assert expected in ids


def test_gravatar_extracts_linked_accounts():
    ctx = FakeContext({
        ".json": {"entry": [{
            "displayName": "Jane",
            "accounts": [{"username": "jane_x", "shortname": "twitter"}],
        }]},
    })
    findings = _run(GravatarCollector().collect("jane@example.com", ctx))
    f = findings[0]
    assert f.data["exists"] is True
    import hashlib
    assert f.data["email_md5"] == hashlib.md5(b"jane@example.com").hexdigest()
    handles = [e["value"] for e in f.entities if e["kind"] == "username"]
    assert "jane_x" in handles


def test_gravatar_rejects_bad_email():
    with pytest.raises(ValueError):
        _run(GravatarCollector().collect("not-an-email", FakeContext()))


def test_keybase_collects_proofs():
    ctx = FakeContext({
        "user/lookup.json": {"them": [{
            "basics": {"username": "chris"},
            "proofs_summary": {"all": [
                {"proof_type": "github", "nametag": "chrisdev",
                 "service_url": "https://github.com/chrisdev"},
            ]},
        }]},
    })
    f = _run(KeybaseCollector().collect("chris", ctx))[0]
    assert f.data["found"] is True
    assert f.data["proofs"][0]["platform"] == "github"
    assert any(e["value"] == "chrisdev" for e in f.entities)
    assert f.entities[0]["verified"] is True  # keybase user exists


def test_keybase_absent_user():
    f = _run(KeybaseCollector().collect("ghost", FakeContext({"lookup.json": {"them": []}})))[0]
    assert f.data["found"] is False
    assert f.entities[0]["verified"] is False


def test_hackernews_found_and_missing():
    ctx = FakeContext({".json": {"id": "pg", "karma": 155000, "created": 1160418092}})
    f = _run(HackerNewsCollector().collect("pg", ctx))[0]
    assert f.data["found"] is True and f.entities[0]["verified"] is True

    ctx2 = FakeContext({".json": None})
    f2 = _run(HackerNewsCollector().collect("nobody", ctx2))[0]
    assert f2.data["found"] is False and f2.entities[0]["verified"] is False


def test_breach_free_provider_and_entity_enrichment():
    """No API key -> free XposedOrNot; breaches become company/domain entities."""
    xon = {"ExposedBreaches": {"breaches_details": [
        {"breach": "Adobe", "domain": "adobe.com", "xposed_date": "2013",
         "xposed_records": 152000000, "xposed_data": "Emails;Passwords",
         "details": "Adobe breach", "verified": "true"},
        {"breach": "Canva", "domain": "canva.com", "xposed_date": "2019",
         "xposed_data": "Emails;Names", "verified": "true"},
    ]}}
    ctx = FakeContext({"xposedornot": xon})  # no hibp_api_key secret
    f = _run(BreachCollector().collect("victim@example.com", ctx))[0]
    assert any("xposedornot" in u for u in ctx.requested)  # used the FREE provider
    assert f.data["count"] == 2
    kinds = {(e["kind"], e["value"]) for e in f.entities}
    assert ("company", "Adobe") in kinds
    assert ("domain", "adobe.com") in kinds
    assert ("email", "victim@example.com") in kinds


def test_breach_uses_hibp_when_key_present():
    ctx = FakeContext(
        {"haveibeenpwned": [{"Name": "LinkedIn", "Domain": "linkedin.com"}]},
        secrets={"hibp_api_key": "secret"},
    )
    f = _run(BreachCollector().collect("x@example.com", ctx))[0]
    assert any("haveibeenpwned" in u for u in ctx.requested)
    assert ("company", "LinkedIn") in {(e["kind"], e["value"]) for e in f.entities}
