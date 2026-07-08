"""Tests for the collectors added in the Privacy-Reclaim integration phases.

Network collectors are exercised against a fake context that returns canned
JSON, so the suite stays offline and deterministic.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from argus_osint.collectors import (
    BreachCollector,
    CensusAddressCollector,
    CISAKEVCollector,
    CollectorRegistry,
    ElectionRegistrationCollector,
    EmailUnsubscribeCollector,
    EPSSCollector,
    GitLabCollector,
    GravatarCollector,
    HackerNewsCollector,
    HouseholdPublicRecordsCollector,
    KeybaseCollector,
    NVDCollector,
    PackageRegistryCollector,
    RedditCollector,
    RobotsSitemapCollector,
    SecurityTxtCollector,
    ShodanInternetDBCollector,
    SocialProfileCollector,
    UrlscanCollector,
    YouTubeCollector,
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

    async def request(
        self,
        method,
        url,
        *,
        headers=None,
        params=None,
        cache_ttl=None,
        follow_redirects=True,
    ):
        self.requested.append(url)
        for fragment, payload in self._responses.items():
            if fragment in url:
                if isinstance(payload, httpx.Response):
                    return payload
                if isinstance(payload, dict) and "__text__" in payload:
                    return httpx.Response(
                        payload.get("__status__", 200),
                        text=payload["__text__"],
                        request=httpx.Request(method, url),
                    )
        response = httpx.Response(404, request=httpx.Request(method, url))
        raise httpx.HTTPStatusError("not found", request=response.request, response=response)


def _run(coro):
    return asyncio.run(coro)


def test_all_new_collectors_registered():
    ids = {c.id for c in CollectorRegistry().all()}
    for expected in {"data_broker", "gravatar", "keybase", "hackernews",
                     "reddit", "gitlab", "package_registry", "security_txt",
                     "robots_sitemap", "nvd_cve", "cisa_kev", "epss",
                     "shodan_internetdb", "urlscan", "social_profiles", "youtube",
                     "email_unsubscribe", "election_registration", "census_address",
                     "household_records"}:
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


def test_reddit_found_and_missing():
    ctx = FakeContext({"about.json": {"data": {"name": "spez", "total_karma": 500000,
                                               "created_utc": 1118030400}}})
    f = _run(RedditCollector().collect("u/spez", ctx))[0]
    assert f.data["found"] is True
    assert f.entities[0] == {"kind": "username", "value": "spez", "verified": True}

    empty = _run(RedditCollector().collect("ghost_user", FakeContext({"about.json": {}})))[0]
    assert empty.data["found"] is False
    assert empty.entities[0]["verified"] is False


def test_reddit_rejects_bad_username():
    with pytest.raises(ValueError):
        _run(RedditCollector().collect("a", FakeContext()))  # too short


def test_gitlab_profile_and_projects():
    ctx = FakeContext({
        "/users?username=": [{"id": 42, "username": "torvalds", "name": "Linus",
                              "web_url": "https://gitlab.com/torvalds"}],
        "/users/42/projects": [{"name": "proj1"}, {"name": "proj2"}],
    })
    f = _run(GitLabCollector().collect("torvalds", ctx))[0]
    assert f.data["found"] is True
    assert len(f.data["projects"]) == 2
    assert f.entities[0] == {"kind": "username", "value": "torvalds",
                             "display_name": "Linus", "verified": True}


def test_gitlab_missing_user():
    f = _run(GitLabCollector().collect("nobody", FakeContext({"/users?username=": []})))[0]
    assert f.data["found"] is False
    assert f.entities[0]["verified"] is False


def test_package_registry_pypi_and_npm():
    ctx = FakeContext({
        "pypi.org": {"info": {"name": "requests", "author": "Kenneth Reitz",
                              "author_email": "me@kennethreitz.org"}},
        "registry.npmjs.org": {"name": "express", "description": "web framework",
                               "author": {"name": "TJ", "email": "tj@example.com"}},
    })
    findings = _run(PackageRegistryCollector().collect("requests", ctx))
    titles = {f.title for f in findings}
    assert any(t.startswith("PyPI:") for t in titles)
    assert any(t.startswith("npm:") for t in titles)
    all_entities = {(e["kind"], e["value"]) for f in findings for e in f.entities}
    assert ("person", "Kenneth Reitz") in all_entities
    assert ("email", "tj@example.com") in all_entities


def test_package_registry_not_found():
    findings = _run(PackageRegistryCollector().collect("zzz-nonexistent", FakeContext()))
    assert len(findings) == 1
    assert findings[0].data["found"] is False


def test_security_txt_parses_disclosure_fields(monkeypatch):
    monkeypatch.setattr("argus_osint.collectors._ensure_public_host", lambda host, port=443: None)
    ctx = FakeContext({
        "/.well-known/security.txt": {"__text__": (
            "Contact: mailto:security@example.org\n"
            "Expires: 2027-01-01T00:00:00Z\n"
            "Policy: https://example.org/security\n"
        )},
    })
    f = _run(SecurityTxtCollector().collect("example.org", ctx))[0]
    assert f.data["found"] is True
    assert f.data["fields"]["contact"] == ["mailto:security@example.org"]
    assert f.entities[0] == {"kind": "domain", "value": "example.org", "verified": True}


def test_robots_sitemap_extracts_urls(monkeypatch):
    monkeypatch.setattr("argus_osint.collectors._ensure_public_host", lambda host, port=443: None)
    ctx = FakeContext({
        "/robots.txt": {"__text__": (
            "User-agent: *\n"
            "Disallow: /private\n"
            "Sitemap: https://example.org/from-robots.xml\n"
        )},
        "/sitemap.xml": {"__text__": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            "<url><loc>https://example.org/about</loc></url>"
            "</urlset>"
        )},
    })
    f = _run(RobotsSitemapCollector().collect("https://example.org", ctx))[0]
    assert f.data["robots"]["disallow"] == ["/private"]
    assert set(f.data["sitemap_urls"]) == {
        "https://example.org/about",
        "https://example.org/from-robots.xml",
    }
    assert ("url", "https://example.org/about") in {
        (entity["kind"], entity["value"]) for entity in f.entities
    }


def test_nvd_cve_extracts_cve_and_reference_entities():
    ctx = FakeContext({"services.nvd.nist.gov": {
        "totalResults": 1,
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-3094",
                "references": {"referenceData": [
                    {"url": "https://example.org/advisory"},
                ]},
            },
        }],
    }})
    f = _run(NVDCollector().collect("CVE-2024-3094", ctx))[0]
    assert f.data["result_count"] == 1
    assert ("cve", "CVE-2024-3094") in {(e["kind"], e["value"]) for e in f.entities}
    assert ("url", "https://example.org/advisory") in {
        (e["kind"], e["value"]) for e in f.entities
    }


def test_cisa_kev_filters_live_catalog_rows():
    ctx = FakeContext({"known_exploited_vulnerabilities": {
        "catalogVersion": "2026.07.08",
        "dateReleased": "2026-07-08",
        "vulnerabilities": [
            {"cveID": "CVE-2024-3094", "vendorProject": "XZ Utils",
             "product": "XZ", "knownRansomwareCampaignUse": "Unknown"},
            {"cveID": "CVE-2023-0001", "vendorProject": "Other", "product": "Thing"},
        ],
    }})
    f = _run(CISAKEVCollector().collect("xz", ctx))[0]
    assert f.data["result_count"] == 1
    assert ("cve", "CVE-2024-3094") in {(e["kind"], e["value"]) for e in f.entities}
    assert ("company", "XZ Utils") in {(e["kind"], e["value"]) for e in f.entities}


def test_epss_returns_probability_and_percentile():
    ctx = FakeContext({"api.first.org": {"data": [
        {"cve": "CVE-2024-3094", "epss": "0.94421",
         "percentile": "0.99911", "date": "2026-07-08"},
    ]}})
    f = _run(EPSSCollector().collect("CVE-2024-3094", ctx))[0]
    assert f.data["found"] is True
    assert f.data["epss"] == pytest.approx(0.94421)
    assert f.entities[0]["attributes"]["percentile"] == pytest.approx(0.99911)


def test_shodan_internetdb_extracts_exposure_entities():
    ctx = FakeContext({"internetdb.shodan.io": {
        "ip": "8.8.8.8",
        "ports": [53, 443],
        "hostnames": ["dns.google"],
        "cpes": ["cpe:/a:example:service"],
        "tags": ["cdn"],
        "vulns": ["CVE-2024-0001"],
    }})
    f = _run(ShodanInternetDBCollector().collect("8.8.8.8", ctx))[0]
    assert f.data["ports"] == [53, 443]
    assert ("ip", "8.8.8.8") in {(e["kind"], e["value"]) for e in f.entities}
    assert ("domain", "dns.google") in {(e["kind"], e["value"]) for e in f.entities}
    assert ("cve", "CVE-2024-0001") in {(e["kind"], e["value"]) for e in f.entities}


def test_urlscan_search_extracts_page_entities():
    ctx = FakeContext({"urlscan.io": {
        "total": 1,
        "results": [{
            "task": {"uuid": "scan-uuid"},
            "page": {"domain": "example.org", "ip": "93.184.216.34",
                     "url": "https://example.org/login"},
        }],
    }})
    f = _run(UrlscanCollector().collect("example.org", ctx))[0]
    assert f.data["query"] == "domain:example.org"
    entities = {(e["kind"], e["value"]) for e in f.entities}
    assert ("domain", "example.org") in entities
    assert ("ip", "93.184.216.34") in entities
    assert ("url", "https://example.org/login") in entities
    assert ("urlscan_uuid", "scan-uuid") in entities


def test_social_profile_leads_are_free_and_unverified():
    f = _run(SocialProfileCollector().collect("alice", FakeContext()))[0]
    assert f.data["cost"] == "free"
    assert f.data["requires_api_key"] is False
    platforms = {item["platform"] for item in f.data["candidates"]}
    assert {"X", "Instagram", "TikTok", "YouTube", "LinkedIn", "Telegram"} <= platforms
    assert all(item["identity_match"] is False for item in f.data["candidates"])
    assert f.entities[0] == {"kind": "username", "value": "alice", "verified": False}


def test_youtube_resolves_handle_and_reads_public_feed():
    feed = """<?xml version="1.0" encoding="UTF-8"?>
    <feed xmlns="http://www.w3.org/2005/Atom" xmlns:yt="http://www.youtube.com/xml/schemas/2015">
      <title>Alice Channel</title>
      <author><name>Alice</name></author>
      <entry>
        <yt:videoId>video123</yt:videoId>
        <title>Launch notes</title>
        <published>2026-07-08T00:00:00+00:00</published>
        <updated>2026-07-08T00:00:00+00:00</updated>
        <link rel="alternate" href="https://www.youtube.com/watch?v=video123" />
      </entry>
    </feed>"""
    ctx = FakeContext({
        "@alice": {"__text__": '{"channelId":"UCabc12345678901234567890"}'},
        "feeds/videos.xml": {"__text__": feed},
    })
    f = _run(YouTubeCollector().collect("@alice", ctx))[0]
    assert f.data["cost"] == "free"
    assert f.data["requires_api_key"] is False
    assert f.data["channel_id"] == "UCabc12345678901234567890"
    assert f.data["entries"][0]["video_id"] == "video123"
    assert ("youtube_channel", "UCabc12345678901234567890") in {
        (entity["kind"], entity["value"]) for entity in f.entities
    }


def test_email_unsubscribe_parses_list_headers():
    raw = """From: Example Sender <news@example.org>
Return-Path: <bounce@example.org>
List-ID: Example Newsletter <news.example.org>
List-Unsubscribe: <mailto:unsubscribe@example.org?subject=unsubscribe>, <https://example.org/unsub?id=abc>
List-Unsubscribe-Post: List-Unsubscribe=One-Click
Authentication-Results: mx.example; spf=pass smtp.mailfrom=example.org

Hello
"""
    f = _run(EmailUnsubscribeCollector().collect(raw, FakeContext()))[0]
    assert f.data["cost"] == "free"
    assert f.data["does_not_click_links"] is True
    assert f.data["one_click_supported"] is True
    kinds = {(option["kind"], option["target"]) for option in f.data["unsubscribe_options"]}
    assert ("mailto", "mailto:unsubscribe@example.org?subject=unsubscribe") in kinds
    assert ("url", "https://example.org/unsub?id=abc") in kinds
    entities = {(entity["kind"], entity["value"]) for entity in f.entities}
    assert ("email", "unsubscribe@example.org") in entities
    assert ("url", "https://example.org/unsub?id=abc") in entities
    assert ("domain", "example.org") in entities


def test_email_unsubscribe_plain_address_returns_guidance():
    f = _run(EmailUnsubscribeCollector().collect("person@example.org", FakeContext()))[0]
    assert f.data["headers_required"] is True
    assert f.data["requires_api_key"] is False
    assert f.entities[0] == {"kind": "email", "value": "person@example.org", "verified": False}


def _census_payload():
    return {
        "result": {
            "addressMatches": [{
                "matchedAddress": "4600 SILVER HILL RD, WASHINGTON, DC, 20233",
                "coordinates": {"x": -76.9274872423, "y": 38.8460162239},
                "addressComponents": {"state": "DC", "city": "WASHINGTON", "zip": "20233"},
                "geographies": {
                    "Counties": [{"NAME": "District of Columbia", "GEOID": "11001"}],
                    "Census Tracts": [{"NAME": "Tract 8024.01", "GEOID": "11001002401"}],
                    "Congressional Districts": [{"NAME": "Delegate District", "GEOID": "98"}],
                },
            }],
        }
    }


def test_election_registration_state_resources_are_official_and_free():
    f = _run(ElectionRegistrationCollector().collect("DC", FakeContext()))[0]
    assert f.data["state"] == {"code": "DC", "name": "District of Columbia"}
    assert f.data["does_not_query_voter_rolls"] is True
    assert all(item["cost"] == "free" for item in f.data["resources"])
    assert any("vote.gov" in item["url"] for item in f.data["resources"])
    assert any("nass.org" in item["url"] for item in f.data["resources"])


def test_election_registration_address_uses_census_state():
    ctx = FakeContext({"geocoding.geo.census.gov": _census_payload()})
    f = _run(ElectionRegistrationCollector().collect(
        "4600 Silver Hill Rd, Washington, DC 20233", ctx
    ))[0]
    assert f.data["state"]["code"] == "DC"
    assert f.data["matched_address"] == "4600 SILVER HILL RD, WASHINGTON, DC, 20233"
    assert ("state", "DC") in {(entity["kind"], entity["value"]) for entity in f.entities}


def test_census_address_collector_extracts_geographies_and_location():
    ctx = FakeContext({"geocoding.geo.census.gov": _census_payload()})
    f = _run(CensusAddressCollector().collect(
        "4600 Silver Hill Rd, Washington, DC 20233", ctx
    ))[0]
    assert f.data["match_count"] == 1
    assert f.data["latitude"] == pytest.approx(38.8460162239)
    assert f.data["geographies"]["Counties"]["GEOID"] == "11001"
    assert f.entities[0]["kind"] == "address"


def test_household_public_records_are_address_leads_not_resident_claims():
    ctx = FakeContext({"geocoding.geo.census.gov": _census_payload()})
    f = _run(HouseholdPublicRecordsCollector().collect(
        "4600 Silver Hill Rd, Washington, DC 20233", ctx
    ))[0]
    assert f.data["identity_match"] is False
    assert "does not identify residents" in f.data["warning"]
    lead_titles = {lead["title"] for lead in f.data["leads"]}
    assert {"County property assessor", "County election office"} <= lead_titles
    assert all("search.usa.gov" in lead["search_url"] for lead in f.data["leads"])
