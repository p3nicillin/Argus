"""Tests for the data-broker exposure module and its collector wrapper."""

from __future__ import annotations

import asyncio

import pytest

from argus_osint import databrokers
from argus_osint.collectors import CollectorRegistry, DataBrokerCollector


def test_candidate_links_for_name():
    leads = databrokers.candidate_links("Luke McClellan")
    searchable = [b for b in databrokers.BROKERS if b.search_url]
    assert len(leads) == len(searchable)
    assert len(leads) >= 20  # registry expanded to a useful breadth
    spokeo = next(lead for lead in leads if lead["broker"] == "Spokeo")
    assert spokeo["search_url"] == "https://www.spokeo.com/Luke+McClellan"
    whitepages = next(lead for lead in leads if lead["broker"] == "Whitepages")
    assert whitepages["search_url"] == "https://www.whitepages.com/name/Luke+McClellan"
    assert whitepages["opt_out_url"] == "https://www.whitepages.com/suppression-requests"
    # every lead is explicitly an unverified candidate
    assert all(lead["identity_match"] is False for lead in leads)
    assert all(lead["status"] == "unverified candidate" for lead in leads)
    assert all("removal_status" in lead for lead in leads)


def test_candidate_links_email_uses_local_part():
    leads = databrokers.candidate_links("jane.doe@example.com")
    assert all("jane.doe" in lead["search_url"] for lead in leads)
    assert all("example.com" not in lead["search_url"] for lead in leads)


def test_candidate_links_rejects_empty():
    with pytest.raises(ValueError):
        databrokers.candidate_links("   ")


def test_collector_registered_and_shaped():
    registry = CollectorRegistry()
    assert "data_broker" in {c.id for c in registry.all()}

    collector = DataBrokerCollector()
    findings = asyncio.run(collector.collect("Luke McClellan", context=None))
    assert len(findings) == 1
    f = findings[0]
    assert f.confidence == 0.2  # unverified leads, like username correlation
    assert f.entities[0] == {"kind": "person", "value": "Luke McClellan", "verified": False}
    assert len(f.data["candidates"]) == len([b for b in databrokers.BROKERS if b.search_url])
    assert "warning" in f.data
    assert any(candidate["opt_out_url"] for candidate in f.data["candidates"])
