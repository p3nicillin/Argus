from __future__ import annotations

import asyncio
import json
from pathlib import Path

from argus_osint.campaigns import CampaignPlanner, CampaignRunner
from argus_osint.collectors import CollectorRegistry
from argus_osint.db import Database
from argus_osint.operations import OperationManager
from argus_osint.reports import ReportEngine
from argus_osint.repository import Repository
from argus_osint.security import SecurityBriefBuilder


class FakeContext:
    def __init__(self, responses: dict | None = None):
        self._responses = responses or {}
        self.requested: list[str] = []

    def secret(self, name: str) -> str:
        return ""

    async def get_json(self, url, *, headers=None, params=None, cache_ttl=None):
        self.requested.append(url)
        for fragment, payload in self._responses.items():
            if fragment in url:
                return payload
        return {}


def _run(coro):
    return asyncio.run(coro)


def test_campaign_planner_builds_security_domain_and_cve_plans():
    planner = CampaignPlanner()
    domain_plan = planner.plan_seed("example.org")
    cve_plan = planner.plan_seed("CVE-2024-3094")

    assert {"dns", "web", "security_txt", "robots_sitemap", "urlscan"} <= {
        item.collector for item in domain_plan
    }
    assert [item.collector for item in cve_plan[:3]] == ["nvd_cve", "cisa_kev", "epss"]
    assert all(item.reason for item in domain_plan + cve_plan)


def test_campaign_runner_archives_seed_results(tmp_path: Path):
    repository = Repository(Database(tmp_path / "argus.sqlite3"), "analyst")
    try:
        case_id = repository.create_investigation("Security campaign")
        context = FakeContext({"services.nvd.nist.gov": {
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
        operations = OperationManager(repository, CollectorRegistry(), context)
        result = _run(
            CampaignRunner(operations).run_seed(
                case_id, "CVE-2024-3094", depth=0, max_jobs=1
            )
        )

        assert result["job_count"] == 1
        assert repository.rows("collection_jobs", case_id)[0]["status"] == "completed"
        assert repository.rows("intelligence", case_id)[0]["collector"] == "nvd_cve"
        entities = {(row["kind"], row["value"]) for row in repository.rows("entities", case_id)}
        assert ("cve", "CVE-2024-3094") in entities
        assert ("url", "https://example.org/advisory") in entities
    finally:
        repository.db.close()


def test_security_brief_scores_risks_and_exports(tmp_path: Path):
    repository = Repository(Database(tmp_path / "brief.sqlite3"), "analyst")
    try:
        case_id = repository.create_investigation("Prioritized case")
        repository.add_entity(case_id, "cve", "CVE-2024-3094", verified=True)
        repository.add_intelligence(
            case_id,
            "cisa_kev",
            "CVE-2024-3094",
            "CISA KEV: CVE-2024-3094",
            {"vulnerabilities": [{"cveID": "CVE-2024-3094", "vendorProject": "XZ Utils"}]},
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            0.9,
        )
        repository.add_intelligence(
            case_id,
            "epss",
            "CVE-2024-3094",
            "EPSS: CVE-2024-3094",
            {"cve": "CVE-2024-3094", "epss": 0.94, "percentile": 0.99},
            "https://www.first.org/epss/data_stats?cve=CVE-2024-3094",
            0.85,
        )
        repository.add_intelligence(
            case_id,
            "shodan_internetdb",
            "8.8.8.8",
            "Shodan InternetDB: 8.8.8.8",
            {"ip": "8.8.8.8", "ports": [53, 443], "vulnerabilities": ["CVE-2024-3094"]},
            "https://www.shodan.io/host/8.8.8.8",
            0.75,
        )

        brief = SecurityBriefBuilder(repository).build(case_id)
        top = brief["top_risks"][0]
        assert top["value"] == "CVE-2024-3094"
        assert top["score"] >= 9
        assert any("CISA" in reason for reason in top["reasons"])

        output = ReportEngine(repository).export_security_brief(case_id, tmp_path / "brief.json")
        payload = json.loads(output.read_text(encoding="utf-8"))
        assert payload["summary"]["risk_count"] >= 2
        markdown = ReportEngine(repository).export_security_brief(case_id, tmp_path / "brief.md")
        assert "Security research brief" in markdown.read_text(encoding="utf-8")
    finally:
        repository.db.close()
