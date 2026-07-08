from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .campaigns import CampaignPlanner
from .repository import Repository


class SecurityBriefBuilder:
    """Create a compact security-research brief from archived Argus records."""

    def __init__(self, repository: Repository) -> None:
        self.repository = repository
        self.planner = CampaignPlanner()

    def build(self, case_id: int, *, top: int = 10) -> dict[str, Any]:
        investigation = self.repository.investigation(case_id)
        intelligence = self.repository.rows("intelligence", case_id)
        entities = self.repository.rows("entities", case_id)
        sources = self.repository.rows("source_records", case_id)
        jobs = self.repository.rows("collection_jobs", case_id)
        risks = self._risks(intelligence, entities)
        top_risks = sorted(risks, key=lambda item: item["score"], reverse=True)[:top]
        next_steps = [request.to_dict() for request in self.planner.plan_case(entities, limit=12)]
        return {
            "investigation": {
                "id": investigation["id"],
                "title": investigation["title"],
                "status": investigation["status"],
            },
            "summary": {
                "entity_count": len(entities),
                "intelligence_count": len(intelligence),
                "source_count": len(sources),
                "completed_jobs": sum(1 for job in jobs if job.get("status") == "completed"),
                "risk_count": len(risks),
                "highest_score": top_risks[0]["score"] if top_risks else 0.0,
            },
            "collector_coverage": dict(Counter(row["collector"] for row in intelligence)),
            "entity_coverage": dict(Counter(row["kind"] for row in entities)),
            "top_risks": top_risks,
            "source_provenance": [
                {
                    "title": row["title"],
                    "url": row["url"],
                    "publisher": row["publisher"],
                    "retrieved_at": row["retrieved_at"],
                    "content_hash": row["content_hash"],
                }
                for row in sources[-25:]
            ],
            "recommended_collection": next_steps,
        }

    def markdown(self, case_id: int, *, top: int = 10) -> str:
        brief = self.build(case_id, top=top)
        lines = [
            f"# Security research brief: {brief['investigation']['title']}",
            "",
            "## Summary",
            f"- Entities: {brief['summary']['entity_count']}",
            f"- Intelligence records: {brief['summary']['intelligence_count']}",
            f"- Sources: {brief['summary']['source_count']}",
            f"- Completed jobs: {brief['summary']['completed_jobs']}",
            f"- Risk items: {brief['summary']['risk_count']}",
            "",
            "## Top risks",
        ]
        if not brief["top_risks"]:
            lines.append("- No prioritized security risks were found in the archived data.")
        for risk in brief["top_risks"]:
            lines.append(f"- {risk['score']:.1f} {risk['title']} ({risk['kind']})")
            for reason in risk["reasons"]:
                lines.append(f"  - {reason}")
        lines.extend(["", "## Recommended collection"])
        for item in brief["recommended_collection"]:
            lines.append(f"- `{item['collector']}` on `{item['query']}`: {item['reason']}")
        return "\n".join(lines) + "\n"

    def _risks(
        self,
        intelligence: list[dict[str, Any]],
        entities: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        risk_index: dict[tuple[str, str], dict[str, Any]] = {}
        cve_entities = {row["value"] for row in entities if row["kind"] == "cve"}
        for cve in cve_entities:
            risk_index[("cve", cve)] = {
                "kind": "cve",
                "value": cve,
                "title": f"Vulnerability observed: {cve}",
                "score": 4.0,
                "reasons": ["CVE was discovered in case intelligence"],
                "sources": [],
            }

        shodan_cves: defaultdict[str, set[str]] = defaultdict(set)
        for row in intelligence:
            data = row.get("data") or {}
            collector = row.get("collector", "")
            if collector == "cisa_kev":
                for item in data.get("vulnerabilities", []):
                    cve = item.get("cveID")
                    if cve:
                        risk = risk_index.setdefault(("cve", cve), self._risk("cve", cve))
                        risk["score"] += 4.0
                        risk["reasons"].append("Listed in CISA Known Exploited Vulnerabilities")
                        risk["sources"].append(row.get("source_url", ""))
            elif collector == "epss":
                cve = data.get("cve") or row.get("query", "").upper()
                probability = float(data.get("epss") or 0.0)
                percentile = float(data.get("percentile") or 0.0)
                risk = risk_index.setdefault(("cve", cve), self._risk("cve", cve))
                risk["score"] += min(3.0, probability * 3.0 + percentile)
                risk["reasons"].append(
                    f"EPSS probability {probability:.3f}, percentile {percentile:.3f}"
                )
                risk["sources"].append(row.get("source_url", ""))
            elif collector == "shodan_internetdb":
                ip = data.get("ip") or row.get("query", "")
                ports = data.get("ports") or []
                vulns = data.get("vulnerabilities") or []
                if ports:
                    risk_index[("exposure", ip)] = {
                        "kind": "exposure",
                        "value": ip,
                        "title": f"Public services exposed on {ip}",
                        "score": min(7.0, 2.0 + len(ports) * 0.4 + len(vulns) * 1.5),
                        "reasons": [f"Observed public ports: {', '.join(map(str, ports[:12]))}"],
                        "sources": [row.get("source_url", "")],
                    }
                for cve in vulns:
                    shodan_cves[cve].add(ip)
            elif collector == "breach":
                count = int(data.get("count") or len(data.get("breaches", [])))
                if count:
                    email = data.get("email") or row.get("query", "")
                    risk_index[("breach", email)] = {
                        "kind": "breach",
                        "value": email,
                        "title": f"Breach exposure for {email}",
                        "score": min(8.0, 3.0 + count * 0.8),
                        "reasons": [f"{count} breach records returned by lawful exposure check"],
                        "sources": [row.get("source_url", "")],
                    }
            elif collector == "security_txt" and data.get("found") is False:
                domain = row.get("query", "")
                risk_index[("disclosure", domain)] = {
                    "kind": "disclosure",
                    "value": domain,
                    "title": f"No security.txt found for {domain}",
                    "score": 2.0,
                    "reasons": ["No public vulnerability disclosure metadata was found"],
                    "sources": [row.get("source_url", "")],
                }

        for cve, ips in shodan_cves.items():
            risk = risk_index.setdefault(("cve", cve), self._risk("cve", cve))
            risk["score"] += min(3.0, len(ips) * 1.5)
            risk["reasons"].append(f"Referenced by Shodan InternetDB for {len(ips)} IP address(es)")

        for risk in risk_index.values():
            risk["score"] = round(min(10.0, risk["score"]), 2)
            risk["reasons"] = list(dict.fromkeys(reason for reason in risk["reasons"] if reason))
            risk["sources"] = list(dict.fromkeys(source for source in risk["sources"] if source))
        return list(risk_index.values())

    @staticmethod
    def _risk(kind: str, value: str) -> dict[str, Any]:
        return {
            "kind": kind,
            "value": value,
            "title": f"Vulnerability observed: {value}",
            "score": 4.0,
            "reasons": ["CVE was discovered in case intelligence"],
            "sources": [],
        }
