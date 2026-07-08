from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse

from . import civic
from .collectors import CollectorRegistry
from .operations import OperationManager


@dataclass(frozen=True, slots=True)
class CollectorRequest:
    collector: str
    query: str
    reason: str

    def key(self) -> tuple[str, str]:
        return self.collector, self.query.casefold().strip()

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


class CampaignPlanner:
    """Build bounded, explainable collector plans from seeds and discovered entities."""

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()

    def plan_seed(self, value: str, kind: str | None = None) -> list[CollectorRequest]:
        seed = value.strip()
        if not seed:
            raise ValueError("Campaign seed is required")
        entity_kind = (kind or self.classify(seed)).casefold()
        requests: list[CollectorRequest] = []

        if entity_kind == "domain":
            requests.extend([
                self._request("dns", seed, "Resolve DNS, WHOIS and RDAP"),
                self._request("web", seed, "Fingerprint the public website"),
                self._request("security_txt", seed, "Find disclosure contacts and policy"),
                self._request("robots_sitemap", seed, "Discover public crawl and sitemap hints"),
                self._request(
                    "certificate_transparency", seed, "Discover subdomains from public CT logs"
                ),
                self._request("urlscan", seed, "Find public urlscan observations"),
                self._request("wayback", seed, "Review historical captures"),
            ])
        elif entity_kind == "ip":
            requests.extend([
                self._request("ip", seed, "Collect GeoIP, ASN and reverse-DNS context"),
                self._request("shodan_internetdb", seed, "Review public exposure and CVE hints"),
                self._request("dns", seed, "Resolve reverse DNS and RDAP"),
                self._request("urlscan", seed, "Find public scans that observed this IP"),
            ])
        elif entity_kind == "phone":
            requests.extend([
                self._request("phone", seed, "Parse public numbering-plan metadata offline"),
                self._request("data_broker", seed, "Generate unverified people-search leads"),
            ])
        elif entity_kind == "file_hash":
            requests.append(
                self._request(
                    "virustotal",
                    seed,
                    "Check official hash reputation when a free VirusTotal API key is configured",
                )
            )
        elif entity_kind == "url":
            requests.extend([
                self._request("web", seed, "Fingerprint URL and redirects"),
                self._request("urlscan", seed, "Find public scan records for the URL"),
                self._request("wayback", seed, "Review historical captures"),
            ])
        elif entity_kind == "cve":
            cve = seed.upper()
            requests.extend([
                self._request("nvd_cve", cve, "Collect NVD CVE details and references"),
                self._request("cisa_kev", cve, "Check known exploited status"),
                self._request("epss", cve, "Score exploit likelihood with EPSS"),
                self._request("news", cve, "Find recent public reporting"),
            ])
        elif entity_kind == "email":
            requests.extend([
                self._request("email", seed, "Analyze address syntax and mail domain policy"),
                self._request("breach", seed, "Check lawful breach exposure sources"),
                self._request("gravatar", seed, "Check public Gravatar profile signals"),
                self._request("data_broker", seed, "Generate unverified broker review leads"),
                self._request(
                    "email_unsubscribe",
                    seed,
                    "Parse unsubscribe headers from a specific message source",
                ),
            ])
        elif entity_kind in {"address", "household"}:
            requests.extend([
                self._request("census_address", seed, "Resolve address through Census geography"),
                self._request(
                    "household_records",
                    seed,
                    "Generate address-level public-record and election-office leads",
                ),
                self._request(
                    "election_registration",
                    seed,
                    "Find official voter registration resources for the address state",
                ),
            ])
        elif entity_kind == "state":
            requests.append(
                self._request(
                    "election_registration",
                    seed,
                    "Find official voter registration and status resources",
                )
            )
        elif entity_kind == "username":
            handle = seed.lstrip("@")
            requests.extend([
                self._request("social_profiles", handle, "Generate free social profile leads"),
                self._request("username_correlation", handle, "Generate unverified handle leads"),
                self._request("youtube", handle, "Collect public YouTube channel data if resolvable"),
                self._request("github", handle, "Collect public GitHub account data"),
                self._request("gitlab", handle, "Collect public GitLab account data"),
                self._request("reddit", handle, "Collect public Reddit account data"),
                self._request("bluesky", handle, "Collect public Bluesky account data"),
                self._request("mastodon", handle, "Collect public Mastodon profile data"),
                self._request("keybase", handle, "Collect public Keybase proofs"),
                self._request("hackernews", handle, "Collect public Hacker News profile"),
            ])
        elif entity_kind in {"github", "gitlab", "reddit", "youtube", "bluesky", "mastodon"}:
            handle = seed.lstrip("@").rstrip("/").split("/")[-1]
            requests.extend([
                self._request(entity_kind, handle, f"Collect public {entity_kind} account data"),
                self._request("social_profiles", handle, "Generate cross-platform public profile leads"),
            ])
        elif entity_kind in {"person", "company", "organization"}:
            requests.extend([
                self._request("company", seed, "Search open legal entity records"),
                self._request("news", seed, "Find recent public reporting"),
                self._request("wikidata", seed, "Find public knowledge-base entities"),
                self._request("data_broker", seed, "Generate unverified people-search leads"),
            ])
        else:
            requests.extend([
                self._request("news", seed, "Find public reporting"),
                self._request("wikidata", seed, "Find public knowledge-base entities"),
            ])
        return self._dedupe_available(requests)

    def plan_case(self, entities: list[dict[str, Any]], limit: int = 50) -> list[CollectorRequest]:
        requests: list[CollectorRequest] = []
        for entity in entities:
            value = str(entity.get("value", "")).strip()
            kind = str(entity.get("kind", "")).strip()
            if not value or kind in {"urlscan_uuid", "file_hash", "steam_id", "discord_server"}:
                continue
            requests.extend(self.plan_seed(value, kind))
            if len(requests) >= limit * 2:
                break
        return self._dedupe_available(requests)[:limit]

    @staticmethod
    def classify(value: str) -> str:
        seed = value.strip()
        if re.fullmatch(r"CVE-\d{4}-\d{4,}", seed.upper()):
            return "cve"
        if civic.normalize_state(seed):
            return "state"
        if re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", seed):
            return "email"
        parsed = urlparse(seed)
        if parsed.scheme in {"http", "https"} and parsed.hostname:
            return "url"
        try:
            ipaddress.ip_address(seed)
            return "ip"
        except ValueError:
            pass
        if re.fullmatch(
            r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}",
            seed,
        ):
            return "domain"
        if any(character.isdigit() for character in seed) and "," in seed:
            return "address"
        if re.fullmatch(r"@?[A-Za-z0-9_.-]{3,50}", seed):
            return "username"
        return "person"

    @staticmethod
    def _request(collector: str, query: str, reason: str) -> CollectorRequest:
        return CollectorRequest(collector, query, reason)

    def _dedupe_available(self, requests: list[CollectorRequest]) -> list[CollectorRequest]:
        available = {collector.id for collector in self.registry.all()}
        output: list[CollectorRequest] = []
        seen: set[tuple[str, str]] = set()
        for request in requests:
            if request.collector not in available or request.key() in seen:
                continue
            seen.add(request.key())
            output.append(request)
        return output


class CampaignRunner:
    """Run a campaign through OperationManager and expand from archived entities."""

    def __init__(
        self,
        operations: OperationManager,
        planner: CampaignPlanner | None = None,
    ) -> None:
        self.operations = operations
        self.planner = planner or CampaignPlanner(operations.registry)

    async def run_seed(
        self,
        case_id: int,
        value: str,
        kind: str | None = None,
        *,
        depth: int = 1,
        concurrency: int = 3,
        max_jobs: int = 25,
    ) -> dict[str, Any]:
        seen: set[tuple[str, str]] = set()
        pending = self.planner.plan_seed(value, kind)
        waves: list[dict[str, Any]] = []

        for wave_number in range(max(1, depth + 1)):
            requests = [request for request in pending if request.key() not in seen]
            requests = requests[: max(0, max_jobs - len(seen))]
            if not requests:
                break
            for request in requests:
                seen.add(request.key())
            results = await self.operations.run_batch(
                case_id,
                [(request.collector, request.query) for request in requests],
                concurrency=concurrency,
            )
            waves.append({
                "wave": wave_number,
                "requests": [request.to_dict() for request in requests],
                "results": results,
            })
            if wave_number >= depth or len(seen) >= max_jobs:
                break
            entities = self.operations.repository.rows("entities", case_id)
            pending = self.planner.plan_case(entities, limit=max_jobs - len(seen))

        return {
            "seed": {"kind": kind or self.planner.classify(value), "value": value},
            "waves": waves,
            "job_count": len(seen),
        }
