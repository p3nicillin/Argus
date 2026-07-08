from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse

from .campaigns import CampaignPlanner
from .repository import Repository


@dataclass(frozen=True, slots=True)
class NormalizedInput:
    raw: str
    kind: str
    value: str
    valid: bool
    confidence: float
    warnings: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class UniversalInputNormalizer:
    """Normalize public-source research seeds without asserting identity."""

    social_hosts = {
        "github.com": "github",
        "gitlab.com": "gitlab",
        "reddit.com": "reddit",
        "www.reddit.com": "reddit",
        "bsky.app": "bluesky",
        "youtube.com": "youtube",
        "www.youtube.com": "youtube",
        "youtu.be": "youtube",
        "linkedin.com": "social_profile_url",
        "www.linkedin.com": "social_profile_url",
        "x.com": "social_profile_url",
        "twitter.com": "social_profile_url",
        "instagram.com": "social_profile_url",
        "www.instagram.com": "social_profile_url",
        "tiktok.com": "social_profile_url",
        "www.tiktok.com": "social_profile_url",
        "facebook.com": "social_profile_url",
        "www.facebook.com": "social_profile_url",
        "mastodon.social": "mastodon",
    }

    def normalize(self, query: str) -> NormalizedInput:
        raw = query.strip()
        if not raw:
            return NormalizedInput(query, "unknown", "", False, 0.0, ["Search input is empty"])
        warnings: list[str] = []
        value = raw
        kind = self._classify(raw)
        valid = kind != "unknown"
        confidence = 0.9 if valid else 0.2
        if kind in {"github", "gitlab", "reddit", "youtube", "bluesky", "mastodon"}:
            value = self._profile_handle(raw) or raw.lstrip("@")
            warnings.append("Platform profile matches should be reviewed in context.")
        elif kind == "domain":
            value = raw.lower().rstrip(".")
        elif kind == "email":
            value = raw.lower()
        elif kind == "cve":
            value = raw.upper()
        elif kind == "file_hash":
            value = raw.lower()
        elif kind == "username":
            value = raw.lstrip("@")
            warnings.append("Username matches are leads, not identity proof.")
        elif kind == "social_profile_url":
            warnings.append("Public profile URLs should be reviewed manually for identity context.")
        elif kind == "address":
            warnings.append("Address searches produce geography/public-record leads, not resident identity.")
        elif kind == "voter_registration":
            warnings.append("Argus links to official resources and does not query voter rolls.")
        elif kind == "unknown":
            warnings.append("Input did not match a supported structured type; using general search.")
        return NormalizedInput(raw, kind, value, valid, confidence, warnings)

    def _classify(self, value: str) -> str:
        candidate = value.strip()
        if re.fullmatch(r"CVE-\d{4}-\d{4,}", candidate.upper()):
            return "cve"
        if re.fullmatch(r"AS\d{1,10}", candidate.upper()):
            return "asn"
        if re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", candidate):
            return "email"
        if re.fullmatch(r"@?[A-Za-z0-9_.-]{1,100}@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}", candidate):
            return "mastodon"
        try:
            ipaddress.ip_network(candidate, strict=False)
            return "cidr" if "/" in candidate else "ip"
        except ValueError:
            pass
        parsed = urlparse(candidate)
        if parsed.scheme in {"http", "https"} and parsed.hostname:
            host = parsed.hostname.lower()
            return self.social_hosts.get(host, "url")
        if re.fullmatch(r"(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})", candidate):
            return "file_hash"
        if re.fullmatch(r"0x[a-fA-F0-9]{40}", candidate):
            return "crypto_wallet"
        if re.fullmatch(r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,90}", candidate):
            return "crypto_wallet"
        if re.fullmatch(
            r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}",
            candidate,
        ):
            return "domain"
        if any(character.isdigit() for character in candidate) and "," in candidate:
            return "address"
        if candidate.casefold() in {"voter registration", "election registration"}:
            return "voter_registration"
        if re.fullmatch(r"\+?[0-9][0-9 .()/-]{6,}", candidate):
            return "phone"
        if re.fullmatch(r"@?[A-Za-z0-9_.-]{3,100}", candidate):
            return "username"
        if len(candidate) >= 2:
            return "person"
        return "unknown"

    @staticmethod
    def _profile_handle(value: str) -> str:
        parsed = urlparse(value.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return ""
        parts = [part for part in parsed.path.split("/") if part]
        if not parts:
            return ""
        if parsed.hostname in {"youtube.com", "www.youtube.com"} and parts[0] in {
            "channel",
            "c",
            "user",
        }:
            return parts[-1].lstrip("@")
        if parsed.hostname in {"youtu.be"}:
            return ""
        return parts[-1].lstrip("@")


class UniversalSearchService:
    """Plan and record universal search from one normalized input."""

    def __init__(
        self,
        repository: Repository,
        planner: CampaignPlanner | None = None,
        normalizer: UniversalInputNormalizer | None = None,
    ) -> None:
        self.repository = repository
        self.planner = planner or CampaignPlanner()
        self.normalizer = normalizer or UniversalInputNormalizer()

    def plan(self, query: str) -> dict[str, Any]:
        normalized = self.normalizer.normalize(query)
        collector_kind = self._collector_kind(normalized.kind)
        plan = (
            [request.to_dict() for request in self.planner.plan_seed(normalized.value, collector_kind)]
            if normalized.valid and collector_kind
            else []
        )
        return {
            "input": normalized.to_dict(),
            "collector_kind": collector_kind,
            "plan": plan,
            "supported": bool(plan),
        }

    def search(self, query: str, case_id: int | None = None, limit: int = 200) -> dict[str, Any]:
        local_results = self.repository.search(query, case_id, limit)
        return {
            **self.plan(query),
            "local_results": local_results,
            "local_result_count": len(local_results),
            "case_id": case_id,
        }

    @staticmethod
    def supported_inputs() -> list[str]:
        return [
            "name",
            "username",
            "email",
            "phone",
            "domain",
            "website/url",
            "ip",
            "cidr",
            "file hash",
            "organization/company",
            "social profile URL",
            "GitHub/GitLab/Reddit/YouTube handles",
            "Mastodon/Bluesky handles",
            "address/household",
            "state/election registration resources",
            "CVE",
            "ASN",
            "crypto wallet",
            "package name",
        ]

    @staticmethod
    def _collector_kind(kind: str) -> str | None:
        mapping = {
            "social_profile_url": "url",
            "voter_registration": "state",
            "github": "github",
            "gitlab": "gitlab",
            "reddit": "reddit",
            "youtube": "youtube",
            "bluesky": "bluesky",
            "mastodon": "mastodon",
            "file_hash": "file_hash",
            "crypto_wallet": None,
            "asn": None,
            "cidr": None,
        }
        return mapping.get(kind, kind)
