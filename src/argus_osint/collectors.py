from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re
import socket
import ssl
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote, urljoin, urlparse

import httpx

from . import databrokers
from .config import SecretStore, Settings
from .db import Database
from .evidence import extract_metadata
from .repository import now


def _ensure_public_host(host: str, port: int = 443) -> None:
    results = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not results:
        raise ValueError("Host did not resolve")
    for result in results:
        address = ipaddress.ip_address(result[4][0])
        if not address.is_global:
            raise ValueError("The target must resolve only to public IP addresses")


@dataclass(slots=True)
class Finding:
    title: str
    source_url: str
    data: dict[str, Any]
    confidence: float = 0.7
    entities: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Collector(Protocol):
    id: str
    name: str
    description: str
    query_hint: str

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]: ...


class CollectorContext:
    def __init__(
        self, settings: Settings, db: Database, secrets: SecretStore | None = None
    ) -> None:
        self.settings = settings
        self.db = db
        self.secrets = secrets or SecretStore()
        self._locks: dict[str, asyncio.Lock] = {}
        self._last_request: dict[str, float] = {}

    def secret(self, name: str) -> str:
        return self.secrets.get(name)

    async def get_json(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        cache_ttl: int | None = None,
    ) -> Any:
        response = await self.request(
            "GET", url, headers=headers, params=params, cache_ttl=cache_ttl
        )
        try:
            return response.json()
        except ValueError as exc:
            raise RuntimeError(f"{url} returned invalid JSON") from exc

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        cache_ttl: int | None = None,
        follow_redirects: bool = True,
    ) -> httpx.Response:
        cache_key = hashlib.sha256(
            json.dumps([method, url, params, follow_redirects, headers], sort_keys=True).encode()
        ).hexdigest()
        if method == "GET":
            cached = self.db.one(
                "SELECT value FROM cache WHERE key=? AND expires_at>?", (cache_key, now())
            )
            if cached:
                payload = json.loads(cached["value"])
                return httpx.Response(
                    payload["status"],
                    headers=payload["headers"],
                    content=bytes.fromhex(payload["body"]),
                    request=httpx.Request(method, url),
                )
        host = urlparse(url).netloc
        lock = self._locks.setdefault(host, asyncio.Lock())
        async with lock:
            current = asyncio.get_running_loop().time()
            delay = 0.25 - (current - self._last_request.get(host, 0.0))
            if delay > 0:
                await asyncio.sleep(delay)
            transport_headers = {
                "User-Agent": self.settings.user_agent,
                "Accept": "application/json, text/plain, */*",
                **(headers or {}),
            }
            proxy = self.settings.proxy or None
            async with httpx.AsyncClient(
                timeout=self.settings.request_timeout,
                verify=self.settings.verify_tls,
                proxy=proxy,
                max_redirects=self.settings.max_redirects,
            ) as client:
                last_error: Exception | None = None
                for attempt in range(3):
                    try:
                        response = await client.request(
                            method,
                            url,
                            headers=transport_headers,
                            params=params,
                            follow_redirects=follow_redirects,
                        )
                        if response.status_code == 429:
                            wait = min(float(response.headers.get("Retry-After", "2")), 30.0)
                            await asyncio.sleep(wait)
                            continue
                        response.raise_for_status()
                        break
                    except (httpx.TimeoutException, httpx.NetworkError) as exc:
                        last_error = exc
                        await asyncio.sleep(0.5 * 2**attempt)
                else:
                    raise RuntimeError(f"Network request failed for {url}: {last_error}")
            self._last_request[host] = asyncio.get_running_loop().time()
        if method == "GET" and len(response.content) <= 5_000_000:
            ttl = cache_ttl if cache_ttl is not None else self.settings.cache_ttl_seconds
            expires = (datetime.now(UTC) + timedelta(seconds=ttl)).isoformat(timespec="seconds")
            value = json.dumps(
                {
                    "status": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.content.hex(),
                }
            )
            self.db.execute(
                "INSERT OR REPLACE INTO cache(key,value,expires_at,created_at) VALUES(?,?,?,?)",
                (cache_key, value, expires, now()),
            )
        return response


class DNSCollector:
    id, name = "dns", "DNS & WHOIS"
    description, query_hint = (
        "DNS records, registration data, RDAP and reverse DNS",
        "example.com or 8.8.8.8",
    )

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]:
        query = query.strip().rstrip(".")
        try:
            address = ipaddress.ip_address(query)
        except ValueError:
            address = None
        if address:
            hostname = await asyncio.to_thread(self._reverse, query)
            data = await context.get_json(f"https://rdap.org/ip/{quote(query)}")
            return [
                Finding(
                    f"RDAP for {query}",
                    f"https://rdap.org/ip/{quote(query)}",
                    {"reverse_dns": hostname, "rdap": data},
                    entities=[{"kind": "ip", "value": query, "verified": True}],
                )
            ]
        if not re.fullmatch(
            r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}",
            query,
        ):
            raise ValueError("Enter a valid domain name or IP address")
        dns_records, registration = await asyncio.gather(
            asyncio.to_thread(self._dns, query), asyncio.to_thread(self._whois, query)
        )
        try:
            rdap = await context.get_json(f"https://rdap.org/domain/{quote(query)}")
        except Exception as exc:
            rdap = {"error": str(exc)}
        return [
            Finding(
                f"Domain intelligence: {query}",
                f"https://rdap.org/domain/{quote(query)}",
                {"dns": dns_records, "whois": registration, "rdap": rdap},
                entities=[{"kind": "domain", "value": query.lower(), "verified": True}],
            )
        ]

    @staticmethod
    def _reverse(value: str) -> str:
        try:
            return socket.gethostbyaddr(value)[0]
        except OSError:
            return ""

    @staticmethod
    def _dns(domain: str) -> dict[str, list[str]]:
        try:
            import dns.resolver
        except ImportError as exc:
            raise RuntimeError("DNS collection requires dnspython") from exc
        result: dict[str, list[str]] = {}
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 8
        for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA"):
            try:
                answers = resolver.resolve(domain, record_type)
                result[record_type] = [answer.to_text().strip('"') for answer in answers]
            except Exception:
                result[record_type] = []
        return result

    @staticmethod
    def _whois(domain: str) -> dict[str, Any]:
        try:
            import whois
        except ImportError:
            return {"unavailable": "Install python-whois for registry WHOIS data"}
        try:
            value = whois.whois(domain)
            return {
                key: _json_safe(item)
                for key, item in dict(value).items()
                if item not in (None, "", [])
            }
        except Exception as exc:
            return {"error": str(exc)}


class WebCollector:
    id, name = "web", "Website fingerprint"
    description, query_hint = (
        "Redirects, HTTP headers, TLS certificate and technology signals",
        "https://example.com",
    )

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]:
        url = query.strip()
        if not urlparse(url).scheme:
            url = "https://" + url
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Enter a valid HTTP or HTTPS URL")
        history: list[dict[str, Any]] = []
        current_url = url
        for redirect_count in range(context.settings.max_redirects + 1):
            current = urlparse(current_url)
            if current.scheme not in {"http", "https"} or not current.hostname:
                raise ValueError("A redirect left the HTTP/HTTPS public web")
            await asyncio.to_thread(
                _ensure_public_host,
                current.hostname,
                current.port or (443 if current.scheme == "https" else 80),
            )
            response = await context.request(
                "GET",
                current_url,
                headers={"Accept": "text/html,*/*"},
                follow_redirects=False,
            )
            if not response.is_redirect:
                break
            location = response.headers.get("location")
            if not location:
                break
            history.append(
                {"status": response.status_code, "url": current_url, "location": location}
            )
            current_url = urljoin(current_url, location)
            if redirect_count == context.settings.max_redirects:
                raise RuntimeError("Website exceeded the configured redirect limit")
        final = urlparse(str(response.url))
        certificate = (
            await asyncio.to_thread(self._certificate, final.hostname, final.port or 443)
            if final.scheme == "https" and final.hostname
            else {}
        )
        body = response.text[:1_000_000]
        technologies = self._technologies(response.headers, body)
        data = {
            "final_url": str(response.url),
            "status": response.status_code,
            "redirects": history,
            "headers": dict(response.headers),
            "tls_certificate": certificate,
            "technology_signals": technologies,
            "title": self._title(body),
        }
        return [
            Finding(
                f"Website fingerprint: {parsed.hostname}",
                str(response.url),
                data,
                entities=[
                    {"kind": "url", "value": str(response.url), "verified": True},
                    {"kind": "domain", "value": parsed.hostname, "verified": True},
                ],
            )
        ]

    @staticmethod
    def _certificate(hostname: str, port: int) -> dict[str, Any]:
        context = ssl.create_default_context()
        with (
            socket.create_connection((hostname, port), timeout=10) as raw,
            context.wrap_socket(raw, server_hostname=hostname) as secure,
        ):
            cert = secure.getpeercert()
            cipher = secure.cipher()
        return {
            "subject": cert.get("subject"),
            "issuer": cert.get("issuer"),
            "serialNumber": cert.get("serialNumber"),
            "notBefore": cert.get("notBefore"),
            "notAfter": cert.get("notAfter"),
            "subjectAltName": cert.get("subjectAltName"),
            "cipher": cipher,
        }

    @staticmethod
    def _technologies(headers: httpx.Headers, body: str) -> list[str]:
        values: set[str] = set()
        for name in ("server", "x-powered-by", "x-generator"):
            if headers.get(name):
                values.add(headers[name])
        patterns = {
            "WordPress": r"wp-(?:content|includes)",
            "Drupal": r"Drupal.settings|/sites/default/files",
            "Joomla": r"/media/system/js/|option=com_",
            "React": r"data-reactroot|__NEXT_DATA__",
            "Angular": r"ng-version=|<app-root",
            "Vue": r"data-v-|__NUXT__",
            "Google Analytics": r"googletagmanager.com|google-analytics.com",
        }
        for name, pattern in patterns.items():
            if re.search(pattern, body, re.I):
                values.add(name)
        return sorted(values)

    @staticmethod
    def _title(body: str) -> str:
        match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        return re.sub(r"\s+", " ", match.group(1)).strip()[:500] if match else ""


class CertificateTransparencyCollector:
    id, name = "certificate_transparency", "Certificate transparency"
    description, query_hint = (
        "Public certificates and discovered subdomains via crt.sh",
        "example.com",
    )

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]:
        domain = query.strip().lower().rstrip(".")
        data = await context.get_json(
            "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, cache_ttl=1800
        )
        names = sorted(
            {
                name.lower()
                for item in data
                for name in item.get("name_value", "").splitlines()
                if "*" not in name
            }
        )
        return [
            Finding(
                f"Certificate transparency: {domain}",
                f"https://crt.sh/?q={quote('%.' + domain)}",
                {"certificate_count": len(data), "names": names, "certificates": data[:1000]},
                entities=[
                    {"kind": "domain", "value": name, "verified": False} for name in names[:250]
                ],
            )
        ]


class IPCollector:
    id, name = "ip", "IP & ASN intelligence"
    description, query_hint = "Public GeoIP, routing, ASN and reverse-DNS context", "8.8.8.8"

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]:
        ip = str(ipaddress.ip_address(query.strip()))
        if ipaddress.ip_address(ip).is_private:
            raise ValueError("Public IP intelligence is not available for private addresses")
        data = await context.get_json(f"https://ipwho.is/{quote(ip)}")
        reverse = await asyncio.to_thread(DNSCollector._reverse, ip)
        return [
            Finding(
                f"IP intelligence: {ip}",
                f"https://ipwho.is/{quote(ip)}",
                {**data, "reverse_dns": reverse},
                entities=[
                    {"kind": "ip", "value": ip, "verified": True},
                    *([{"kind": "domain", "value": reverse, "verified": True}] if reverse else []),
                ],
            )
        ]


class GitHubCollector:
    id, name = "github", "GitHub profile"
    description, query_hint = (
        "Public account, repositories, events, organizations and social links",
        "username",
    )

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]:
        username = query.strip().lstrip("@").split("/")[-1]
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", username):
            raise ValueError("Enter a valid GitHub username")
        token = context.secret("github_token")
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        base = f"https://api.github.com/users/{quote(username)}"
        profile, repos, events, orgs = await asyncio.gather(
            *[
                context.get_json(url, headers=headers, cache_ttl=900)
                for url in (
                    base,
                    base + "/repos?per_page=100&sort=updated",
                    base + "/events/public?per_page=100",
                    base + "/orgs?per_page=100",
                )
            ]
        )
        data = {
            "profile": profile,
            "repositories": repos,
            "public_events": events,
            "organizations": orgs,
        }
        return [
            Finding(
                f"GitHub: {profile.get('login', username)}",
                profile.get("html_url", f"https://github.com/{username}"),
                data,
                entities=[
                    {
                        "kind": "username",
                        "value": profile.get("login", username),
                        "display_name": profile.get("name") or "",
                        "verified": True,
                    },
                    *(
                        [{"kind": "email", "value": profile["email"], "verified": True}]
                        if profile.get("email")
                        else []
                    ),
                ],
            )
        ]


class UsernameCorrelationCollector:
    id, name = "username_correlation", "Username correlation"
    description, query_hint = (
        "Builds cross-platform candidates without claiming matching names share an identity",
        "username",
    )
    templates = {
        "X": "https://x.com/{name}",
        "Facebook": "https://www.facebook.com/{name}",
        "Instagram": "https://www.instagram.com/{name}/",
        "Reddit": "https://www.reddit.com/user/{name}/",
        "TikTok": "https://www.tiktok.com/@{name}",
        "YouTube": "https://www.youtube.com/@{name}",
        "LinkedIn": "https://www.linkedin.com/in/{name}/",
        "GitHub": "https://github.com/{name}",
        "Twitch": "https://www.twitch.tv/{name}",
        "Telegram": "https://t.me/{name}",
        "Bluesky": "https://bsky.app/profile/{name}",
        "Pinterest": "https://www.pinterest.com/{name}/",
        "Snapchat": "https://www.snapchat.com/add/{name}",
    }

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]:
        username = query.strip().lstrip("@").rstrip("/")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", username):
            raise ValueError("Enter a syntactically valid username")
        candidates = [
            {
                "platform": platform,
                "url": template.format(name=quote(username)),
                "status": "unverified candidate",
                "identity_match": False,
            }
            for platform, template in self.templates.items()
        ]
        return [
            Finding(
                f"Username candidates: {username}",
                "",
                {
                    "warning": "Matching usernames alone do not establish a shared identity.",
                    "candidates": candidates,
                },
                confidence=0.2,
                entities=[{"kind": "username", "value": username, "verified": False}],
            )
        ]


class SteamCollector:
    id, name = "steam", "Steam profile"
    description, query_hint = (
        "Official Steam Web API profile, friends, games, groups and achievements",
        "SteamID64 or vanity name",
    )

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]:
        key = context.secret("steam_api_key")
        if not key:
            raise RuntimeError(
                "Add steam_api_key in Settings; Steam's official Web API requires a key"
            )
        value = query.strip().rstrip("/").split("/")[-1]
        steam_id = value
        if not value.isdigit():
            resolution = await context.get_json(
                "https://api.steampowered.com/ISteamUser/ResolveVanityURL/v1/",
                params={"key": key, "vanityurl": value},
            )
            steam_id = str(resolution.get("response", {}).get("steamid", ""))
            if not steam_id:
                raise ValueError("Steam vanity name was not found")
        endpoints = {
            "profile": (
                "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/",
                {"key": key, "steamids": steam_id},
            ),
            "friends": (
                "https://api.steampowered.com/ISteamUser/GetFriendList/v1/",
                {"key": key, "steamid": steam_id, "relationship": "friend"},
            ),
            "games": (
                "https://api.steampowered.com/IPlayerService/GetOwnedGames/v1/",
                {
                    "key": key,
                    "steamid": steam_id,
                    "include_appinfo": 1,
                    "include_played_free_games": 1,
                },
            ),
            "recent_games": (
                "https://api.steampowered.com/IPlayerService/GetRecentlyPlayedGames/v1/",
                {"key": key, "steamid": steam_id},
            ),
            "badges": (
                "https://api.steampowered.com/IPlayerService/GetBadges/v1/",
                {"key": key, "steamid": steam_id},
            ),
            "groups": (
                "https://api.steampowered.com/ISteamUser/GetUserGroupList/v1/",
                {"key": key, "steamid": steam_id},
            ),
        }

        async def safely(url: str, params: dict[str, Any]) -> Any:
            try:
                return await context.get_json(url, params=params, cache_ttl=600)
            except Exception as exc:
                return {"unavailable": str(exc)}

        values = await asyncio.gather(*(safely(url, params) for url, params in endpoints.values()))
        data = dict(zip(endpoints, values, strict=True))
        players = data.get("profile", {}).get("response", {}).get("players", [])
        profile = players[0] if players else {}
        return [
            Finding(
                f"Steam: {profile.get('personaname', steam_id)}",
                profile.get("profileurl", f"https://steamcommunity.com/profiles/{steam_id}"),
                data,
                entities=[
                    {
                        "kind": "steam_id",
                        "value": steam_id,
                        "display_name": profile.get("personaname", ""),
                        "verified": True,
                    }
                ],
            )
        ]


class DiscordInviteCollector:
    id, name = "discord_invite", "Discord invite"
    description, query_hint = (
        "Public server and invite metadata from Discord's official API",
        "invite code or URL",
    )

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]:
        code = query.strip().rstrip("/").split("/")[-1]
        if not re.fullmatch(r"[A-Za-z0-9_-]{2,64}", code):
            raise ValueError("Enter a valid Discord invite code or URL")
        url = f"https://discord.com/api/v10/invites/{quote(code)}"
        data = await context.get_json(
            url, params={"with_counts": "true", "with_expiration": "true"}, cache_ttl=300
        )
        guild = data.get("guild", {})
        entities = [{"kind": "discord_invite", "value": code, "verified": True}]
        if guild.get("id"):
            entities.append(
                {
                    "kind": "discord_server",
                    "value": guild["id"],
                    "display_name": guild.get("name", ""),
                    "verified": True,
                }
            )
        return [
            Finding(
                f"Discord invite: {guild.get('name', code)}",
                f"https://discord.gg/{code}",
                data,
                entities=entities,
            )
        ]


class BreachCollector:
    id, name = "breach", "Breach exposure"
    description, query_hint = (
        "Lawful breach exposure check. Uses the free XposedOrNot service by "
        "default; uses the official HIBP API automatically when a key is set.",
        "name@example.com",
    )

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]:
        email = query.strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            raise ValueError("Enter a valid email address")
        key = context.secret("hibp_api_key")
        if key:
            breaches, source = await self._hibp(email, key, context), "https://haveibeenpwned.com/"
        else:
            breaches, source = await self._xposedornot(email, context), "https://xposedornot.com/"
        return [
            Finding(
                f"Breach exposure: {email}",
                source,
                {"email": email, "breaches": breaches, "count": len(breaches)},
                entities=self._entities(email, breaches),
            )
        ]

    @staticmethod
    def _entities(email: str, breaches: list) -> list[dict[str, Any]]:
        # The email plus the breached companies/domains, so correlation can link
        # a subject to the organisations that exposed their data.
        entities: list[dict[str, Any]] = [
            {"kind": "email", "value": email, "verified": False}
        ]
        seen: set[tuple[str, str]] = set()
        for breach in breaches:
            name = breach.get("Name") or breach.get("Title")
            if name and ("company", name) not in seen:
                seen.add(("company", name))
                entities.append({"kind": "company", "value": name, "verified": False})
            domain = breach.get("Domain")
            if domain and ("domain", domain) not in seen:
                seen.add(("domain", domain))
                entities.append({"kind": "domain", "value": domain, "verified": False})
        return entities

    @staticmethod
    async def _hibp(email: str, key: str, context: CollectorContext) -> list:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}"
        try:
            return await context.get_json(
                url,
                headers={"hibp-api-key": key},
                params={"truncateResponse": "false"},
                cache_ttl=3600,
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return []
            raise

    @staticmethod
    async def _xposedornot(email: str, context: CollectorContext) -> list:
        # Free, no API key. 404 = the address is not in any known breach.
        url = f"https://api.xposedornot.com/v1/breach-analytics?email={quote(email)}"
        try:
            data = await context.get_json(url, cache_ttl=3600)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return []
            raise
        details = ((data or {}).get("ExposedBreaches") or {}).get("breaches_details") or []
        return [
            {
                "Name": d.get("breach", ""),
                "Title": d.get("breach", ""),
                "Domain": d.get("domain", ""),
                "BreachDate": str(d.get("xposed_date", "")),
                "PwnCount": d.get("xposed_records", 0),
                "DataClasses": [x.strip() for x in
                                str(d.get("xposed_data", "")).split(";") if x.strip()],
                "Description": d.get("details", ""),
                "IsVerified": str(d.get("verified", "")).lower() == "true",
            }
            for d in details
        ]


class DataBrokerCollector:
    id, name = "data_broker", "Data broker exposure"
    description, query_hint = (
        "People-search and data-broker sites that may list the subject. Each "
        "result is an unverified lead for public-records review, not a match.",
        "Full name or email",
    )

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]:
        leads = databrokers.candidate_links(query)
        subject = query.strip()
        entity_kind = "email" if "@" in subject else "person"
        return [
            Finding(
                f"Data-broker candidates: {subject}",
                "",
                {
                    "warning": "A listing on these sites does not establish that a "
                               "record belongs to the subject; review each source.",
                    "candidates": leads,
                },
                confidence=0.2,
                entities=[{"kind": entity_kind, "value": subject, "verified": False}],
            )
        ]


class GravatarCollector:
    id, name = "gravatar", "Gravatar profile"
    description, query_hint = (
        "Public Gravatar avatar and self-declared profile linked to an email hash",
        "name@example.com",
    )

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]:
        email = query.strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            raise ValueError("Enter a valid email address")
        digest = hashlib.md5(email.encode("utf-8")).hexdigest()  # noqa: S324 (gravatar id, not security)
        avatar = f"https://www.gravatar.com/avatar/{digest}?d=404"
        try:
            profile = await context.get_json(
                f"https://www.gravatar.com/{digest}.json", cache_ttl=3600
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                profile = None
            else:
                raise
        entries = (profile or {}).get("entry") or []
        entry = entries[0] if entries else None
        entities: list[dict[str, Any]] = [
            {"kind": "email", "value": email, "verified": False}
        ]
        for account in (entry or {}).get("accounts", []) or []:
            handle = account.get("username") or account.get("display")
            if handle:
                entities.append({
                    "kind": "username", "value": handle,
                    "display_name": account.get("shortname", ""), "verified": False,
                })
        return [
            Finding(
                f"Gravatar: {email}",
                f"https://gravatar.com/{digest}",
                {"email_md5": digest, "avatar_url": avatar,
                 "exists": bool(entry), "profile": entry},
                confidence=0.5 if entry else 0.2,
                entities=entities,
            )
        ]


class KeybaseCollector:
    id, name = "keybase", "Keybase profile"
    description, query_hint = (
        "Public Keybase identity, proofs and linked accounts",
        "username",
    )

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]:
        username = query.strip().lstrip("@")
        if not re.fullmatch(r"[A-Za-z0-9_]{1,50}", username):
            raise ValueError("Enter a valid Keybase username")
        data = await context.get_json(
            f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={quote(username)}",
            cache_ttl=900,
        )
        them = (data or {}).get("them") or []
        who = them[0] if them else None
        entities: list[dict[str, Any]] = [
            {"kind": "username", "value": username, "verified": bool(who)}
        ]
        proofs = []
        for proof in ((who or {}).get("proofs_summary", {}) or {}).get("all", []) or []:
            proofs.append({
                "platform": proof.get("proof_type"),
                "handle": proof.get("nametag"),
                "url": proof.get("service_url"),
            })
            if proof.get("nametag"):
                entities.append({
                    "kind": "username", "value": proof["nametag"],
                    "display_name": proof.get("proof_type", ""), "verified": False,
                })
        return [
            Finding(
                f"Keybase: {username}",
                f"https://keybase.io/{username}",
                {"found": bool(who), "basics": (who or {}).get("basics"),
                 "proofs": proofs},
                confidence=0.6 if who else 0.2,
                entities=entities,
            )
        ]


class HackerNewsCollector:
    id, name = "hackernews", "Hacker News profile"
    description, query_hint = (
        "Public Hacker News user profile, karma and account age",
        "username",
    )

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]:
        username = query.strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{2,15}", username):
            raise ValueError("Enter a valid Hacker News username")
        data = await context.get_json(
            f"https://hacker-news.firebaseio.com/v0/user/{quote(username)}.json",
            cache_ttl=900,
        )
        found = bool(data)
        return [
            Finding(
                f"Hacker News: {username}",
                f"https://news.ycombinator.com/user?id={quote(username)}",
                {"found": found, "profile": data or {}},
                confidence=0.5 if found else 0.2,
                entities=[{"kind": "username", "value": username, "verified": found}],
            )
        ]


class RedditCollector:
    id, name = "reddit", "Reddit profile"
    description, query_hint = (
        "Public Reddit account profile, karma and account age",
        "username",
    )

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]:
        username = query.strip().lstrip("@").removeprefix("u/").removeprefix("/u/")
        if not re.fullmatch(r"[A-Za-z0-9_-]{3,20}", username):
            raise ValueError("Enter a valid Reddit username")
        try:
            data = await context.get_json(
                f"https://www.reddit.com/user/{quote(username)}/about.json",
                headers={"User-Agent": "ArgusOSINT/1.0 (public-source research)"},
                cache_ttl=900,
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (403, 404):
                data = {}
            else:
                raise
        profile = (data or {}).get("data") or {}
        found = bool(profile)
        return [
            Finding(
                f"Reddit: u/{username}",
                f"https://www.reddit.com/user/{username}",
                {"found": found, "profile": profile},
                confidence=0.5 if found else 0.2,
                entities=[{"kind": "username", "value": username, "verified": found}],
            )
        ]


class GitLabCollector:
    id, name = "gitlab", "GitLab profile"
    description, query_hint = (
        "Public GitLab user account and projects",
        "username",
    )

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]:
        username = query.strip().lstrip("@")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", username):
            raise ValueError("Enter a valid GitLab username")
        users = await context.get_json(
            f"https://gitlab.com/api/v4/users?username={quote(username)}",
            cache_ttl=900,
        )
        if not users:
            return [
                Finding(
                    f"GitLab: {username}",
                    f"https://gitlab.com/{username}",
                    {"found": False},
                    confidence=0.2,
                    entities=[{"kind": "username", "value": username, "verified": False}],
                )
            ]
        user = users[0]
        projects = await context.get_json(
            f"https://gitlab.com/api/v4/users/{user['id']}/projects?per_page=100",
            cache_ttl=900,
        )
        return [
            Finding(
                f"GitLab: {user.get('username', username)}",
                user.get("web_url", f"https://gitlab.com/{username}"),
                {"found": True, "profile": user, "projects": projects},
                entities=[{
                    "kind": "username",
                    "value": user.get("username", username),
                    "display_name": user.get("name", ""),
                    "verified": True,
                }],
            )
        ]


class PackageRegistryCollector:
    id, name = "package_registry", "Package registry (PyPI/npm)"
    description, query_hint = (
        "Public package metadata and maintainers on PyPI and npm",
        "package name",
    )

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]:
        pkg = query.strip()
        if not re.fullmatch(r"[A-Za-z0-9._@/-]{1,120}", pkg):
            raise ValueError("Enter a valid package name")
        findings: list[Finding] = []

        try:
            data = await context.get_json(
                f"https://pypi.org/pypi/{quote(pkg)}/json", cache_ttl=3600
            )
            info = (data or {}).get("info") or {}
            if info:
                findings.append(Finding(
                    f"PyPI: {info.get('name', pkg)}",
                    f"https://pypi.org/project/{pkg}/",
                    {"registry": "pypi", "info": info},
                    confidence=0.6,
                    entities=self._people(info.get("author"), info.get("author_email")),
                ))
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 404:
                raise

        try:
            data = await context.get_json(
                f"https://registry.npmjs.org/{quote(pkg, safe='@/')}", cache_ttl=3600
            )
            if data and not data.get("error") and data.get("name"):
                author = data.get("author") if isinstance(data.get("author"), dict) else {}
                findings.append(Finding(
                    f"npm: {data.get('name', pkg)}",
                    f"https://www.npmjs.com/package/{pkg}",
                    {"registry": "npm", "name": data.get("name"),
                     "description": data.get("description"),
                     "maintainers": data.get("maintainers"), "author": author},
                    confidence=0.6,
                    entities=self._people(author.get("name"), author.get("email")),
                ))
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 404:
                raise

        if not findings:
            findings.append(Finding(
                f"Package not found: {pkg}", "", {"found": False}, confidence=0.1
            ))
        return findings

    @staticmethod
    def _people(name: str | None, email: str | None) -> list[dict[str, Any]]:
        entities: list[dict[str, Any]] = []
        if name:
            entities.append({"kind": "person", "value": name, "verified": False})
        if email:
            entities.append({"kind": "email", "value": email, "verified": False})
        return entities


class FileCollector:
    id, name = "file", "File metadata & hashes"
    description, query_hint = (
        "Local file SHA hashes, MIME details and EXIF metadata",
        "C:\\path\\to\\file",
    )

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]:
        path = Path(query.strip().strip('"')).expanduser().resolve(strict=True)
        if not path.is_file():
            raise ValueError("Select a local file")

        def inspect() -> dict[str, Any]:
            data = extract_metadata(path)
            data["hashes"] = {}
            for algorithm in ("md5", "sha1", "sha256", "sha512"):
                digest = hashlib.new(algorithm)
                with path.open("rb") as stream:
                    while chunk := stream.read(1024 * 1024):
                        digest.update(chunk)
                data["hashes"][algorithm] = digest.hexdigest()
            return data

        data = await asyncio.to_thread(inspect)
        return [
            Finding(
                f"File analysis: {path.name}",
                path.as_uri(),
                data,
                confidence=1.0,
                entities=[
                    {"kind": "file_hash", "value": data["hashes"]["sha256"], "verified": True}
                ],
            )
        ]


class MalwareHashCollector:
    id, name = "virustotal", "VirusTotal hash reputation"
    description, query_hint = (
        "Official VirusTotal API reputation for a known file hash",
        "SHA-256 hash",
    )

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]:
        digest = query.strip().lower()
        if not re.fullmatch(r"(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})", digest):
            raise ValueError("Enter an MD5, SHA-1 or SHA-256 hash")
        key = context.secret("virustotal_api_key")
        if not key:
            raise RuntimeError(
                "Add virustotal_api_key in Settings; VirusTotal's official API requires a key"
            )
        url = f"https://www.virustotal.com/api/v3/files/{digest}"
        data = await context.get_json(url, headers={"x-apikey": key}, cache_ttl=1800)
        return [
            Finding(
                f"VirusTotal: {digest}",
                f"https://www.virustotal.com/gui/file/{digest}",
                data,
                entities=[{"kind": "file_hash", "value": digest, "verified": True}],
            )
        ]


class EmailCollector:
    id, name = "email", "Email analysis"
    description, query_hint = (
        "Syntax, mail routing, domain policy and privacy-preserving avatar signals",
        "name@example.com",
    )

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]:
        email = query.strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            raise ValueError("Enter a valid email address")
        local_part, domain = email.rsplit("@", 1)
        records = await asyncio.to_thread(DNSCollector._dns, domain)
        gravatar_hash = hashlib.md5(email.encode(), usedforsecurity=False).hexdigest()
        data = {
            "address": email,
            "local_part": local_part,
            "domain": domain,
            "dns": records,
            "has_mail_exchanger": bool(records.get("MX")),
            "gravatar_profile": f"https://gravatar.com/{gravatar_hash}.json",
            "gravatar_avatar": f"https://www.gravatar.com/avatar/{gravatar_hash}?d=404",
            "note": "Avatar URLs are deterministic lookups, not proof of account ownership.",
        }
        return [
            Finding(
                f"Email analysis: {email}",
                f"https://rdap.org/domain/{quote(domain)}",
                data,
                entities=[
                    {"kind": "email", "value": email, "verified": False},
                    {"kind": "domain", "value": domain, "verified": True},
                ],
            )
        ]


class PhoneCollector:
    id, name = "phone", "Phone number analysis"
    description, query_hint = (
        "Offline parsing, validation, geography, carrier and timezone metadata",
        "+44 20 7946 0958",
    )

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]:
        try:
            import phonenumbers
            from phonenumbers import carrier, geocoder, timezone
        except ImportError as exc:
            raise RuntimeError("Phone analysis requires phonenumbers") from exc
        try:
            number = phonenumbers.parse(query.strip(), None)
        except phonenumbers.NumberParseException as exc:
            raise ValueError(f"Invalid international phone number: {exc}") from exc
        if not phonenumbers.is_possible_number(number):
            raise ValueError("The number is not possible for its numbering plan")
        e164 = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)
        data = {
            "e164": e164,
            "international": phonenumbers.format_number(
                number, phonenumbers.PhoneNumberFormat.INTERNATIONAL
            ),
            "national": phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.NATIONAL),
            "valid": phonenumbers.is_valid_number(number),
            "region_code": phonenumbers.region_code_for_number(number),
            "number_type": phonenumbers.PhoneNumberType.to_string(phonenumbers.number_type(number)),
            "description": geocoder.description_for_number(number, "en"),
            "carrier": carrier.name_for_number(number, "en"),
            "timezones": list(timezone.time_zones_for_number(number)),
            "note": "Number-plan metadata does not identify a subscriber or prove current ownership.",
        }
        return [
            Finding(
                f"Phone analysis: {e164}",
                "https://github.com/daviddrysdale/python-phonenumbers",
                data,
                confidence=1.0,
                entities=[{"kind": "phone", "value": e164, "verified": False}],
            )
        ]


class BlueskyCollector:
    id, name = "bluesky", "Bluesky profile"
    description, query_hint = (
        "Public profile and recent author feed via Bluesky's public AppView API",
        "handle.bsky.social",
    )

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]:
        actor = query.strip().lstrip("@").rstrip("/").split("/")[-1]
        if not actor or len(actor) > 253:
            raise ValueError("Enter a Bluesky handle or DID")
        base = "https://public.api.bsky.app/xrpc/"
        profile, feed = await asyncio.gather(
            context.get_json(
                base + "app.bsky.actor.getProfile", params={"actor": actor}, cache_ttl=600
            ),
            context.get_json(
                base + "app.bsky.feed.getAuthorFeed",
                params={"actor": actor, "limit": 100, "filter": "posts_with_replies"},
                cache_ttl=300,
            ),
        )
        handle = profile.get("handle", actor)
        return [
            Finding(
                f"Bluesky: {profile.get('displayName') or handle}",
                f"https://bsky.app/profile/{quote(handle)}",
                {"profile": profile, "author_feed": feed.get("feed", [])},
                entities=[
                    {
                        "kind": "username",
                        "value": handle,
                        "display_name": profile.get("displayName", ""),
                        "verified": True,
                        "attributes": {"platform": "Bluesky", "did": profile.get("did", "")},
                    }
                ],
            )
        ]


class MastodonCollector:
    id, name = "mastodon", "Mastodon profile"
    description, query_hint = (
        "Public federated profile and statuses from the account's Mastodon server",
        "username@mastodon.social",
    )

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]:
        address = query.strip().lstrip("@")
        if "@" not in address:
            raise ValueError("Use a full federated address such as username@mastodon.social")
        username, host = address.rsplit("@", 1)
        if not username or not re.fullmatch(
            r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}",
            host,
        ):
            raise ValueError("Enter a valid Mastodon account address")
        await asyncio.to_thread(_ensure_public_host, host)
        api = f"https://{host}/api/v1"
        profile = await context.get_json(
            api + "/accounts/lookup", params={"acct": username}, cache_ttl=600
        )
        statuses = await context.get_json(
            api + f"/accounts/{quote(str(profile['id']))}/statuses",
            params={"limit": 40, "exclude_replies": "false"},
            cache_ttl=300,
        )
        return [
            Finding(
                f"Mastodon: {profile.get('display_name') or address}",
                profile.get("url", f"https://{host}/@{username}"),
                {"profile": profile, "statuses": statuses},
                entities=[
                    {
                        "kind": "username",
                        "value": address,
                        "display_name": profile.get("display_name", ""),
                        "verified": True,
                        "attributes": {"platform": "Mastodon", "account_id": profile["id"]},
                    }
                ],
            )
        ]


class CompanyCollector:
    id, name = "company", "Company & LEI search"
    description, query_hint = (
        "Open legal-entity, address, registration and relationship data from GLEIF",
        "Company name or LEI",
    )

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]:
        value = query.strip()
        if len(value) < 2:
            raise ValueError("Enter a company name or LEI")
        params = {"page[size]": 50}
        if re.fullmatch(r"[A-Z0-9]{18}[0-9]{2}", value.upper()):
            url = f"https://api.gleif.org/api/v1/lei-records/{quote(value.upper())}"
        else:
            url = "https://api.gleif.org/api/v1/lei-records"
            params["filter[fulltext]"] = value
        payload = await context.get_json(url, params=params, cache_ttl=3600)
        records = payload.get("data", [])
        if isinstance(records, dict):
            records = [records]
        entities = []
        for record in records:
            attributes = record.get("attributes", {})
            legal_name = attributes.get("entity", {}).get("legalName", {}).get("name", "")
            entities.append(
                {
                    "kind": "company",
                    "value": record.get("id", legal_name),
                    "display_name": legal_name,
                    "verified": True,
                    "attributes": {"lei": record.get("id", "")},
                }
            )
        return [
            Finding(
                f"GLEIF company search: {value}",
                "https://www.gleif.org/en/lei-search",
                {"records": records, "meta": payload.get("meta", {})},
                entities=entities,
            )
        ]


class NewsCollector:
    id, name = "news", "Public news search"
    description, query_hint = (
        "Recent multilingual news coverage indexed by the GDELT DOC API",
        "organization, person, domain or topic",
    )

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]:
        value = query.strip()
        if len(value) < 2:
            raise ValueError("Enter a news search query")
        url = "https://api.gdeltproject.org/api/v2/doc/doc"
        data = await context.get_json(
            url,
            params={
                "query": value,
                "mode": "artlist",
                "maxrecords": 250,
                "format": "json",
                "sort": "datedesc",
            },
            cache_ttl=900,
        )
        articles = data.get("articles", [])
        return [
            Finding(
                f"News search: {value}",
                f"https://api.gdeltproject.org/api/v2/doc/doc?query={quote(value)}&mode=artlist",
                {"article_count": len(articles), "articles": articles},
                confidence=0.6,
            )
        ]


class WaybackCollector:
    id, name = "wayback", "Website archives"
    description, query_hint = (
        "Historical public captures from the Internet Archive Wayback Machine",
        "https://example.com/*",
    )

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]:
        value = query.strip()
        if not value:
            raise ValueError("Enter a URL or domain")
        data = await context.get_json(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": value,
                "output": "json",
                "fl": "timestamp,original,statuscode,mimetype,digest",
                "filter": "statuscode:200",
                "collapse": "digest",
                "limit": 1000,
            },
            cache_ttl=1800,
        )
        header, *values = (
            data if data else [["timestamp", "original", "statuscode", "mimetype", "digest"]]
        )
        captures = [dict(zip(header, row, strict=False)) for row in values]
        for capture in captures:
            capture["archive_url"] = (
                f"https://web.archive.org/web/{capture['timestamp']}/{capture['original']}"
            )
        return [
            Finding(
                f"Wayback captures: {value}",
                f"https://web.archive.org/web/*/{value}",
                {"capture_count": len(captures), "captures": captures},
                confidence=1.0,
            )
        ]


def _json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    return str(value)


class CollectorRegistry:
    def __init__(self) -> None:
        self._collectors: dict[str, Collector] = {}
        for collector in (
            DNSCollector(),
            EmailCollector(),
            PhoneCollector(),
            WebCollector(),
            CertificateTransparencyCollector(),
            IPCollector(),
            GitHubCollector(),
            UsernameCorrelationCollector(),
            SteamCollector(),
            DiscordInviteCollector(),
            BlueskyCollector(),
            MastodonCollector(),
            CompanyCollector(),
            NewsCollector(),
            WaybackCollector(),
            BreachCollector(),
            DataBrokerCollector(),
            GravatarCollector(),
            KeybaseCollector(),
            HackerNewsCollector(),
            RedditCollector(),
            GitLabCollector(),
            PackageRegistryCollector(),
            FileCollector(),
            MalwareHashCollector(),
        ):
            self.register(collector)

    def register(self, collector: Collector) -> None:
        if not collector.id or collector.id in self._collectors:
            raise ValueError(f"Duplicate or empty collector id: {collector.id}")
        self._collectors[collector.id] = collector

    def all(self) -> list[Collector]:
        return sorted(self._collectors.values(), key=lambda item: item.name.lower())

    def get(self, collector_id: str) -> Collector:
        try:
            return self._collectors[collector_id]
        except KeyError as exc:
            raise KeyError(f"Unknown collector: {collector_id}") from exc
