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
from urllib.parse import quote, urlparse

import httpx

from .config import SecretStore, Settings
from .db import Database
from .evidence import extract_metadata
from .repository import now


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
            json.dumps([method, url, params], sort_keys=True).encode()
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
        response = await context.request("GET", url, headers={"Accept": "text/html,*/*"})
        certificate = (
            await asyncio.to_thread(self._certificate, parsed.hostname, parsed.port or 443)
            if parsed.scheme == "https"
            else {}
        )
        body = response.text[:1_000_000]
        technologies = self._technologies(response.headers, body)
        history = [
            {
                "status": item.status_code,
                "url": str(item.url),
                "location": item.headers.get("location", ""),
            }
            for item in response.history
        ]
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
    id, name = "breach", "Have I Been Pwned"
    description, query_hint = (
        "Lawful breach exposure check using the official HIBP API",
        "name@example.com",
    )

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]:
        email = query.strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            raise ValueError("Enter a valid email address")
        key = context.secret("hibp_api_key")
        if not key:
            raise RuntimeError("Add hibp_api_key in Settings; HIBP's official API requires a key")
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}"
        try:
            data = await context.get_json(
                url,
                headers={"hibp-api-key": key},
                params={"truncateResponse": "false"},
                cache_ttl=3600,
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                data = []
            else:
                raise
        return [
            Finding(
                f"Breach exposure: {email}",
                "https://haveibeenpwned.com/",
                {"email": email, "breaches": data, "count": len(data)},
                entities=[{"kind": "email", "value": email, "verified": False}],
            )
        ]


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
        await asyncio.to_thread(self._ensure_public_server, host)
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

    @staticmethod
    def _ensure_public_server(host: str) -> None:
        for result in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM):
            address = ipaddress.ip_address(result[4][0])
            if not address.is_global:
                raise ValueError("The server must resolve only to public IP addresses")


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
