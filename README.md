# Argus OSINT

Argus is a local-first, case-centric desktop system for lawful public-source research. It combines persistent collection operations, investigation management, evidence integrity, provenance, entity/link analysis, explainable correlation, geospatial review, full-text search, reporting, and API-backed collectors in a modern PySide6 interface.

Argus does not bypass authentication or privacy controls. Its network modules use public pages, public feeds, and official APIs; services that require credentials read them from the operating-system credential vault. Argus is designed to be free to run locally with keyless collectors or free-tier/user-provided API keys; see [Free-use policy](docs/FREE_USE.md).

## Run

Python 3.11 or newer is required.

```powershell
python -m pip install -e ".[dev]"
python -m argus_osint.main
```

On first launch, Argus creates a workspace in the platform-specific user-data directory. Choose **File → Open workspace** to use another folder. Add API credentials in **Settings**.

## Included capabilities

- Create, edit, archive, reopen, duplicate, and merge investigations.
- Queue individual or batch collection jobs with bounded concurrency, durable status, progress, retry, cancellation, error records, and event history.
- Store notes, typed entities, aliases, confidence and verification state, relationships, timelines, bookmarks, comments, intelligence records, tags, locations, source provenance, and audit history in SQLite/WAL.
- Ingest evidence into content-addressed managed storage, extract image/EXIF and file metadata, calculate SHA-256, verify integrity, and export manifests.
- Search across investigations, notes, entities, evidence metadata, timelines, bookmarks, and collector results with SQLite FTS5.
- Use universal search services that normalize names, usernames, emails, phones, domains, URLs, social profile URLs, IPs, hashes, CVEs, addresses, states, crypto wallets, ASNs, and CIDR inputs into local search plus bounded collection plans.
- Generate conservative, explainable entity-correlation suggestions; an investigator must accept a suggestion before it becomes an unverified relationship.
- Navigate a service-backed enterprise desktop shell with sidebar sections, dashboard summaries, universal search, relationship graphs, unified timelines, entity enrichment profiles, inspector panels, dockable collectors, persistent layouts, and an offline geospatial observation map without leaking case coordinates to a tile provider.
- Merge duplicate entities while retaining aliases, relationships, locations, timeline references, confidence, and audit provenance.
- Export reports as PDF, HTML, DOCX, Markdown, CSV, JSON, or text.
- Export and import integrity-checked `.argus` investigation bundles containing records and verified evidence bytes, with ZIP traversal and decompression-bomb defenses.
- Run DNS/WHOIS/RDAP, email and phone analysis, safe email unsubscribe-header analysis, official election registration resource lookup, Census address/geography lookup, household public-record lead generation, website/TLS fingerprinting, security.txt, robots.txt and sitemap discovery, certificate transparency, GeoIP/ASN, NVD CVE records, CISA Known Exploited Vulnerabilities, FIRST EPSS scoring, Shodan InternetDB exposure snapshots, urlscan.io public search, GitHub, GitLab, Gravatar, Keybase, Hacker News, Reddit, YouTube public channel RSS, broad social-profile leads, Steam, Discord invite, Bluesky, Mastodon, GLEIF company, GDELT news, Wayback Machine, package-registry (PyPI/npm) metadata, breach exposure (free by default via XposedOrNot, HIBP when a key is set), VirusTotal, local file analysis, and explicitly unverified cross-platform username and data-broker correlation.
- Generate Whitepages-style people-search/data-broker review leads with manual opt-out and privacy links where known. These are exposure-management leads, not identity assertions.
- Link to official voter registration/status resources without querying voter rolls, and build household/address context from Census geography and public-record search leads without identifying residents.
- Plan and run bounded security-research campaigns from domains, IPs, URLs, CVEs, emails, usernames, people, or organisations, expanding from archived entities through the normal queued operation pipeline.
- Generate risk-prioritized security briefs that summarize collector coverage, source provenance, top security risks, and recommended next collection steps.
- Breach findings surface the exposed organisations as company and domain entities, so correlation can link a subject to the sources that leaked their data.
- Keep API keys in Windows Credential Manager (or the native credential backend on other platforms).
- Discover, enable, disable, atomically install, and remove versioned plugins. Plugins execute out-of-process over JSON-RPC.
- Switch dark/light themes, rearrange dock panels, filter/sort tables, use keyboard shortcuts, drag files in as evidence, and switch workspaces.

## Data and security model

The workspace contains `argus.sqlite3`, managed `evidence/`, and optional `plugins/`. Database writes use transactions, foreign keys, WAL journaling, constraints, and audit records. Evidence is copied via a temporary file and accepted only after its hash matches the source.

Installed plugins are not automatically trusted. Argus validates archive paths and checks declared permissions and optional entrypoint checksums, then invokes plugins in an isolated Python subprocess. Declared permissions are informative on platforms without an OS sandbox; inspect third-party plugin code before enabling it.

Checksums in an investigation bundle detect corruption but do not establish who created the bundle. Establish authenticity through a separately trusted signature or transport channel.

See [Architecture](docs/ARCHITECTURE.md) for the component and data-flow design.
See [Platform overhaul](docs/PLATFORM_OVERHAUL.md) for the staged enterprise-grade modernization plan.

## Tests

```powershell
python -m pytest
python -m ruff check .
```

## Useful shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+N` | New investigation |
| `Ctrl+E` | Add entity |
| `Ctrl+Shift+N` | Add note |
| `Ctrl+I` | Ingest evidence |
| `Ctrl+R` | Export report |
| `Ctrl+K` | Focus global search |
| `Ctrl+Shift+T` | Toggle theme |
