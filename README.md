# Argus OSINT

Argus is a local-first, case-centric desktop workstation for lawful public-source research. It combines investigation management, evidence integrity, entity/link analysis, full-text search, reporting, and API-backed collectors in a modern PySide6 interface.

Argus does not bypass authentication or privacy controls. Its network modules use public pages and official APIs; services that require credentials read them from the operating-system credential vault.

## Run

Python 3.11 or newer is required.

```powershell
python -m pip install -e ".[dev]"
argus-osint
```

On first launch, Argus creates a workspace in the platform-specific user-data directory. Choose **File → Open workspace** to use another folder. Add API credentials in **Settings**.

## Included capabilities

- Create, edit, archive, reopen, duplicate, and merge investigations.
- Store notes, typed entities, confidence and verification state, relationships, timelines, bookmarks, intelligence records, tags, and audit history in SQLite/WAL.
- Ingest evidence into content-addressed managed storage, extract image/EXIF and file metadata, calculate SHA-256, verify integrity, and export manifests.
- Search across investigations, notes, entities, evidence metadata, timelines, bookmarks, and collector results with SQLite FTS5.
- Export reports as PDF, HTML, DOCX, Markdown, CSV, JSON, or text.
- Run DNS/WHOIS/RDAP, email and phone analysis, website/TLS fingerprinting, certificate transparency, GeoIP/ASN, GitHub, Steam, Discord invite, Bluesky, Mastodon, GLEIF company, GDELT news, Wayback Machine, HIBP, VirusTotal, and local file-analysis collectors.
- Keep API keys in Windows Credential Manager (or the native credential backend on other platforms).
- Discover, enable, disable, atomically install, and remove versioned plugins. Plugins execute out-of-process over JSON-RPC.
- Switch dark/light themes, rearrange dock panels, filter/sort tables, use keyboard shortcuts, drag files in as evidence, and switch workspaces.

## Data and security model

The workspace contains `argus.sqlite3`, managed `evidence/`, and optional `plugins/`. Database writes use transactions, foreign keys, WAL journaling, constraints, and audit records. Evidence is copied via a temporary file and accepted only after its hash matches the source.

Installed plugins are not automatically trusted. Argus validates archive paths and checks declared permissions and optional entrypoint checksums, then invokes plugins in an isolated Python subprocess. Declared permissions are informative on platforms without an OS sandbox; inspect third-party plugin code before enabling it.

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
