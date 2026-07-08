# Argus architecture

Argus is deliberately local-first. An investigation can contain sensitive working notes even when every collected source is public, so the application does not send case data to a hosted Argus service.

## Component boundaries

- `db.py` owns SQLite connections, schema constraints, WAL configuration, and transactional access. Each worker receives a thread-local connection; shutdown waits for workers and closes every tracked connection.
- `repository.py` is the only domain write surface used by the UI and services. It maintains audit records and the FTS5 index alongside case records.
- `app_services.py` is the desktop composition root. It wires settings, SQLite, repository, collector registry, HTTP context, operations, campaign planning, reporting, universal search, dashboard, graph, timeline, enrichment, and security brief services.
- `universal.py` normalizes mixed OSINT/security inputs into stable seed types and pairs local FTS search with bounded collection plans.
- `workspace.py` provides read-model services for dashboard panels, relationship graphs, unified timelines, and entity enrichment profiles.
- `web.py` serves a local-only HTTP API and static web shell on `127.0.0.1` by default. It reuses the same `ArgusServices` composition root as the desktop UI.
- `web_static/` contains the zero-build browser interface for dashboard, universal search, investigations, entities, graph, timeline, evidence, reports, and settings.
- `collectors.py` contains bounded, lawful public-source adapters. Collectors return typed `Finding` values and do not write investigations directly.
- `operations.py` persists jobs before execution, applies concurrency limits, records failures, normalizes entities, archives findings, hashes source payloads, extracts geospatial observations, and invokes correlation.
- `correlation.py` creates explainable suggestions from conservative normalization keys. Suggestions never become relationships without an investigator decision.
- `evidence.py` copies files into content-addressed storage and verifies the copy before committing its database record.
- `bundles.py` exports and imports portable case archives. Every included file is size- and SHA-256-checked; unsafe ZIP paths, duplicate paths, excessive expansion ratios, and oversized archives are rejected.
- `reports.py` renders a consistent investigation snapshot into seven professional exchange formats.
- `plugins.py` installs plugins atomically and invokes them in isolated Python subprocesses through a one-request JSON-RPC protocol.
- `ui.py` contains the PySide6 desktop shell: top toolbar, sidebar navigation, service-backed dashboard/search/workspace pages, inspector and collector docks, persistent layouts, and interaction logic. Network and batch work runs outside the GUI thread.

## Collection flow

```text
Investigator query
      |
      v
Persistent collection job -----> job event log / audit trail
      |
      v
Collector + rate-limited HTTP context
      |
      v
Finding records
      |
      +----> intelligence JSON + source URL + payload hash
      +----> normalized entities + aliases
      +----> geospatial observations
      +----> source provenance
      |
      v
Explainable correlation suggestions --investigator review--> relationships
```

Failures remain attached to their jobs and can be retried. A successful retry is a new job, preserving the original failure rather than rewriting history.

## Campaign and brief flow

`campaigns.py` adds an orchestration layer above individual collectors. A campaign plan maps a seed or archived entity to a bounded, explainable set of collector requests. `CampaignRunner` executes those requests through `OperationManager`, so campaign output still follows the same durable job, intelligence, entity, provenance, location, and correlation path as a manually queued collection.

`security.py` builds security-research briefs from records already admitted into an investigation. The brief builder ranks CVEs, exposed public services, breach exposure, and disclosure gaps from archived intelligence; every risk item preserves its reasons and source URLs. `reports.py` can export these briefs separately from full case reports for quick triage handoff.

## Workspace service flow

`app_services.py` composes the application once and exposes stable services to UI, CLI, and future API layers. The UI can ask `UniversalSearchService` for normalized inputs, local FTS matches, and next collector requests without knowing collector IDs. Dashboard, graph, timeline, and enrichment views read through `workspace.py`, keeping presentation code away from SQL and making the next UI overhaul incremental instead of a rewrite.

## Local web flow

`web.py` exposes the same local workspace through JSON routes under `/api/*` and serves `web_static/` for the browser UI. The server binds to loopback by default, applies conservative browser headers, and does not require a hosted Argus service. Job creation still goes through `OperationManager`, so web-triggered collection uses the same durable queue, source provenance, entity normalization, and correlation path as desktop-triggered collection.

## Free social-source boundary

Social collectors must remain free to run and must use either public endpoints/feeds or generated public profile URLs. Platforms with reliable free public endpoints can produce live findings; platforms that require login, paid API access, or restrictive developer approval are represented as explicitly unverified review leads. Matching social handles are never treated as identity proof by themselves.

## Civic and household boundary

Election collectors provide official registration/status resource routing and may use the Census Geocoder to infer state-level context from an address. They do not retrieve voter rolls or confirm an individual's registration. Household collectors produce address-level geography and public-record search leads; they do not identify residents or infer household membership.

## Trust semantics

Argus distinguishes these concepts throughout the model:

- `verified` means the record was directly established by a cited public source. It does not mean a person controls an account today.
- `confidence` expresses the investigator or collector's assessment and is never silently promoted to verification.
- correlation suggestions are hypotheses. Accepted suggestions create relationships that remain unverified unless the investigator separately establishes them.
- source payload hashes establish that the locally retained result has not changed. They do not authenticate a remote publisher.

## Scaling characteristics

SQLite WAL and FTS5 provide a strong single-workstation default. Network work is asynchronous, jobs are durable, collectors apply per-host pacing, cached GET responses have expirations, and tables are indexed by investigation and common filter fields. The repository boundary keeps a future PostgreSQL adapter possible without coupling collectors or the GUI to SQL.

Argus intentionally bounds collection concurrency to ten tasks, geospatial extraction to 250 points per finding, archive expansion to 5 GiB, cached response bodies to 5 MB, and graph/report inputs to records already admitted into an investigation. These limits reduce accidental denial of service and runaway evidence growth.

## Plugin protocol

A plugin ZIP contains one `plugin.json` and an entrypoint inside the package root. The manifest declares its ID, version, description, entrypoint, permissions, and optional entrypoint SHA-256. Argus rejects traversal paths and installs through a staging directory with rollback.

At invocation, Argus starts the entrypoint using Python isolated mode and sends one JSON-RPC 2.0 request on standard input. The plugin returns one response on standard output. Timeouts, non-zero exits, malformed envelopes, and plugin errors fail closed. Declared permissions are visible policy metadata; they are not an operating-system sandbox on platforms that do not provide one.

## Lawful-use boundary

Collectors use public content and official APIs where available. Argus does not defeat access controls, automate credential attacks, enumerate private accounts, or scrape login-gated pages. Operators remain responsible for API terms, rate limits, data-protection obligations, retention rules, and the lawful basis for each investigation.
