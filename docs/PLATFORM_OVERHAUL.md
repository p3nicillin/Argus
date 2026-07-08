# Platform overhaul

This roadmap turns Argus into a professional local-first OSINT and security research platform while keeping the default system free to run. Paid-only data vendors, login-gated scraping, CAPTCHA bypass, private account access, and automated voter-roll or people-search removals are outside the project boundary.

## Phase 1: Platform service foundation

Status: implemented in the current service-layer pass.

- Add a composition root for desktop UI, CLI, tests, and future API adapters.
- Normalize universal search inputs before collector selection.
- Provide reusable dashboard, graph, timeline, and enrichment read models.
- Keep all collection execution on the existing durable job pipeline.
- Expand campaign planning for phone, file hash, social platform, address, household, and civic seeds.

## Phase 2: Professional desktop workspace

Status: initial desktop shell and local web shell implemented; deeper per-view redesign remains open.

- Move the PySide6 UI toward service-backed pages instead of direct repository calls.
- Add a command palette, saved layout presets, richer notifications, activity center, and keyboard-first navigation.
- Build first-class dashboard, universal search, case workspace, graph, timeline, map, evidence, reports, settings, and plugin views.
- Preserve the current dark/light theme support and tighten accessibility contrast, focus order, and empty/loading/error states.

## Phase 3: Source marketplace and live-data reliability

- Add source health checks, rate-limit visibility, free/keyless/optional-key labels, and per-source policy notes.
- Split social coverage into live public collectors and unverified public URL lead generators.
- Improve official-source civic routing, Census geography handling, broker/Whitepages-style review links, and safe email unsubscribe analysis.
- Add collector contract tests and recorded public-shape fixtures for fragile third-party endpoints.

## Phase 4: Analysis, visualization, and evidence operations

- Add richer graph filters, entity clustering, timeline lanes, geospatial layers, screenshot/snapshot capture, and report templates.
- Make provenance, confidence, verification, source hashes, and manual review state visible in every analysis view.
- Add case templates for security exposure review, identity exposure management, vulnerability triage, and civic/public-record research.
- Improve import/export bundles with manifest previews and integrity status views.

## Phase 5: Hardening, extensibility, and release quality

- Add plugin permission review UX, plugin signing guidance, source-pack versioning, and isolated collector bundles.
- Add structured logs, diagnostics export, backup/restore, migration tests, and crash-safe recovery flows.
- Increase unit, integration, UI smoke, accessibility, and performance coverage.
- Package signed desktop builds with clear free-use, lawful-use, and third-party-source disclosures.

## Current slice

The current overhaul pass adds the backend service layer needed by later UI phases:

- `app_services.py`: single dependency-injection entry point.
- `universal.py`: universal input normalizer and search/planning service.
- `workspace.py`: dashboard, graph, timeline, and enrichment services.
- `ui.py`: enterprise-style desktop shell with top toolbar, sidebar navigation, dashboard cards, universal search page, inspector dock, collector dock, command palette, persistent layout, and service-backed status panels.
- `web.py` and `web_static/`: local-first browser UI and JSON API for the same dashboard, search, investigation, graph, timeline, evidence, and report workflows.
- Expanded campaign planning for free social platforms, phone, hash, address, household, and election-resource workflows.
- Tests that lock in the new platform behavior.
