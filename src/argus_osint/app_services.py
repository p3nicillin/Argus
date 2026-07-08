from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .campaigns import CampaignPlanner, CampaignRunner
from .collectors import CollectorContext, CollectorRegistry
from .config import SecretStore, Settings
from .db import Database
from .operations import OperationManager
from .reports import ReportEngine
from .repository import Repository
from .security import SecurityBriefBuilder
from .universal import UniversalSearchService
from .workspace import DashboardService, EnrichmentService, GraphService, TimelineService


@dataclass(slots=True)
class ArgusServices:
    """One composition root for desktop UI, CLI, tests, and future API adapters."""

    settings: Settings
    database: Database
    repository: Repository
    collectors: CollectorRegistry
    context: CollectorContext
    operations: OperationManager
    reports: ReportEngine
    campaign_planner: CampaignPlanner
    campaign_runner: CampaignRunner
    universal_search: UniversalSearchService
    dashboard: DashboardService
    graph: GraphService
    timeline: TimelineService
    enrichment: EnrichmentService
    security: SecurityBriefBuilder

    @classmethod
    def build(
        cls,
        *,
        settings: Settings | None = None,
        db_path: Path | None = None,
        actor: str | None = None,
        secrets: SecretStore | None = None,
        registry: CollectorRegistry | None = None,
    ) -> ArgusServices:
        settings = settings or Settings()
        database = Database(db_path or settings.resolved_workspace() / "argus.sqlite3")
        repository = Repository(database, actor if actor is not None else settings.investigator)
        collectors = registry or CollectorRegistry()
        context = CollectorContext(settings, database, secrets)
        operations = OperationManager(repository, collectors, context)
        campaign_planner = CampaignPlanner(collectors)
        campaign_runner = CampaignRunner(operations, campaign_planner)
        return cls(
            settings=settings,
            database=database,
            repository=repository,
            collectors=collectors,
            context=context,
            operations=operations,
            reports=ReportEngine(repository),
            campaign_planner=campaign_planner,
            campaign_runner=campaign_runner,
            universal_search=UniversalSearchService(repository, campaign_planner),
            dashboard=DashboardService(repository),
            graph=GraphService(repository),
            timeline=TimelineService(repository),
            enrichment=EnrichmentService(repository, campaign_planner),
            security=SecurityBriefBuilder(repository),
        )

    def close(self) -> None:
        self.database.close()


def build_services(**kwargs: Any) -> ArgusServices:
    return ArgusServices.build(**kwargs)
