from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .campaigns import CampaignPlanner
from .repository import Repository, decode_rows


class DashboardService:
    def __init__(self, repository: Repository) -> None:
        self.repository = repository

    def overview(self, case_id: int | None = None) -> dict[str, Any]:
        recent_cases = self.repository.list_investigations(include_archived=True)[:10]
        saved_searches = self.repository.saved_searches()[:10]
        search_history = decode_rows(
            self.repository.db.all(
                "SELECT * FROM search_history "
                + ("WHERE investigation_id=? " if case_id is not None else "")
                + "ORDER BY created_at DESC LIMIT 20",
                (case_id,) if case_id is not None else (),
            )
        )
        jobs = (
            self.repository.rows("collection_jobs", case_id)
            if case_id is not None
            else decode_rows(
                self.repository.db.all(
                    "SELECT * FROM collection_jobs ORDER BY created_at DESC LIMIT 50"
                )
            )
        )
        return {
            "stats": self.repository.dashboard_stats(case_id),
            "recent_investigations": recent_cases,
            "pinned_investigations": [
                item for item in recent_cases if "pinned" in item.get("tags", [])
            ],
            "saved_searches": saved_searches,
            "search_history": search_history,
            "recent_jobs": jobs[:10],
            "system_status": {
                "failed_jobs": sum(1 for job in jobs if job.get("status") == "failed"),
                "running_jobs": sum(1 for job in jobs if job.get("status") == "running"),
                "pending_jobs": sum(1 for job in jobs if job.get("status") == "pending"),
                "database_path": str(self.repository.db.path),
            },
        }


class GraphService:
    def __init__(self, repository: Repository) -> None:
        self.repository = repository

    def relationship_graph(self, case_id: int) -> dict[str, Any]:
        entities = self.repository.rows("entities", case_id)
        relationships = self.repository.rows("relationships", case_id)
        suggestions = self.repository.rows("correlation_suggestions", case_id)
        nodes = [
            {
                "id": f"entity:{entity['id']}",
                "entity_id": entity["id"],
                "kind": entity["kind"],
                "label": entity.get("display_name") or entity["value"],
                "value": entity["value"],
                "verified": entity["verified"],
                "confidence": entity["confidence"],
                "group": entity["kind"],
            }
            for entity in entities
        ]
        edges = [
            {
                "id": f"relationship:{relationship['id']}",
                "source": f"entity:{relationship['source_entity_id']}",
                "target": f"entity:{relationship['target_entity_id']}",
                "kind": relationship["kind"],
                "confidence": relationship["confidence"],
                "verified": relationship["verified"],
                "status": "accepted",
            }
            for relationship in relationships
        ]
        edges.extend(
            {
                "id": f"suggestion:{suggestion['id']}",
                "source": f"entity:{suggestion['source_entity_id']}",
                "target": f"entity:{suggestion['target_entity_id']}",
                "kind": suggestion["relationship_kind"],
                "confidence": suggestion["score"],
                "verified": False,
                "status": suggestion["status"],
                "reasons": suggestion["reasons"],
            }
            for suggestion in suggestions
        )
        return {
            "nodes": nodes,
            "edges": edges,
            "groups": dict(Counter(node["group"] for node in nodes)),
            "filters": {
                "kinds": sorted({node["kind"] for node in nodes}),
                "relationship_kinds": sorted({edge["kind"] for edge in edges}),
            },
        }


class TimelineService:
    def __init__(self, repository: Repository) -> None:
        self.repository = repository

    def unified_timeline(self, case_id: int, limit: int = 500) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for row in self.repository.rows("timeline_events", case_id):
            events.append({
                "time": row["occurred_at"],
                "kind": row["kind"],
                "title": row["title"],
                "description": row["description"],
                "source_url": row["source_url"],
                "object_type": "timeline_event",
                "object_id": row["id"],
            })
        for row in self.repository.rows("intelligence", case_id):
            events.append({
                "time": row["collected_at"],
                "kind": "collection",
                "title": row["title"],
                "description": f"{row['collector']} on {row['query']}",
                "source_url": row["source_url"],
                "object_type": "intelligence",
                "object_id": row["id"],
            })
        for row in self.repository.rows("evidence", case_id):
            events.append({
                "time": row["captured_at"],
                "kind": "evidence",
                "title": row["title"],
                "description": row["notes"],
                "source_url": row["source_url"],
                "object_type": "evidence",
                "object_id": row["id"],
            })
        for row in self.repository.rows("collection_jobs", case_id):
            events.append({
                "time": row["finished_at"] or row["started_at"] or row["created_at"],
                "kind": f"job_{row['status']}",
                "title": f"{row['collector']}: {row['query']}",
                "description": row["error"],
                "source_url": "",
                "object_type": "collection_job",
                "object_id": row["id"],
            })
        return sorted(events, key=lambda item: item["time"], reverse=True)[:limit]


class EnrichmentService:
    def __init__(self, repository: Repository, planner: CampaignPlanner | None = None) -> None:
        self.repository = repository
        self.planner = planner or CampaignPlanner()

    def entity_profiles(self, case_id: int) -> list[dict[str, Any]]:
        aliases_by_entity: defaultdict[int, list[dict[str, Any]]] = defaultdict(list)
        for alias in self.repository.rows("entity_aliases", case_id):
            aliases_by_entity[alias["entity_id"]].append(alias)
        relationships_by_entity: defaultdict[int, list[dict[str, Any]]] = defaultdict(list)
        for relationship in self.repository.rows("relationships", case_id):
            relationships_by_entity[relationship["source_entity_id"]].append(relationship)
            relationships_by_entity[relationship["target_entity_id"]].append(relationship)
        profiles = []
        for entity in self.repository.rows("entities", case_id):
            plan = [
                request.to_dict()
                for request in self.planner.plan_seed(
                    str(entity["value"]), str(entity["kind"])
                )[:8]
            ]
            profiles.append({
                "entity": entity,
                "aliases": aliases_by_entity[entity["id"]],
                "relationships": relationships_by_entity[entity["id"]],
                "recommended_collection": plan,
                "confidence_band": self._confidence_band(float(entity["confidence"])),
            })
        return profiles

    @staticmethod
    def _confidence_band(value: float) -> str:
        if value >= 0.8:
            return "high"
        if value >= 0.5:
            return "medium"
        return "low"
