import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import current_user
from app.database import database_session
from app.models import Agent, HealthState, Incident, Site, User

router = APIRouter(prefix="/api/v1", tags=["dashboard"])


class SiteCounts(BaseModel):
    total: int
    ok: int
    warning: int
    critical: int
    offline: int


class DashboardSummary(BaseModel):
    sites: SiteCounts
    active_incidents: int
    recent_recoveries: int
    generated_at: datetime


class SiteSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    slug: str
    display_name: str
    status: HealthState
    agent_count: int
    online_agents: int
    active_incidents: int
    last_seen_at: datetime | None


async def site_summaries(session: AsyncSession) -> list[SiteSummary]:
    sites = list(
        await session.scalars(
            select(Site).where(Site.enabled.is_(True)).order_by(Site.display_name)
        )
    )
    agents = list(await session.scalars(select(Agent).where(Agent.enabled.is_(True))))
    incidents = list(await session.scalars(select(Incident).where(Incident.status == "open")))
    result: list[SiteSummary] = []
    rank = {
        HealthState.ok: 0,
        HealthState.warning: 1,
        HealthState.critical: 2,
        HealthState.unknown: 3,
        HealthState.offline: 4,
    }
    for site in sites:
        site_agents = [agent for agent in agents if agent.site_id == site.id]
        state = max(
            (agent.current_status for agent in site_agents),
            key=lambda value: rank[value],
            default=HealthState.unknown,
        )
        seen = [agent.last_seen_at for agent in site_agents if agent.last_seen_at]
        result.append(
            SiteSummary(
                id=site.id,
                slug=site.slug,
                display_name=site.display_name,
                status=state,
                agent_count=len(site_agents),
                online_agents=sum(
                    agent.current_status != HealthState.offline for agent in site_agents
                ),
                active_incidents=sum(item.site_id == site.id for item in incidents),
                last_seen_at=max(seen, default=None),
            )
        )
    return result


@router.get("/dashboard/summary", response_model=DashboardSummary)
async def summary(
    _: Annotated[User, Depends(current_user)],
    session: Annotated[AsyncSession, Depends(database_session)],
) -> DashboardSummary:
    sites = await site_summaries(session)
    counts = Counter(site.status for site in sites)
    active = list(await session.scalars(select(Incident).where(Incident.status == "open")))
    recent = list(
        await session.scalars(
            select(Incident).where(Incident.closed_at >= datetime.now(UTC) - timedelta(hours=24))
        )
    )
    return DashboardSummary(
        sites=SiteCounts(
            total=len(sites),
            ok=counts[HealthState.ok],
            warning=counts[HealthState.warning],
            critical=counts[HealthState.critical],
            offline=counts[HealthState.offline],
        ),
        active_incidents=len(active),
        recent_recoveries=len(recent),
        generated_at=datetime.now(UTC),
    )


@router.get("/sites", response_model=list[SiteSummary])
async def sites(
    _: Annotated[User, Depends(current_user)],
    session: Annotated[AsyncSession, Depends(database_session)],
) -> list[SiteSummary]:
    return await site_summaries(session)
