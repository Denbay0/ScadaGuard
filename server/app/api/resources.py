import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from app.api.auth import current_user
from app.database import database_session
from app.models import (
    Agent,
    AuditLog,
    HealthState,
    Incident,
    IncidentEvent,
    SignalDefinition,
    SignalSample,
    Site,
    User,
    UserRole,
)

router = APIRouter(prefix="/api/v1", tags=["monitoring"])


class PageInfo(BaseModel):
    total: int
    limit: int
    offset: int


class IncidentSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    severity: HealthState
    status: str
    source: str
    title: str
    site_id: uuid.UUID
    site_name: str
    agent_id: uuid.UUID
    agent_name: str
    opened_at: datetime
    last_seen_at: datetime
    closed_at: datetime | None
    acknowledged_at: datetime | None
    occurrence_count: int


class IncidentPage(PageInfo):
    items: list[IncidentSummary]


class IncidentEventView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_type: str
    timestamp: datetime
    payload: dict[str, object]


class IncidentDetail(IncidentSummary):
    description: str
    details: dict[str, object]
    events: list[IncidentEventView]


class SignalSummary(BaseModel):
    id: int
    signal_id: str
    display_name: str
    unit: str | None
    site_id: uuid.UUID
    site_name: str
    agent_id: uuid.UUID
    agent_name: str
    value: float | None
    quality: str | None
    source_timestamp: datetime | None
    origin: str | None
    anomaly_flags: list[str]


class SignalPage(PageInfo):
    items: list[SignalSummary]


class SignalSampleView(BaseModel):
    value: float
    quality: str
    source_timestamp: datetime
    received_timestamp: datetime
    origin: str
    anomaly_flags: list[str]


class SignalSamples(BaseModel):
    signal_id: str
    from_timestamp: datetime | None
    to_timestamp: datetime | None
    items: list[SignalSampleView]


def incident_query() -> Select[tuple[Incident, str, str]]:
    return (
        select(Incident, Site.display_name, Agent.display_name)
        .join(Site, Site.id == Incident.site_id)
        .join(Agent, Agent.id == Incident.agent_id)
    )


def incident_view(item: Incident, site_name: str, agent_name: str) -> IncidentSummary:
    return IncidentSummary(
        id=item.id,
        severity=item.severity,
        status=item.status,
        source=item.source,
        title=item.title,
        site_id=item.site_id,
        site_name=site_name,
        agent_id=item.agent_id,
        agent_name=agent_name,
        opened_at=item.opened_at,
        last_seen_at=item.last_seen_at,
        closed_at=item.closed_at,
        acknowledged_at=item.acknowledged_at,
        occurrence_count=item.occurrence_count,
    )


@router.get("/incidents", response_model=IncidentPage)
async def incidents(
    _: Annotated[User, Depends(current_user)],
    session: Annotated[AsyncSession, Depends(database_session)],
    site_id: uuid.UUID | None = None,
    agent_id: uuid.UUID | None = None,
    incident_status: Annotated[str | None, Query(alias="status")] = None,
    severity: HealthState | None = None,
    from_timestamp: datetime | None = None,
    to_timestamp: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> IncidentPage:
    filters: list[ColumnElement[bool]] = []
    if site_id:
        filters.append(Incident.site_id == site_id)
    if agent_id:
        filters.append(Incident.agent_id == agent_id)
    if incident_status:
        filters.append(Incident.status == incident_status)
    if severity:
        filters.append(Incident.severity == severity)
    if from_timestamp:
        filters.append(Incident.last_seen_at >= from_timestamp)
    if to_timestamp:
        filters.append(Incident.opened_at <= to_timestamp)
    total = await session.scalar(select(func.count()).select_from(Incident).where(*filters))
    rows = (
        await session.execute(
            incident_query()
            .where(*filters)
            .order_by(Incident.opened_at.desc())
            .limit(limit)
            .offset(offset)
        )
    ).all()
    return IncidentPage(
        items=[incident_view(row[0], row[1], row[2]) for row in rows],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@router.get("/incidents/{incident_id}", response_model=IncidentDetail)
async def incident_detail(
    incident_id: uuid.UUID,
    _: Annotated[User, Depends(current_user)],
    session: Annotated[AsyncSession, Depends(database_session)],
) -> IncidentDetail:
    row = (await session.execute(incident_query().where(Incident.id == incident_id))).one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    item = row[0]
    events = list(
        await session.scalars(
            select(IncidentEvent)
            .where(IncidentEvent.incident_id == incident_id)
            .order_by(IncidentEvent.timestamp)
        )
    )
    return IncidentDetail(
        **incident_view(row[0], row[1], row[2]).model_dump(),
        description=item.description,
        details=item.details,
        events=[IncidentEventView.model_validate(event) for event in events],
    )


@router.post("/incidents/{incident_id}/acknowledge", response_model=IncidentDetail)
async def acknowledge_incident(
    incident_id: uuid.UUID,
    user: Annotated[User, Depends(current_user)],
    session: Annotated[AsyncSession, Depends(database_session)],
) -> IncidentDetail:
    if user.role != UserRole.admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Administrator role required")
    item = await session.get(Incident, incident_id)
    if item is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    now = datetime.now(UTC)
    item.acknowledged_at = now
    item.acknowledged_by = user.id
    session.add(
        IncidentEvent(
            incident_id=item.id,
            event_type="acknowledged",
            timestamp=now,
            payload={"user_id": str(user.id), "username": user.username},
        )
    )
    session.add(
        AuditLog(
            user_id=user.id,
            action="incident.acknowledge",
            target_type="incident",
            target_id=str(item.id),
            details={},
        )
    )
    await session.commit()
    return await incident_detail(incident_id, user, session)


@router.get("/signals", response_model=SignalPage)
async def signals(
    _: Annotated[User, Depends(current_user)],
    session: Annotated[AsyncSession, Depends(database_session)],
    site_id: uuid.UUID | None = None,
    agent_id: uuid.UUID | None = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> SignalPage:
    filters: list[ColumnElement[bool]] = [SignalDefinition.enabled.is_(True)]
    if site_id:
        filters.append(SignalDefinition.site_id == site_id)
    if agent_id:
        filters.append(SignalDefinition.agent_id == agent_id)
    if search:
        filters.append(SignalDefinition.display_name.ilike(f"%{search}%"))
    total = await session.scalar(select(func.count()).select_from(SignalDefinition).where(*filters))
    definitions = (
        await session.execute(
            select(SignalDefinition, Site.display_name, Agent.display_name)
            .join(Site, Site.id == SignalDefinition.site_id)
            .join(Agent, Agent.id == SignalDefinition.agent_id)
            .where(*filters)
            .order_by(SignalDefinition.display_name)
            .limit(limit)
            .offset(offset)
        )
    ).all()
    output: list[SignalSummary] = []
    for definition, site_name, agent_name in definitions:
        latest = await session.scalar(
            select(SignalSample)
            .where(
                SignalSample.agent_id == definition.agent_id,
                SignalSample.signal_id == definition.signal_id,
            )
            .order_by(SignalSample.source_timestamp.desc())
            .limit(1)
        )
        output.append(
            SignalSummary(
                id=definition.id,
                signal_id=definition.signal_id,
                display_name=definition.display_name,
                unit=definition.unit,
                site_id=definition.site_id,
                site_name=site_name,
                agent_id=definition.agent_id,
                agent_name=agent_name,
                value=latest.value if latest else None,
                quality=latest.quality if latest else None,
                source_timestamp=latest.source_timestamp if latest else None,
                origin=latest.origin if latest else None,
                anomaly_flags=latest.anomaly_flags if latest else [],
            )
        )
    return SignalPage(items=output, total=total or 0, limit=limit, offset=offset)


@router.get("/signals/{definition_id}/samples", response_model=SignalSamples)
async def signal_samples(
    definition_id: int,
    _: Annotated[User, Depends(current_user)],
    session: Annotated[AsyncSession, Depends(database_session)],
    from_timestamp: datetime | None = None,
    to_timestamp: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=5000)] = 1000,
) -> SignalSamples:
    definition = await session.get(SignalDefinition, definition_id)
    if definition is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Signal not found")
    filters = [
        SignalSample.agent_id == definition.agent_id,
        SignalSample.signal_id == definition.signal_id,
    ]
    if from_timestamp:
        filters.append(SignalSample.source_timestamp >= from_timestamp)
    if to_timestamp:
        filters.append(SignalSample.source_timestamp <= to_timestamp)
    samples = list(
        await session.scalars(
            select(SignalSample)
            .where(*filters)
            .order_by(SignalSample.source_timestamp.desc())
            .limit(limit)
        )
    )
    return SignalSamples(
        signal_id=definition.signal_id,
        from_timestamp=from_timestamp,
        to_timestamp=to_timestamp,
        items=[
            SignalSampleView(
                value=sample.value,
                quality=sample.quality,
                source_timestamp=sample.source_timestamp,
                received_timestamp=sample.received_timestamp,
                origin=sample.origin,
                anomaly_flags=sample.anomaly_flags,
            )
            for sample in reversed(samples)
        ],
    )
