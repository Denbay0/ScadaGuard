from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import database_session
from app.models import (
    Agent,
    AgentToken,
    CheckHistory,
    CheckSnapshot,
    HealthState,
    Incident,
    IncidentEvent,
    IngestedMessage,
    SignalDefinition,
    SignalSample,
)
from app.schemas import (
    AgentEnvelope,
    CheckResultItem,
    IncidentEventItem,
    IngestResponse,
    SignalSampleItem,
)
from app.security import hash_agent_token, parse_bearer_header

router = APIRouter(prefix="/api/v1/agent", tags=["agent-ingest"])


async def authenticated_agent(
    session: Annotated[AsyncSession, Depends(database_session)],
    authorization: Annotated[str | None, Header()] = None,
) -> Agent:
    bearer = parse_bearer_header(authorization)
    if bearer is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Agent bearer token is required")
    token_hash = hash_agent_token(bearer.value)
    query = (
        select(Agent)
        .join(AgentToken, AgentToken.agent_id == Agent.id)
        .where(
            AgentToken.token_hash == token_hash,
            AgentToken.revoked_at.is_(None),
            Agent.enabled.is_(True),
        )
    )
    agent = await session.scalar(query)
    if agent is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or revoked agent token")
    return agent


def payload_items[PayloadItem: BaseModel](
    envelope: AgentEnvelope, model: type[PayloadItem]
) -> list[PayloadItem]:
    raw_items = envelope.payload.get("items")
    if not isinstance(raw_items, list):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload.items must be an array")
    try:
        return [model.model_validate(item) for item in raw_items]
    except ValidationError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=error.errors()) from error


async def persist_checks(envelope: AgentEnvelope, agent: Agent, session: AsyncSession) -> None:
    for item in payload_items(envelope, CheckResultItem):
        payload = item.model_dump(mode="json")
        state = HealthState(item.status)
        session.add(
            CheckHistory(
                agent_id=agent.id,
                check_id=item.check_id,
                status=state,
                observed_at=item.observed_at,
                payload=payload,
            )
        )
        statement = insert(CheckSnapshot).values(
            agent_id=agent.id,
            check_id=item.check_id,
            status=state,
            observed_at=item.observed_at,
            payload=payload,
        )
        await session.execute(
            statement.on_conflict_do_update(
                index_elements=[CheckSnapshot.agent_id, CheckSnapshot.check_id],
                set_={
                    "status": statement.excluded.status,
                    "observed_at": statement.excluded.observed_at,
                    "payload": statement.excluded.payload,
                },
            )
        )


async def persist_incidents(envelope: AgentEnvelope, agent: Agent, session: AsyncSession) -> None:
    for event in payload_items(envelope, IncidentEventItem):
        item = event.incident
        incident_status = "open" if item.active else "closed"
        values: dict[str, Any] = {
            "id": item.incident_id,
            "incident_key": item.incident_key,
            "site_id": agent.site_id,
            "agent_id": agent.id,
            "source": item.source,
            "severity": HealthState(item.severity),
            "status": incident_status,
            "title": item.title,
            "description": item.description,
            "opened_at": item.opened_at,
            "last_seen_at": item.last_seen_at,
            "closed_at": item.closed_at,
            "occurrence_count": item.occurrence_count,
            "details": item.details,
        }
        statement = insert(Incident).values(**values)
        await session.execute(
            statement.on_conflict_do_update(
                index_elements=[Incident.id],
                set_={
                    "severity": statement.excluded.severity,
                    "status": statement.excluded.status,
                    "title": statement.excluded.title,
                    "description": statement.excluded.description,
                    "last_seen_at": statement.excluded.last_seen_at,
                    "closed_at": statement.excluded.closed_at,
                    "occurrence_count": statement.excluded.occurrence_count,
                    "details": statement.excluded.details,
                },
            )
        )
        session.add(
            IncidentEvent(
                incident_id=item.incident_id,
                event_type=event.type,
                timestamp=event.occurred_at,
                payload=event.model_dump(mode="json"),
            )
        )


async def persist_samples(envelope: AgentEnvelope, agent: Agent, session: AsyncSession) -> None:
    for item in payload_items(envelope, SignalSampleItem):
        definition = insert(SignalDefinition).values(
            signal_id=item.signal_id,
            site_id=agent.site_id,
            agent_id=agent.id,
            display_name=item.signal_id,
        )
        await session.execute(
            definition.on_conflict_do_nothing(
                index_elements=[SignalDefinition.agent_id, SignalDefinition.signal_id]
            )
        )
        session.add(
            SignalSample(
                agent_id=agent.id,
                signal_id=item.signal_id,
                value=item.value,
                quality=item.quality,
                source_timestamp=item.source_timestamp,
                server_timestamp=None,
                origin="agent",
                anomaly_flags=[],
            )
        )


async def persist_heartbeat(envelope: AgentEnvelope, agent: Agent) -> None:
    payload = envelope.payload
    raw_version = payload.get("agent_version")
    agent.version = str(raw_version)[:50] if raw_version else agent.version
    agent.protocol_version = envelope.protocol_version
    agent.configuration_hash = (
        str(payload.get("configuration_hash"))[:100]
        if payload.get("configuration_hash")
        else agent.configuration_hash
    )
    raw_status = payload.get("status", payload.get("overall_status"))
    if isinstance(raw_status, str) and raw_status in HealthState._value2member_map_:
        agent.current_status = HealthState(raw_status)


async def ingest(
    envelope: AgentEnvelope,
    expected_kind: Literal["heartbeat", "check_results", "incidents", "signal_samples"],
    agent: Agent,
    session: AsyncSession,
) -> IngestResponse:
    if envelope.message_kind != expected_kind:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "message_kind does not match endpoint"
        )
    if envelope.agent_id != agent.agent_id or envelope.host_id != agent.host_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Agent identity does not match token")

    marker = (
        insert(IngestedMessage)
        .values(
            message_id=envelope.message_id,
            agent_id=agent.id,
            sequence_number=envelope.sequence_number,
            kind=envelope.message_kind,
        )
        .on_conflict_do_nothing(index_elements=[IngestedMessage.message_id])
        .returning(IngestedMessage.message_id)
    )
    if await session.scalar(marker) is None:
        await session.rollback()
        return IngestResponse(message_id=envelope.message_id, duplicate=True)

    if expected_kind == "heartbeat":
        await persist_heartbeat(envelope, agent)
    elif expected_kind == "check_results":
        await persist_checks(envelope, agent, session)
    elif expected_kind == "incidents":
        await persist_incidents(envelope, agent, session)
    else:
        await persist_samples(envelope, agent, session)

    agent.last_seen_at = datetime.now(UTC)
    agent.boot_id = str(envelope.boot_id)
    await session.commit()
    return IngestResponse(message_id=envelope.message_id)


@router.post("/heartbeat", response_model=IngestResponse)
async def ingest_heartbeat(
    envelope: AgentEnvelope,
    agent: Annotated[Agent, Depends(authenticated_agent)],
    session: Annotated[AsyncSession, Depends(database_session)],
) -> IngestResponse:
    return await ingest(envelope, "heartbeat", agent, session)


@router.post("/check-results/batch", response_model=IngestResponse)
async def ingest_check_results(
    envelope: AgentEnvelope,
    agent: Annotated[Agent, Depends(authenticated_agent)],
    session: Annotated[AsyncSession, Depends(database_session)],
) -> IngestResponse:
    return await ingest(envelope, "check_results", agent, session)


@router.post("/incidents/batch", response_model=IngestResponse)
async def ingest_incidents(
    envelope: AgentEnvelope,
    agent: Annotated[Agent, Depends(authenticated_agent)],
    session: Annotated[AsyncSession, Depends(database_session)],
) -> IngestResponse:
    return await ingest(envelope, "incidents", agent, session)


@router.post("/signal-samples/batch", response_model=IngestResponse)
async def ingest_signal_samples(
    envelope: AgentEnvelope,
    agent: Annotated[Agent, Depends(authenticated_agent)],
    session: Annotated[AsyncSession, Depends(database_session)],
) -> IngestResponse:
    return await ingest(envelope, "signal_samples", agent, session)
