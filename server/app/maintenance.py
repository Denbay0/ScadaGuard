import asyncio
import contextlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import cast

import structlog
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.database import session_factory
from app.models import (
    Agent,
    CheckHistory,
    HealthState,
    Incident,
    IncidentEvent,
    SignalSample,
)

logger = structlog.get_logger()


def heartbeat_is_overdue(
    last_seen_at: datetime | None,
    heartbeat_interval_seconds: int,
    default_offline_threshold_seconds: int,
    now: datetime,
) -> bool:
    if last_seen_at is None:
        return False
    threshold = max(default_offline_threshold_seconds, heartbeat_interval_seconds * 3)
    return last_seen_at < now - timedelta(seconds=threshold)


async def reconcile_offline_agents(
    session: AsyncSession, settings: Settings, now: datetime | None = None
) -> tuple[int, int]:
    current = now or datetime.now(UTC)
    opened = 0
    recovered = 0
    agents = list(await session.scalars(select(Agent).where(Agent.enabled.is_(True))))
    for agent in agents:
        threshold = max(
            settings.default_offline_threshold_seconds,
            agent.heartbeat_interval_seconds * 3,
        )
        last_contact = agent.last_seen_at
        is_offline = heartbeat_is_overdue(
            last_contact,
            agent.heartbeat_interval_seconds,
            settings.default_offline_threshold_seconds,
            current,
        )
        incident_key = f"agent_offline:{agent.id}"
        incident = await session.scalar(
            select(Incident).where(
                Incident.incident_key == incident_key,
                Incident.status == "open",
            )
        )
        if is_offline:
            assert last_contact is not None
            agent.current_status = HealthState.offline
            if incident is None:
                incident = Incident(
                    id=uuid.uuid4(),
                    incident_key=incident_key,
                    site_id=agent.site_id,
                    agent_id=agent.id,
                    source="system",
                    severity=HealthState.critical,
                    status="open",
                    title=f"Агент {agent.display_name} недоступен",
                    description="Центральный сервер не получает heartbeat в заданный срок.",
                    opened_at=current,
                    last_seen_at=current,
                    closed_at=None,
                    occurrence_count=1,
                    details={"problem_type": "agent_offline", "threshold_seconds": threshold},
                )
                session.add(incident)
                session.add(
                    IncidentEvent(
                        incident_id=incident.id,
                        event_type="opened",
                        timestamp=current,
                        payload={"last_contact": last_contact.isoformat()},
                    )
                )
                opened += 1
        elif incident is not None and last_contact is not None:
            incident.status = "closed"
            incident.closed_at = current
            incident.last_seen_at = current
            session.add(
                IncidentEvent(
                    incident_id=incident.id,
                    event_type="recovered",
                    timestamp=current,
                    payload={
                        "downtime_seconds": int((current - incident.opened_at).total_seconds())
                    },
                )
            )
            recovered += 1
    await session.commit()
    return opened, recovered


async def apply_retention(
    session: AsyncSession, settings: Settings, now: datetime | None = None, batch_size: int = 1000
) -> tuple[int, int]:
    current = now or datetime.now(UTC)
    signal_ids = (
        select(SignalSample.id)
        .where(
            SignalSample.source_timestamp < current - timedelta(days=settings.signal_retention_days)
        )
        .limit(batch_size)
    )
    check_ids = (
        select(CheckHistory.id)
        .where(CheckHistory.observed_at < current - timedelta(days=settings.check_retention_days))
        .limit(batch_size)
    )
    signal_result = await session.execute(
        delete(SignalSample).where(SignalSample.id.in_(signal_ids))
    )
    check_result = await session.execute(delete(CheckHistory).where(CheckHistory.id.in_(check_ids)))
    await session.commit()
    signal_count = cast(int, getattr(signal_result, "rowcount", 0))
    check_count = cast(int, getattr(check_result, "rowcount", 0))
    return signal_count, check_count


async def maintenance_loop(stop: asyncio.Event) -> None:
    settings = get_settings()
    iteration = 0
    while not stop.is_set():
        try:
            async with session_factory() as session:
                opened, recovered = await reconcile_offline_agents(session, settings)
                if iteration % 240 == 0:
                    await apply_retention(session, settings)
                if opened or recovered:
                    await logger.ainfo("offline_reconciliation", opened=opened, recovered=recovered)
        except Exception:
            await logger.aexception("maintenance_failed")
        iteration += 1
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=15)
