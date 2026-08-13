import hashlib
import json
import uuid
from datetime import UTC, datetime
from pathlib import PureWindowsPath
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.admin import admin_user
from app.api.agent_ingest import authenticated_agent
from app.api.auth import current_user
from app.database import database_session
from app.models import (
    Agent,
    AgentDiscoveryReport,
    AuditLog,
    DesiredAgentConfiguration,
    User,
)

router = APIRouter(prefix="/api/v1", tags=["discovery-configuration"])


def safe_read_only_path(value: str) -> str:
    path = PureWindowsPath(value)
    normalized = str(path).lower().rstrip("\\")
    if not path.is_absolute() or value.startswith("\\\\"):
        raise ValueError("path must be an absolute local Windows path")
    if normalized in {str(path.anchor).lower().rstrip("\\"), "c:\\windows", "c:\\users"}:
        raise ValueError("broad or protected paths are not allowed")
    if normalized.startswith("c:\\windows\\") or normalized.startswith("c:\\users\\"):
        raise ValueError("protected paths are not allowed")
    return value


class SignalThresholds(BaseModel):
    model_config = ConfigDict(extra="forbid")

    minimum: float | None = None
    maximum: float | None = None
    max_rate_per_second: float | None = Field(default=None, gt=0)


class ArchiveMapping(BaseModel):
    model_config = ConfigDict(extra="forbid")

    table: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$", max_length=128)
    timestamp_column: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$", max_length=128)
    signal_id_column: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$", max_length=128)
    value_column: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$", max_length=128)
    quality_column: str | None = Field(
        default=None, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$", max_length=128
    )


class AgentConfigurationBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirmed_archive: str | None = Field(default=None, max_length=4096)
    archive_mapping: ArchiveMapping | None = None
    confirmed_logs: list[str] = Field(default_factory=list, max_length=100)
    monitored_signals: list[str] = Field(default_factory=list, max_length=10000)
    thresholds: dict[str, SignalThresholds] = Field(default_factory=dict)
    monitoring_interval_seconds: int = Field(default=30, ge=5, le=3600)
    server_url: str | None = Field(default=None, max_length=2048)
    rescan_requested_at: datetime | None = None

    @model_validator(mode="after")
    def mapping_requires_archive(self) -> "AgentConfigurationBody":
        if self.archive_mapping is not None and self.confirmed_archive is None:
            raise ValueError("archive_mapping requires confirmed_archive")
        return self

    @field_validator("confirmed_archive")
    @classmethod
    def archive_is_safe(cls, value: str | None) -> str | None:
        return safe_read_only_path(value) if value else None

    @field_validator("confirmed_logs")
    @classmethod
    def logs_are_safe(cls, values: list[str]) -> list[str]:
        return [safe_read_only_path(value) for value in values]

    @field_validator("server_url")
    @classmethod
    def server_uses_https(cls, value: str | None) -> str | None:
        if value and not value.startswith("https://"):
            raise ValueError("server_url must use HTTPS")
        return value


class AgentConfigurationView(BaseModel):
    config_version: int
    config_hash: str
    created_at: datetime | None
    created_by: uuid.UUID | None
    configuration: AgentConfigurationBody
    applied_version: int | None = None
    apply_status: str = "pending"
    apply_message: str = ""


class ConfigurationStatusBody(BaseModel):
    config_version: int = Field(ge=1)
    status: Literal["applied", "rejected"]
    message: str = Field(default="", max_length=4000)


class ArchiveConfirmation(BaseModel):
    path: str = Field(min_length=3, max_length=4096)

    @field_validator("path")
    @classmethod
    def path_is_safe(cls, value: str) -> str:
        return safe_read_only_path(value)


def config_hash(configuration: dict[str, object]) -> str:
    canonical = json.dumps(configuration, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256-" + hashlib.sha256(canonical.encode()).hexdigest()


def configuration_view(value: DesiredAgentConfiguration | None) -> AgentConfigurationView:
    if value is None:
        return AgentConfigurationView(
            config_version=0,
            config_hash="",
            created_at=None,
            created_by=None,
            configuration=AgentConfigurationBody(),
            apply_status="not_configured",
        )
    return AgentConfigurationView(
        config_version=value.config_version,
        config_hash=value.config_hash,
        created_at=value.created_at,
        created_by=value.created_by,
        configuration=AgentConfigurationBody.model_validate(value.configuration),
        applied_version=value.applied_version,
        apply_status=value.apply_status,
        apply_message=value.apply_message,
    )


async def save_configuration(
    agent: Agent,
    body: AgentConfigurationBody,
    user: User,
    session: AsyncSession,
    action: str,
) -> DesiredAgentConfiguration:
    value = await session.get(DesiredAgentConfiguration, agent.id)
    payload = body.model_dump(mode="json")
    if value is None:
        value = DesiredAgentConfiguration(
            agent_id=agent.id,
            config_version=1,
            config_hash=config_hash(payload),
            configuration=payload,
            created_by=user.id,
        )
        session.add(value)
    else:
        value.config_version += 1
        value.config_hash = config_hash(payload)
        value.configuration = payload
        value.created_at = datetime.now(UTC)
        value.created_by = user.id
        value.apply_status = "pending"
        value.apply_message = ""
    session.add(
        AuditLog(
            user_id=user.id,
            action=action,
            target_type="agent_configuration",
            target_id=str(agent.id),
            details={"config_version": value.config_version, "config_hash": value.config_hash},
        )
    )
    await session.commit()
    await session.refresh(value)
    return value


@router.get("/agent/config", response_model=AgentConfigurationView)
async def agent_configuration(
    agent: Annotated[Agent, Depends(authenticated_agent)],
    session: Annotated[AsyncSession, Depends(database_session)],
) -> AgentConfigurationView:
    return configuration_view(await session.get(DesiredAgentConfiguration, agent.id))


@router.post("/agent/config/status", status_code=status.HTTP_204_NO_CONTENT)
async def agent_configuration_status(
    body: ConfigurationStatusBody,
    agent: Annotated[Agent, Depends(authenticated_agent)],
    session: Annotated[AsyncSession, Depends(database_session)],
) -> None:
    value = await session.get(DesiredAgentConfiguration, agent.id)
    if value is None or value.config_version != body.config_version:
        raise HTTPException(status.HTTP_409_CONFLICT, "Configuration version is no longer current")
    value.applied_version = (
        body.config_version if body.status == "applied" else value.applied_version
    )
    value.apply_status = body.status
    value.apply_message = body.message
    value.applied_at = datetime.now(UTC)
    await session.commit()


@router.get("/agents/{agent_id}/discovery")
async def latest_discovery(
    agent_id: uuid.UUID,
    _: Annotated[User, Depends(current_user)],
    session: Annotated[AsyncSession, Depends(database_session)],
) -> dict[str, object]:
    if await session.get(Agent, agent_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent not found")
    report = await session.scalar(
        select(AgentDiscoveryReport)
        .where(AgentDiscoveryReport.agent_id == agent_id)
        .order_by(AgentDiscoveryReport.scanned_at.desc())
        .limit(1)
    )
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Discovery report not found")
    return report.report


@router.get("/agents/{agent_id}/configuration", response_model=AgentConfigurationView)
async def desired_configuration(
    agent_id: uuid.UUID,
    _: Annotated[User, Depends(current_user)],
    session: Annotated[AsyncSession, Depends(database_session)],
) -> AgentConfigurationView:
    if await session.get(Agent, agent_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent not found")
    return configuration_view(await session.get(DesiredAgentConfiguration, agent_id))


@router.put("/agents/{agent_id}/configuration", response_model=AgentConfigurationView)
async def update_configuration(
    agent_id: uuid.UUID,
    body: AgentConfigurationBody,
    user: Annotated[User, Depends(admin_user)],
    session: Annotated[AsyncSession, Depends(database_session)],
) -> AgentConfigurationView:
    agent = await session.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent not found")
    return configuration_view(
        await save_configuration(agent, body, user, session, "agent_configuration.update")
    )


@router.post(
    "/agents/{agent_id}/configuration/confirm-archive", response_model=AgentConfigurationView
)
async def confirm_archive(
    agent_id: uuid.UUID,
    body: ArchiveConfirmation,
    user: Annotated[User, Depends(admin_user)],
    session: Annotated[AsyncSession, Depends(database_session)],
) -> AgentConfigurationView:
    agent = await session.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent not found")
    current = configuration_view(
        await session.get(DesiredAgentConfiguration, agent_id)
    ).configuration
    updated = current.model_copy(update={"confirmed_archive": body.path})
    return configuration_view(
        await save_configuration(agent, updated, user, session, "archive.confirm")
    )


@router.post("/agents/{agent_id}/discovery/rescan", response_model=AgentConfigurationView)
async def request_rescan(
    agent_id: uuid.UUID,
    user: Annotated[User, Depends(admin_user)],
    session: Annotated[AsyncSession, Depends(database_session)],
) -> AgentConfigurationView:
    agent = await session.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent not found")
    current = configuration_view(
        await session.get(DesiredAgentConfiguration, agent_id)
    ).configuration
    updated = current.model_copy(update={"rescan_requested_at": datetime.now(UTC)})
    return configuration_view(
        await save_configuration(agent, updated, user, session, "discovery.rescan_request")
    )
