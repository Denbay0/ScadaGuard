import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import current_user
from app.database import database_session
from app.models import Agent, AgentToken, AuditLog, HealthState, Site, User, UserRole
from app.security import create_agent_token

router = APIRouter(prefix="/api/v1", tags=["administration"])


async def admin_user(user: Annotated[User, Depends(current_user)]) -> User:
    if user.role != UserRole.admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Administrator role required")
    return user


class SiteCreate(BaseModel):
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,98}[a-z0-9]$")
    display_name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)
    timezone: str = Field(default="Europe/Moscow", min_length=1, max_length=64)


class SitePatch(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    timezone: str | None = Field(default=None, min_length=1, max_length=64)
    enabled: bool | None = None


class SiteView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    slug: str
    display_name: str
    description: str
    timezone: str
    enabled: bool
    created_at: datetime
    updated_at: datetime


class AgentCreate(BaseModel):
    agent_id: str = Field(min_length=1, max_length=200)
    site_id: uuid.UUID
    host_id: str = Field(min_length=1, max_length=200)
    display_name: str = Field(min_length=1, max_length=200)
    heartbeat_interval_seconds: int = Field(default=30, ge=5, le=3600)


class AgentPatch(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    enabled: bool | None = None
    heartbeat_interval_seconds: int | None = Field(default=None, ge=5, le=3600)


class AgentView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    agent_id: str
    site_id: uuid.UUID
    host_id: str
    display_name: str
    enabled: bool
    version: str | None
    protocol_version: int | None
    last_seen_at: datetime | None
    current_status: HealthState
    boot_id: str | None
    configuration_hash: str | None
    heartbeat_interval_seconds: int


class TokenCreated(BaseModel):
    token_id: uuid.UUID
    token: str
    token_prefix: str
    warning: str = "Сохраните токен сейчас: повторно получить его невозможно."


def audit(user: User, action: str, target_type: str, target_id: str) -> AuditLog:
    return AuditLog(
        user_id=user.id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details={},
    )


@router.post("/sites", response_model=SiteView, status_code=status.HTTP_201_CREATED)
async def create_site(
    value: SiteCreate,
    user: Annotated[User, Depends(admin_user)],
    session: Annotated[AsyncSession, Depends(database_session)],
) -> Site:
    if await session.scalar(select(Site.id).where(Site.slug == value.slug)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Site slug already exists")
    site = Site(**value.model_dump())
    session.add(site)
    await session.flush()
    session.add(audit(user, "site.create", "site", str(site.id)))
    await session.commit()
    await session.refresh(site)
    return site


@router.get("/sites/{site_id}", response_model=SiteView)
async def get_site(
    site_id: uuid.UUID,
    _: Annotated[User, Depends(current_user)],
    session: Annotated[AsyncSession, Depends(database_session)],
) -> Site:
    site = await session.get(Site, site_id)
    if site is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Site not found")
    return site


@router.patch("/sites/{site_id}", response_model=SiteView)
async def update_site(
    site_id: uuid.UUID,
    value: SitePatch,
    user: Annotated[User, Depends(admin_user)],
    session: Annotated[AsyncSession, Depends(database_session)],
) -> Site:
    site = await session.get(Site, site_id)
    if site is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Site not found")
    for key, item in value.model_dump(exclude_unset=True).items():
        setattr(site, key, item)
    session.add(audit(user, "site.update", "site", str(site.id)))
    await session.commit()
    await session.refresh(site)
    return site


@router.get("/agents", response_model=list[AgentView])
async def agents(
    _: Annotated[User, Depends(current_user)],
    session: Annotated[AsyncSession, Depends(database_session)],
    site_id: uuid.UUID | None = None,
) -> list[Agent]:
    query = select(Agent).order_by(Agent.display_name)
    if site_id:
        query = query.where(Agent.site_id == site_id)
    return list(await session.scalars(query))


@router.post("/agents", response_model=AgentView, status_code=status.HTTP_201_CREATED)
async def create_agent(
    value: AgentCreate,
    user: Annotated[User, Depends(admin_user)],
    session: Annotated[AsyncSession, Depends(database_session)],
) -> Agent:
    if await session.get(Site, value.site_id) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Site does not exist")
    if await session.scalar(select(Agent.id).where(Agent.agent_id == value.agent_id)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Agent ID already exists")
    agent = Agent(**value.model_dump())
    session.add(agent)
    await session.flush()
    session.add(audit(user, "agent.create", "agent", str(agent.id)))
    await session.commit()
    await session.refresh(agent)
    return agent


@router.get("/agents/{agent_id}", response_model=AgentView)
async def get_agent(
    agent_id: uuid.UUID,
    _: Annotated[User, Depends(current_user)],
    session: Annotated[AsyncSession, Depends(database_session)],
) -> Agent:
    agent = await session.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent not found")
    return agent


@router.patch("/agents/{agent_id}", response_model=AgentView)
async def update_agent(
    agent_id: uuid.UUID,
    value: AgentPatch,
    user: Annotated[User, Depends(admin_user)],
    session: Annotated[AsyncSession, Depends(database_session)],
) -> Agent:
    agent = await session.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent not found")
    for key, item in value.model_dump(exclude_unset=True).items():
        setattr(agent, key, item)
    session.add(audit(user, "agent.update", "agent", str(agent.id)))
    await session.commit()
    await session.refresh(agent)
    return agent


@router.post("/agents/{agent_id}/tokens", response_model=TokenCreated)
async def issue_agent_token(
    agent_id: uuid.UUID,
    user: Annotated[User, Depends(admin_user)],
    session: Annotated[AsyncSession, Depends(database_session)],
) -> TokenCreated:
    if await session.get(Agent, agent_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent not found")
    raw, token_hash, prefix = create_agent_token()
    token = AgentToken(
        agent_id=agent_id,
        token_hash=token_hash,
        token_prefix=prefix,
        created_at=datetime.now(UTC),
    )
    session.add(token)
    await session.flush()
    session.add(audit(user, "agent_token.create", "agent_token", str(token.id)))
    await session.commit()
    return TokenCreated(token_id=token.id, token=raw, token_prefix=prefix)


@router.delete("/agents/{agent_id}/tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_agent_token(
    agent_id: uuid.UUID,
    token_id: uuid.UUID,
    user: Annotated[User, Depends(admin_user)],
    session: Annotated[AsyncSession, Depends(database_session)],
) -> None:
    token = await session.get(AgentToken, token_id)
    if token is None or token.agent_id != agent_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Token not found")
    token.revoked_at = datetime.now(UTC)
    session.add(audit(user, "agent_token.revoke", "agent_token", str(token.id)))
    await session.commit()
