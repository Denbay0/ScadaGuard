import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class AgentEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message_id: uuid.UUID
    protocol_version: Literal[1]
    message_kind: Literal["heartbeat", "check_results", "incidents", "signal_samples", "discovery"]
    agent_id: str = Field(min_length=1, max_length=200)
    site_id: str = Field(min_length=1, max_length=200)
    host_id: str = Field(min_length=1, max_length=200)
    boot_id: uuid.UUID
    sequence_number: int = Field(ge=1)
    created_at: datetime
    payload: dict[str, Any]

    @model_validator(mode="after")
    def timestamps_are_aware(self) -> "AgentEnvelope":
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must contain a timezone")
        return self


class IngestResponse(BaseModel):
    accepted: bool = True
    duplicate: bool = False
    message_id: uuid.UUID


class CheckResultItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    check_id: str = Field(min_length=1, max_length=250)
    component: str = Field(min_length=1, max_length=250)
    status: Literal["unknown", "ok", "warning", "critical"]
    message: str
    observed_at: datetime
    details: dict[str, Any] = Field(default_factory=dict)


class IncidentBody(BaseModel):
    model_config = ConfigDict(extra="allow")

    incident_id: uuid.UUID
    incident_key: str = Field(min_length=1, max_length=500)
    component: str = Field(min_length=1, max_length=250)
    severity: Literal["unknown", "ok", "warning", "critical"]
    title: str = Field(min_length=1, max_length=500)
    description: str
    opened_at: datetime
    closed_at: datetime | None
    active: bool
    details: dict[str, Any] = Field(default_factory=dict)
    source: str = Field(default="agent", min_length=1, max_length=50)
    last_seen_at: datetime
    occurrence_count: int = Field(default=1, ge=1)


class IncidentEventItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str = Field(min_length=1, max_length=50)
    occurred_at: datetime
    incident: IncidentBody


class SignalSampleItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    signal_id: str = Field(min_length=1, max_length=300)
    value: float
    source_timestamp: datetime
    received_timestamp: datetime
    quality: str = Field(min_length=1, max_length=100)


class DiscoveryPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    scan_id: str = Field(min_length=1, max_length=100)
    scanned_at: datetime
    masterscada: dict[str, Any]
    components: list[dict[str, Any]] = Field(default_factory=list)
    archive_candidates: list[dict[str, Any]] = Field(default_factory=list)
    log_candidates: list[dict[str, Any]] = Field(default_factory=list)
    opcua_candidates: list[dict[str, Any] | str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def scanned_at_is_aware(self) -> "DiscoveryPayload":
        if self.scanned_at.tzinfo is None:
            raise ValueError("scanned_at must contain a timezone")
        return self
