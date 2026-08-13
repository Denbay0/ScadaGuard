import os
import uuid
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

os.environ.setdefault("SCADAGUARD_SECRET_KEY", "test-only-secret-key-at-least-32-characters")

from app.api.discovery import AgentConfigurationBody, ArchiveMapping, config_hash  # noqa: E402
from app.schemas import AgentEnvelope


def valid_message() -> dict[str, object]:
    return {
        "message_id": str(uuid.uuid4()),
        "protocol_version": 1,
        "message_kind": "heartbeat",
        "agent_id": "agent",
        "site_id": "site",
        "host_id": "host",
        "boot_id": str(uuid.uuid4()),
        "sequence_number": 1,
        "created_at": datetime.now(UTC).isoformat(),
        "payload": {},
    }


def test_protocol_v1_message_is_valid() -> None:
    assert AgentEnvelope.model_validate(valid_message()).protocol_version == 1


def test_unknown_protocol_is_rejected() -> None:
    message = valid_message()
    message["protocol_version"] = 2
    with pytest.raises(ValidationError):
        AgentEnvelope.model_validate(message)


def test_naive_timestamp_is_rejected() -> None:
    message = valid_message()
    message["created_at"] = "2026-08-05T10:00:00"
    with pytest.raises(ValidationError):
        AgentEnvelope.model_validate(message)


def test_discovery_message_kind_is_supported() -> None:
    message = valid_message()
    message["message_kind"] = "discovery"
    assert AgentEnvelope.model_validate(message).message_kind == "discovery"


def test_central_configuration_allows_only_safe_read_only_paths() -> None:
    value = AgentConfigurationBody(confirmed_archive=r"D:\MasterSCADA\archive.db")
    assert value.confirmed_archive == r"D:\MasterSCADA\archive.db"
    for unsafe in ["C:\\", r"\\server\share\archive.db", r"C:\Windows\archive.db"]:
        with pytest.raises(ValidationError):
            AgentConfigurationBody(confirmed_archive=unsafe)


def test_central_configuration_hash_is_deterministic() -> None:
    left = {"monitoring_interval_seconds": 30, "confirmed_logs": []}
    right = {"confirmed_logs": [], "monitoring_interval_seconds": 30}
    assert config_hash(left) == config_hash(right)


def test_archive_mapping_accepts_only_safe_sqlite_identifiers() -> None:
    mapping = ArchiveMapping(
        table="history_2026",
        timestamp_column="recorded_at",
        signal_id_column="item_id",
        value_column="value",
    )
    assert mapping.quality_column is None
    with pytest.raises(ValidationError):
        AgentConfigurationBody(archive_mapping=mapping)
    with pytest.raises(ValidationError):
        ArchiveMapping(
            table="history; DROP TABLE x",
            timestamp_column="recorded_at",
            signal_id_column="item_id",
            value_column="value",
        )


def test_openapi_exposes_discovery_and_configuration_endpoints() -> None:
    from app.main import app

    paths = app.openapi()["paths"]
    required = {
        "/api/v1/agent/discovery",
        "/api/v1/agent/config",
        "/api/v1/agent/config/status",
        "/api/v1/agents/{agent_id}/discovery",
        "/api/v1/agents/{agent_id}/configuration",
        "/api/v1/agents/{agent_id}/configuration/confirm-archive",
        "/api/v1/agents/{agent_id}/discovery/rescan",
    }
    assert required <= paths.keys()
