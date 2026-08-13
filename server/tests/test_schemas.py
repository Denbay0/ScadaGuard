import uuid
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

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
