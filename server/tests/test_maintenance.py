from datetime import UTC, datetime, timedelta

from app.maintenance import heartbeat_is_overdue


def test_agent_without_first_heartbeat_is_not_offline() -> None:
    now = datetime.now(UTC)

    assert heartbeat_is_overdue(None, 30, 90, now) is False


def test_agent_becomes_offline_after_effective_threshold() -> None:
    now = datetime.now(UTC)

    assert heartbeat_is_overdue(now - timedelta(seconds=91), 30, 90, now) is True
    assert heartbeat_is_overdue(now - timedelta(seconds=91), 60, 90, now) is False
