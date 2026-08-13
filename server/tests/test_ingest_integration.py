import os
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import delete

pytestmark = pytest.mark.skipif(
    os.getenv("SCADAGUARD_RUN_DB_TESTS") != "1",
    reason="requires an explicitly disposable PostgreSQL database",
)


@pytest.mark.asyncio
async def test_agent_authentication_identity_and_idempotency() -> None:
    from httpx import ASGITransport, AsyncClient

    from app.database import session_factory
    from app.main import app
    from app.models import Agent, AgentToken, HealthState, IngestedMessage, Site
    from app.security import create_agent_token

    suffix = uuid.uuid4().hex
    raw_token, token_hash, token_prefix = create_agent_token()
    async with session_factory() as session:
        site = Site(slug=f"ci-{suffix}", display_name="CI site", timezone="UTC")
        session.add(site)
        await session.flush()
        agent = Agent(
            agent_id=f"agent-{suffix}",
            site_id=site.id,
            host_id=f"host-{suffix}",
            display_name="CI agent",
            current_status=HealthState.unknown,
        )
        session.add(agent)
        await session.flush()
        session.add(
            AgentToken(
                agent_id=agent.id,
                token_hash=token_hash,
                token_prefix=token_prefix,
            )
        )
        await session.commit()

    message_id = uuid.uuid4()
    envelope = {
        "message_id": str(message_id),
        "protocol_version": 1,
        "message_kind": "heartbeat",
        "agent_id": f"agent-{suffix}",
        "site_id": f"ci-{suffix}",
        "host_id": f"host-{suffix}",
        "boot_id": str(uuid.uuid4()),
        "sequence_number": 1,
        "created_at": datetime.now(UTC).isoformat(),
        "payload": {"status": "ok", "agent_version": "0.1.0"},
    }
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        invalid = await client.post(
            "/api/v1/agent/heartbeat",
            json=envelope,
            headers={"Authorization": "Bearer invalid"},
        )
        assert invalid.status_code == 401

        accepted = await client.post(
            "/api/v1/agent/heartbeat",
            json=envelope,
            headers={"Authorization": f"Bearer {raw_token}"},
        )
        assert accepted.status_code == 200
        assert accepted.json()["duplicate"] is False

        duplicate = await client.post(
            "/api/v1/agent/heartbeat",
            json=envelope,
            headers={"Authorization": f"Bearer {raw_token}"},
        )
        assert duplicate.status_code == 200
        assert duplicate.json()["duplicate"] is True

        envelope["message_id"] = str(uuid.uuid4())
        envelope["agent_id"] = "wrong-agent"
        mismatch = await client.post(
            "/api/v1/agent/heartbeat",
            json=envelope,
            headers={"Authorization": f"Bearer {raw_token}"},
        )
        assert mismatch.status_code == 403

    async with session_factory() as session:
        await session.execute(delete(IngestedMessage).where(IngestedMessage.agent_id == agent.id))
        await session.execute(delete(AgentToken).where(AgentToken.agent_id == agent.id))
        await session.execute(delete(Agent).where(Agent.id == agent.id))
        await session.execute(delete(Site).where(Site.slug == f"ci-{suffix}"))
        await session.commit()
