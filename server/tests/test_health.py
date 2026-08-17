import pytest

from app.main import health


class FakeSession:
    async def execute(self, _statement: object) -> None:
        return None

    async def scalar(self, _statement: object) -> str:
        return "0002_discovery_configuration"


@pytest.mark.asyncio
async def test_health_includes_build_and_migration_metadata() -> None:
    result = await health(FakeSession())  # type: ignore[arg-type]

    assert result["status"] == "ok"
    assert result["version"] == "0.1.0"
    assert result["build"]
    assert result["database_migration_revision"] == "0002_discovery_configuration"
