"""Add agent discovery and desired configuration state."""

from collections.abc import Sequence

from alembic import op
from app.models import AgentDiscoveryReport, DesiredAgentConfiguration

revision: str = "0002_discovery_configuration"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    AgentDiscoveryReport.__table__.create(bind=bind, checkfirst=True)
    DesiredAgentConfiguration.__table__.create(bind=bind, checkfirst=True)


def downgrade() -> None:
    bind = op.get_bind()
    DesiredAgentConfiguration.__table__.drop(bind=bind, checkfirst=True)
    AgentDiscoveryReport.__table__.drop(bind=bind, checkfirst=True)
