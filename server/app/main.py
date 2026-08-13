import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

import structlog
from fastapi import Depends, FastAPI
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.admin import router as admin_router
from app.api.agent_ingest import router as agent_ingest_router
from app.api.auth import router as auth_router
from app.api.dashboard import router as dashboard_router
from app.api.discovery import router as discovery_router
from app.api.resources import router as resources_router
from app.config import get_settings
from app.database import database_session
from app.maintenance import maintenance_loop

settings = get_settings()
logging.basicConfig(level=settings.log_level)
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    import asyncio

    stop = asyncio.Event()
    task = asyncio.create_task(maintenance_loop(stop))
    try:
        yield
    finally:
        stop.set()
        await task


app = FastAPI(title="ScadaGuard Server", version="0.1.0", lifespan=lifespan)
app.include_router(admin_router)
app.include_router(agent_ingest_router)
app.include_router(auth_router)
app.include_router(dashboard_router)
app.include_router(discovery_router)
app.include_router(resources_router)


@app.get("/health", tags=["operations"])
@app.get("/healthz", tags=["operations"])
async def health(
    session: Annotated[AsyncSession, Depends(database_session)],
) -> dict[str, str]:
    await session.execute(text("SELECT 1"))
    return {"status": "ok"}
