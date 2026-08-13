import asyncio
import time
from collections import defaultdict, deque
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import database_session
from app.models import User
from app.security import verify_password
from app.sessions import create_session, verify_session

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])
settings = get_settings()
SESSION_COOKIE = "scadaguard_session"


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=1_000)


class CurrentUser(BaseModel):
    username: str
    role: str


class LoginLimiter:
    def __init__(self, attempts: int = 5, window_seconds: int = 60) -> None:
        self.attempts = attempts
        self.window_seconds = window_seconds
        self._attempts: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def check(self, key: str) -> None:
        async with self._lock:
            now = time.monotonic()
            values = self._attempts[key]
            while values and values[0] < now - self.window_seconds:
                values.popleft()
            if len(values) >= self.attempts:
                raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many login attempts")
            values.append(now)

    async def reset(self, key: str) -> None:
        async with self._lock:
            self._attempts.pop(key, None)


limiter = LoginLimiter()


async def current_user(
    request: Request,
    session: Annotated[AsyncSession, Depends(database_session)],
) -> User:
    cookie = request.cookies.get(SESSION_COOKIE)
    user_id = verify_session(cookie or "", settings.secret_key.get_secret_value())
    user = await session.get(User, user_id) if user_id else None
    if user is None or not user.active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    return user


@router.post("/login", response_model=CurrentUser)
async def login(
    credentials: LoginRequest,
    request: Request,
    response: Response,
    session: Annotated[AsyncSession, Depends(database_session)],
) -> CurrentUser:
    key = f"{request.client.host if request.client else 'unknown'}:{credentials.username.lower()}"
    await limiter.check(key)
    user = await session.scalar(select(User).where(User.username == credentials.username))
    if (
        user is None
        or not user.active
        or not verify_password(credentials.password, user.password_hash)
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
    await limiter.reset(key)
    response.set_cookie(
        SESSION_COOKIE,
        create_session(user.id, settings.secret_key.get_secret_value()),
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        max_age=28_800,
        path="/",
    )
    return CurrentUser(username=user.username, role=user.role.value)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")


@router.get("/me", response_model=CurrentUser)
async def me(user: Annotated[User, Depends(current_user)]) -> CurrentUser:
    return CurrentUser(username=user.username, role=user.role.value)
