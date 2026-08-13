import argparse
import asyncio
import getpass
import os

from sqlalchemy import select

from app.config import get_settings
from app.database import session_factory
from app.models import Agent, AgentToken, Site, User, UserRole
from app.security import create_agent_token, hash_password


async def create_user(role: UserRole, username: str, password: str) -> None:
    if len(password) < 12:
        raise SystemExit("Password must contain at least 12 characters")
    async with session_factory() as session:
        if await session.scalar(select(User).where(User.username == username)):
            print(f"User already exists: {username}")
            return
        session.add(User(username=username, password_hash=hash_password(password), role=role))
        await session.commit()
    print(f"Created {role.value}: {username}")


async def ensure_site(slug: str, display_name: str) -> Site:
    async with session_factory() as session:
        site = await session.scalar(select(Site).where(Site.slug == slug))
        if site is None:
            site = Site(slug=slug, display_name=display_name, timezone="Europe/Moscow")
            session.add(site)
            await session.commit()
            await session.refresh(site)
            print(f"Created site: {site.slug} ({site.id})")
        else:
            print(f"Site already exists: {site.slug} ({site.id})")
        return site


async def ensure_agent(
    agent_id: str,
    site_slug: str,
    host_id: str,
    display_name: str,
    heartbeat_interval_seconds: int = 30,
    update_existing: bool = False,
) -> Agent:
    if not 5 <= heartbeat_interval_seconds <= 3600:
        raise SystemExit("Heartbeat interval must be between 5 and 3600 seconds")
    async with session_factory() as session:
        site = await session.scalar(select(Site).where(Site.slug == site_slug))
        if site is None:
            raise SystemExit(f"Site does not exist: {site_slug}")
        agent = await session.scalar(select(Agent).where(Agent.agent_id == agent_id))
        if agent is None:
            agent = Agent(
                agent_id=agent_id,
                site_id=site.id,
                host_id=host_id,
                display_name=display_name,
                heartbeat_interval_seconds=heartbeat_interval_seconds,
            )
            session.add(agent)
            await session.commit()
            await session.refresh(agent)
            print(f"Created agent: {agent.agent_id} ({agent.id})")
        else:
            if update_existing:
                agent.site_id = site.id
                agent.host_id = host_id
                agent.display_name = display_name
                agent.heartbeat_interval_seconds = heartbeat_interval_seconds
                await session.commit()
            print(f"Agent already exists: {agent.agent_id} ({agent.id})")
        return agent


async def issue_token(agent_id: str) -> str:
    async with session_factory() as session:
        agent = await session.scalar(select(Agent).where(Agent.agent_id == agent_id))
        if agent is None:
            raise SystemExit(f"Agent does not exist: {agent_id}")
        raw, token_hash, prefix = create_agent_token()
        session.add(
            AgentToken(
                agent_id=agent.id,
                token_hash=token_hash,
                token_prefix=prefix,
            )
        )
        await session.commit()
    return raw


def require_development() -> None:
    public_url = str(get_settings().public_url).lower()
    if "localhost" not in public_url and "127.0.0.1" not in public_url:
        raise SystemExit("bootstrap-demo is allowed only with a loopback public URL")


async def bootstrap_demo(host_id: str) -> None:
    require_development()
    await ensure_site("local-masterscada", "Локальная MasterSCADA")
    await ensure_agent(
        "local-masterscada",
        "local-masterscada",
        host_id,
        "Локальная MasterSCADA",
        heartbeat_interval_seconds=10,
        update_existing=True,
    )
    token = await issue_token("local-masterscada")
    print("Development bootstrap is ready")
    print(f"SCADAGUARD_API_TOKEN={token}")


def user_credentials(args: argparse.Namespace) -> tuple[str, str]:
    username = args.username or input("Username: ").strip()
    if args.username:
        password = os.getenv("SCADAGUARD_BOOTSTRAP_PASSWORD", "")
        if not password:
            raise SystemExit(
                "SCADAGUARD_BOOTSTRAP_PASSWORD is required for non-interactive user creation"
            )
        return username, password
    password = getpass.getpass("Password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match")
    return username, password


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    for command in ("create-admin", "create-viewer"):
        user = commands.add_parser(command)
        user.add_argument("--username")
    site = commands.add_parser("create-site")
    site.add_argument("--slug", required=True)
    site.add_argument("--name", required=True)
    agent = commands.add_parser("create-agent")
    agent.add_argument("--agent-id", required=True)
    agent.add_argument("--site-slug", required=True)
    agent.add_argument("--host-id", required=True)
    agent.add_argument("--name", required=True)
    agent.add_argument("--heartbeat-interval-seconds", type=int, default=30)
    token = commands.add_parser("create-agent-token")
    token.add_argument("--agent-id", required=True)
    demo = commands.add_parser("bootstrap-demo")
    demo.add_argument("--host-id", default=os.getenv("COMPUTERNAME", "local-windows"))
    return result


def main() -> None:
    args = parser().parse_args()
    if args.command in {"create-admin", "create-viewer"}:
        username, password = user_credentials(args)
        role = UserRole.admin if args.command == "create-admin" else UserRole.viewer
        asyncio.run(create_user(role, username, password))
    elif args.command == "create-site":
        asyncio.run(ensure_site(args.slug, args.name))
    elif args.command == "create-agent":
        asyncio.run(
            ensure_agent(
                args.agent_id,
                args.site_slug,
                args.host_id,
                args.name,
                args.heartbeat_interval_seconds,
            )
        )
    elif args.command == "create-agent-token":
        print(f"SCADAGUARD_API_TOKEN={asyncio.run(issue_token(args.agent_id))}")
    else:
        asyncio.run(bootstrap_demo(args.host_id))


if __name__ == "__main__":
    main()
