import argparse
import asyncio
import getpass

from sqlalchemy import select

from app.database import session_factory
from app.models import User, UserRole
from app.security import hash_password


async def create_user(role: UserRole, username: str, password: str) -> None:
    if len(password) < 12:
        raise SystemExit("Password must contain at least 12 characters")
    async with session_factory() as session:
        if await session.scalar(select(User).where(User.username == username)):
            raise SystemExit("User already exists")
        session.add(User(username=username, password_hash=hash_password(password), role=role))
        await session.commit()
    print(f"Created {role.value}: {username}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["create-admin", "create-viewer"])
    args = parser.parse_args()
    role = UserRole.admin if args.command == "create-admin" else UserRole.viewer
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match")
    asyncio.run(create_user(role, username, password))


if __name__ == "__main__":
    main()
