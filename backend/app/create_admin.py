"""Create the FIRST admin (nobody can log in to create one through the API).

    docker compose run --rm backend python -m app.create_admin <username>

The password is typed at a hidden prompt, so it never appears in shell history,
process lists or logs. It must satisfy the same policy as the API.
"""
import getpass
import sys

from sqlalchemy import select

from app.core.security import hash_password
from app.db.session import SessionLocal
from app.models import Role, User
from app.schemas.user import UserCreate


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python -m app.create_admin <username>")
        return 2
    password = getpass.getpass("Password: ")
    if password != getpass.getpass("Repeat password: "):
        print("Passwords do not match.")
        return 1
    try:
        data = UserCreate(username=sys.argv[1], password=password, role=Role.admin)
    except ValueError as exc:
        print("Invalid input:", "; ".join(e["msg"] for e in exc.errors()))  # never echoes the password
        return 1
    with SessionLocal() as db:
        if db.scalar(select(User.id).where(User.username == data.username)):
            print("That username already exists.")
            return 1
        db.add(User(username=data.username, password_hash=hash_password(data.password),
                    role=Role.admin.value, is_active=True))
        db.commit()
    print(f"Admin '{data.username}' created.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
