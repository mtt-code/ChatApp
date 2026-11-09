"""
Shared account layer: database engine + register / authenticate.
Used by both the web chat (app.py) and the desktop login (login_app.py).

DATABASE_URL (optional): e.g. a Neon/Supabase Postgres URL. Defaults to local SQLite.
"""
import hmac
import os
import re

from sqlalchemy import create_engine, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from users_aes import User, ensure_schema

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_RE = re.compile(r"^[a-z0-9_]{3,20}$")  # applied after lowercasing
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 128


def make_engine():
    url = os.environ.get("DATABASE_URL", "sqlite:///users.db")
    # Hosts hand out postgres:// or postgresql:// URLs; use the psycopg 3 driver.
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://"):]
    if url.startswith("sqlite"):
        return create_engine(url, connect_args={"check_same_thread": False})
    # pre_ping/recycle: serverless Postgres (Neon) drops idle connections.
    return create_engine(url, pool_pre_ping=True, pool_recycle=300)


engine = make_engine()
ensure_schema(engine)  # creates tables / adds the username column to an old database


def authenticate(identifier: str, password: str):
    """Log in with username OR email. Returns (id, username, email) or None."""
    ident = identifier.strip().lower()
    column = User.email if "@" in ident else User.username
    with Session(engine) as session:
        user = session.scalar(select(User).where(column == ident))
        # Password is decrypted transparently by the column type; compare in constant time.
        if user and hmac.compare_digest(user.password.encode(), password.encode()):
            return str(user.id), user.username, user.email
    return None


def register(username: str, email: str, password: str):
    """Validate and create a user. Returns an error message, or None on success."""
    username, email = username.strip().lower(), email.strip().lower()
    if not USERNAME_RE.match(username):
        return "Username must be 3-20 characters: letters, numbers or underscore."
    if not EMAIL_RE.match(email):
        return "Please enter a valid email address."
    if not MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN:
        return f"Password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} characters."
    try:
        with Session(engine) as session:
            clash = session.scalars(
                select(User).where(or_(User.username == username, User.email == email))
            ).first()
            if clash:
                return (
                    "That username is already taken."
                    if clash.username == username
                    else "An account with this email already exists."
                )
            session.add(User(username=username, email=email, password=password))
            session.commit()
    except IntegrityError:  # race condition: same name registered in between
        return "That username or email is already registered."
    return None
