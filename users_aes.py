"""
Example: storing users (uuid, email, AES-encrypted password) with SQLAlchemy 2.0.

pip install sqlalchemy cryptography
"""
import base64
import hashlib
import os
import re
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import String, TypeDecorator, Uuid, create_engine, inspect, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column


# --- Key handling ---------------------------------------------------------
KEY_FILE = Path(os.environ.get("AES_KEY_FILE", "aes.key"))


def key_from_secret(secret: str) -> bytes:
    """Accept a base64-encoded 32-byte key; anything else is stretched with SHA-256."""
    try:
        raw = base64.b64decode(secret, validate=True)
        if len(raw) == 32:
            return raw
    except ValueError:
        pass
    return hashlib.sha256(secret.encode("utf-8")).digest()


def load_key() -> bytes:
    """Key lookup order: AES_KEY env var -> key file -> generate and save to key file.

    In production prefer a secret manager / env var; keep the key file out of git
    and never store it next to the database backups.
    """
    env_key = os.environ.get("AES_KEY")
    if env_key:
        return key_from_secret(env_key)

    if os.environ.get("DATABASE_URL"):
        # Hosted mode: free hosts have ephemeral disks, so a key file would be lost on
        # restart and every stored password/message would become undecryptable.
        raise RuntimeError("AES_KEY must be set when DATABASE_URL is set.")

    if KEY_FILE.exists():
        return base64.b64decode(KEY_FILE.read_text().strip())

    # First run: generate a key and persist it (owner read/write only)
    key = AESGCM.generate_key(bit_length=256)
    fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(base64.b64encode(key).decode("ascii"))
    os.chmod(KEY_FILE, 0o600)
    print(f"[info] Generated new AES key and saved it to {KEY_FILE.resolve()}")
    return key


KEY = load_key()
AES = AESGCM(KEY)


# --- Transparent encrypted column type -----------------------------------
class AESEncryptedString(TypeDecorator):
    """Encrypts on write, decrypts on read. Stored as base64(nonce || ciphertext+tag)."""

    impl = String
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        nonce = os.urandom(12)  # unique per encryption, required for GCM
        ct = AES.encrypt(nonce, value.encode("utf-8"), None)
        return base64.b64encode(nonce + ct).decode("ascii")

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        raw = base64.b64decode(value)
        nonce, ct = raw[:12], raw[12:]
        return AES.decrypt(nonce, ct, None).decode("utf-8")


# --- Model ---------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    # Stored lowercase, so usernames are case-insensitive. 3-20 chars: a-z, 0-9, underscore.
    username: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password: Mapped[str] = mapped_column(AESEncryptedString(512), nullable=False)

    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username} email={self.email}>"


def ensure_schema(engine) -> None:
    """Create tables, and upgrade an older users table that has no username column.

    Existing users get a username generated from their email (alice@x.com -> alice,
    with a number appended on collisions).
    """
    Base.metadata.create_all(engine)
    if "username" in {c["name"] for c in inspect(engine).get_columns("users")}:
        return

    with engine.begin() as conn:
        conn.exec_driver_sql("ALTER TABLE users ADD COLUMN username VARCHAR(32)")
        rows = conn.exec_driver_sql("SELECT id, email FROM users").fetchall()
        taken: set[str] = set()
        for row_id, email in rows:
            base = re.sub(r"[^a-z0-9_]", "", email.split("@")[0].lower())[:17]
            if len(base) < 3:
                base = f"{base}user"
            name, n = base, 1
            while name in taken:
                n += 1
                name = f"{base}{n}"
            taken.add(name)
            conn.exec_driver_sql("UPDATE users SET username = ? WHERE id = ?", (name, row_id))
        conn.exec_driver_sql("CREATE UNIQUE INDEX ix_users_username ON users (username)")


# --- Demo ----------------------------------------------------------------
if __name__ == "__main__":
    engine = create_engine("sqlite:///users.db", echo=False)
    ensure_schema(engine)

    with Session(engine) as session:
        user = session.scalar(select(User).where(User.email == "alice@example.com"))
        if user is None:
            user = User(username="alice", email="alice@example.com", password="s3cret-p@ssw0rd")
            session.add(user)
            session.commit()
            print("Created:", user)
        else:
            print("Already exists:", user)

        # Read back through the ORM -> decrypted automatically
        fetched = session.scalar(select(User).where(User.email == "alice@example.com"))
        print("Decrypted password via ORM:", fetched.password)

        # Raw DB value -> encrypted
        raw = session.connection().exec_driver_sql(
            "SELECT password FROM users WHERE email = ?", ("alice@example.com",)
        ).scalar()
        print("Raw value in DB:", raw)
