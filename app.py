"""
Real-time chat server: FastAPI + WebSockets + SQLAlchemy, on top of auth.py / users_aes.py.

Local:   uvicorn app:app --reload
Hosted:  see README.md (Render + Neon)
"""
import asyncio
import hashlib
import json
import re
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from itsdangerous import BadSignature, URLSafeTimedSerializer
from pydantic import BaseModel
from sqlalchemy import DateTime, ForeignKey, String, Uuid, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from auth import authenticate, engine, register
from users_aes import KEY, AESEncryptedString, Base, User

ROOM_RE = re.compile(r"^[a-z0-9_-]{1,30}$")
MAX_MESSAGE_LEN = 500
HISTORY_LIMIT = 50
SESSION_COOKIE = "session"
SESSION_MAX_AGE = 7 * 24 * 3600


# --- Models --------------------------------------------------------------
class Message(Base):
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(primary_key=True)
    room: Mapped[str] = mapped_column(String(30), index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"), index=True)
    # Encrypted at rest with the same AES-GCM column type as passwords.
    text: Mapped[str] = mapped_column(AESEncryptedString(4000))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


Base.metadata.create_all(engine)  # creates the messages table (users already exist)


def iso(dt: datetime) -> str:
    if dt.tzinfo is None:  # SQLite returns naive datetimes; they are UTC
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def save_message(room: str, user_id: str, text: str) -> dict:
    with Session(engine) as session:
        msg = Message(room=room, user_id=uuid.UUID(user_id), text=text)
        session.add(msg)
        session.commit()
        return {"id": msg.id, "room": room, "text": msg.text, "ts": iso(msg.created_at)}


def load_history(room: str, before: int | None, limit: int) -> list[dict]:
    query = (
        select(Message.id, User.username, Message.text, Message.created_at)
        .join(User, User.id == Message.user_id)
        .where(Message.room == room)
        .order_by(Message.id.desc())
        .limit(limit)
    )
    if before:
        query = query.where(Message.id < before)
    with Session(engine) as session:
        rows = session.execute(query).all()
    return [
        {"id": r.id, "username": r.username, "text": r.text, "ts": iso(r.created_at)}
        for r in reversed(rows)
    ]


# --- Sessions (signed cookie; the signing key is derived from the AES key) ----
serializer = URLSafeTimedSerializer(
    hashlib.sha256(b"chat-session:" + KEY).digest(), salt="session"
)


def user_from_token(token: str):
    """Return (id, username) for a valid session token, else None."""
    try:
        user_id = uuid.UUID(serializer.loads(token, max_age=SESSION_MAX_AGE))
    except (BadSignature, ValueError):
        return None
    with Session(engine) as session:
        user = session.get(User, user_id)
        return (str(user.id), user.username) if user else None


def current_user(request: Request):
    ident = user_from_token(request.cookies.get(SESSION_COOKIE, ""))
    if ident is None:
        raise HTTPException(401, "Not signed in.")
    return ident


# --- Tiny in-memory rate limiter (fine for a single free-tier instance) ----
_failures: dict[str, deque] = defaultdict(deque)


def too_many(key: str, limit: int, window: float) -> bool:
    now = time.monotonic()
    q = _failures[key]
    while q and now - q[0] > window:
        q.popleft()
    return len(q) >= limit


def record(key: str) -> None:
    if len(_failures) > 10_000:
        _failures.clear()
    _failures[key].append(time.monotonic())


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    return forwarded or (request.client.host if request.client else "unknown")


# --- HTTP API ------------------------------------------------------------
app = FastAPI(title="Chat", docs_url=None, redoc_url=None)
INDEX = Path(__file__).parent / "static" / "index.html"


class RegisterIn(BaseModel):
    username: str
    email: str
    password: str


class LoginIn(BaseModel):
    identifier: str
    password: str


@app.get("/")
def index():
    return FileResponse(INDEX)


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/api/register")
def api_register(body: RegisterIn, request: Request):
    key = f"reg:{client_ip(request)}"
    if too_many(key, limit=10, window=3600):
        raise HTTPException(429, "Too many sign-ups from this address. Try again later.")
    error = register(body.username, body.email, body.password)
    if error:
        record(key)
        raise HTTPException(400, error)
    return {"ok": True}


@app.post("/api/login")
def api_login(body: LoginIn, request: Request, response: Response):
    key = f"login:{client_ip(request)}:{body.identifier.strip().lower()}"
    if too_many(key, limit=8, window=300):
        raise HTTPException(429, "Too many attempts. Try again in a few minutes.")
    result = authenticate(body.identifier, body.password)
    if result is None:
        record(key)
        raise HTTPException(401, "Invalid username/email or password.")
    user_id, username, _email = result
    _failures.pop(key, None)
    secure = request.headers.get("x-forwarded-proto", request.url.scheme) == "https"
    response.set_cookie(
        SESSION_COOKIE, serializer.dumps(user_id), max_age=SESSION_MAX_AGE,
        httponly=True, samesite="lax", secure=secure,
    )
    return {"username": username}


@app.post("/api/logout")
def api_logout(response: Response):
    response.delete_cookie(SESSION_COOKIE)
    return {"ok": True}


@app.get("/api/me")
def api_me(request: Request):
    _id, username = current_user(request)
    return {"username": username}


@app.get("/api/messages")
def api_messages(request: Request, room: str = "general", before: int | None = None):
    current_user(request)
    room = room.strip().lower()
    if not ROOM_RE.match(room):
        raise HTTPException(400, "Invalid room name.")
    return load_history(room, before, HISTORY_LIMIT)


# --- WebSocket hub -------------------------------------------------------
class Hub:
    def __init__(self):
        self.rooms: dict[str, dict[WebSocket, str]] = defaultdict(dict)

    async def broadcast(self, room: str, payload: dict) -> None:
        data = json.dumps(payload)
        sockets = list(self.rooms.get(room, {}))
        results = await asyncio.gather(*(ws.send_text(data) for ws in sockets), return_exceptions=True)
        for ws, result in zip(sockets, results):
            if isinstance(result, Exception):
                self.rooms[room].pop(ws, None)

    async def presence(self, room: str) -> None:
        users = sorted(set(self.rooms.get(room, {}).values()))
        await self.broadcast(room, {"type": "presence", "users": users})

    async def join(self, room: str, ws: WebSocket, username: str) -> None:
        self.rooms[room][ws] = username
        await self.presence(room)

    async def leave(self, room: str, ws: WebSocket) -> None:
        self.rooms[room].pop(ws, None)
        if self.rooms[room]:
            await self.presence(room)
        else:
            del self.rooms[room]


hub = Hub()


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket, room: str = "general"):
    # Block cross-site WebSocket hijacking: the page's origin must be this host.
    origin = ws.headers.get("origin")
    if origin and urlparse(origin).netloc != ws.headers.get("host"):
        await ws.close(code=1008)
        return

    room = room.strip().lower()
    await ws.accept()
    ident = await asyncio.to_thread(user_from_token, ws.cookies.get(SESSION_COOKIE, ""))
    if ident is None:
        await ws.close(code=4401)  # client shows the sign-in screen
        return
    if not ROOM_RE.match(room):
        await ws.close(code=1008)
        return

    user_id, username = ident
    await hub.join(room, ws, username)
    sent = deque()  # timestamps, for rate limiting: max 5 messages / 5 seconds
    try:
        while True:
            try:
                data = json.loads(await ws.receive_text())
            except ValueError:
                continue
            if not isinstance(data, dict):
                continue

            kind = data.get("type")
            if kind == "ping":  # keep-alive from the browser
                await ws.send_text('{"type":"pong"}')
                continue
            if kind != "message":
                continue

            text = str(data.get("text", "")).strip()
            if not text:
                continue
            if len(text) > MAX_MESSAGE_LEN:
                await ws.send_text(json.dumps({"type": "error", "text": f"Max {MAX_MESSAGE_LEN} characters."}))
                continue
            now = time.monotonic()
            while sent and now - sent[0] > 5:
                sent.popleft()
            if len(sent) >= 5:
                await ws.send_text(json.dumps({"type": "error", "text": "Slow down a little."}))
                continue
            sent.append(now)

            msg = await asyncio.to_thread(save_message, room, user_id, text)
            await hub.broadcast(room, {"type": "message", "username": username, **msg})
    except WebSocketDisconnect:
        pass
    finally:
        await hub.leave(room, ws)
