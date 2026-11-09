# Chat app (FastAPI + WebSockets + AES-encrypted storage)

Accounts use your existing `users_aes.py` model (UUID, username, email, AES-GCM password).
Messages are stored with the same AES-GCM column type. Rooms are created on demand
(`# general` is the default). `login_app.py` (desktop) shares the same accounts via `auth.py`.

## Run locally

    pip install -r requirements.txt
    uvicorn app:app --reload
    # open http://localhost:8000   (creates users.db + aes.key on first run)

## Deploy for free: Neon (database) + Render (web server)

Render's free disk is wiped on every restart/sleep, so accounts and messages live in a
free external Postgres instead. Never rely on SQLite or `aes.key` on the free host.

1. **Database** - create a free project at https://neon.com and copy the connection string
   (`postgresql://user:pass@host/db?sslmode=require`).
2. **Key** - generate your AES key and keep a backup somewhere safe:

       python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"

   If this key is lost, every stored password and message is unreadable.
3. **GitHub** - push this folder to a new repo (`.gitignore` already excludes keys and DBs).
4. **Render** - dashboard > New > *Blueprint* > pick the repo (it reads `render.yaml`).
   When asked, set `DATABASE_URL` (step 1) and `AES_KEY` (step 2). Deploy.
   Prefer manual setup? New > Web Service, runtime Python, plan Free, build command
   `pip install -r requirements.txt`, start command
   `uvicorn app:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips "*"`,
   plus the two env vars.
5. Open the `https://<name>.onrender.com` URL and register.

## Free-tier behaviour to expect

- Render spins a free service down after 15 minutes without HTTP requests or WebSocket
  messages; waking it takes about a minute. The page reconnects automatically with backoff.
  An open tab sends a ping every 25 s, which keeps the service awake while someone is online.
- Free instances get 750 hours per month per workspace (about one always-on service).
- Neon pauses an idle database and wakes it on the next query (a short delay on the first request).
- Limits and policies change; check Render's "Deploy for Free" docs and Neon's plan page.

## Security notes

- Passwords are AES-encrypted (reversible), per the original design. Anyone with both the
  database and `AES_KEY` can read them. Before inviting strangers, switch to argon2 hashing.
- Messages are encrypted at rest only; the server can read them. This is not end-to-end encryption.
- Session = signed HttpOnly cookie (7 days), WebSocket origin check, login/sign-up rate limits
  (in memory, per instance).
