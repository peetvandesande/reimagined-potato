# reimagined-potato

Small demo service (backend + frontend) with Redis and Postgres. This repository now centralizes runtime configuration in a top-level `.env` file used by Docker Compose.

Quick start
1. Copy or edit the provided `.env` at the project root to adjust values for your environment. The defaults are safe for local development but must be changed for production (notably `JWT_SECRET`).
2. Build and start the stack:

```bash
docker compose up -d --build
```

3. Open the frontend at http://localhost:3000 and log in using credentials from `backend/users.txt` (example: `peet:peetpass1`).

What changed
- `.env` — central defaults for backend and frontend (API base, WS base, cookie name, Redis/Postgres URLs, prefixes and TTLs).
- `docker-compose.yml` — now reads `.env` and passes values to services.
- `backend/config.js` and `frontend/src/config.js` — central in-app config modules which read process.env (frontend reads REACT_APP_* at build time).

Security notes
- Set a strong `JWT_SECRET` in your environment before deploying to production.
- Set `COOKIE_SECURE=1` when serving over HTTPS so refresh cookies are marked Secure.

If you want, I can add a small integration test that verifies login → refresh → logout flows with the configured values.

Quick tips
- Copy `.env.example` to `.env` and update secrets (especially `JWT_SECRET`) before deploying.
- To build the frontend image with custom REACT_APP_* values you can use the provided helper or Makefile:

```bash
# set override envs and run
REACT_APP_API_BASE=https://api.example.com REACT_APP_WS_BASE=wss://api.example.com ./build-frontend.sh
# or via make
make build-frontend
```

The `docker-compose.yml` loads values from `.env` so after editing `.env` you can run `docker compose up -d --build` to rebuild services with the new settings.
