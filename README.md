# Fullstack Auth Starter

A production-ready authentication boilerplate with React + FastAPI. Battle-tested security features out of the box.

## Tech Stack

- **Frontend:** React 19 + Vite + React Router
- **Backend:** Python FastAPI + SQLAlchemy + PostgreSQL (SQLite for local dev)
- **Email:** Resend (verification codes, password resets)
- **Deploy:** Docker (Railway, Render, Fly.io, etc.)

## Features

- JWT authentication with token blacklisting
- Email verification (6-digit codes via Resend)
- Password reset flow
- Account lockout (10 failed attempts = 15 min lockout)
- Rate limiting on all auth endpoints
- Security headers (CSP, HSTS, X-Frame-Options, etc.)
- Request size limiting (1MB)
- Timing-safe comparisons (prevents user enumeration)
- Automatic cleanup of expired tokens and stale accounts
- Swagger/ReDoc disabled in production
- Cross-tab logout sync

## Local Setup

### Prerequisites

- Node.js 20+
- Python 3.12+

### Frontend

```bash
npm install
npm run dev          # http://localhost:5173
```

### Backend

```bash
cd backend
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env
# Edit .env with your values (SECRET_KEY is required)

# Run migrations
python migrate.py

# Start server
uvicorn app.main:app --reload   # http://localhost:8000
```

### Generate a SECRET_KEY

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | No | Database URL (defaults to SQLite) |
| `SECRET_KEY` | **Yes** | 32-byte hex for JWT signing |
| `RESEND_API_KEY` | No | Resend API key for emails |
| `ALLOWED_ORIGINS` | No | Comma-separated CORS origins |
| `APP_NAME` | No | App name used in emails and API title |
| `FROM_EMAIL` | No | Sender email address |
| `LOG_LEVEL` | No | Logging level (default: INFO) |
| `ENVIRONMENT` | No | Set to `production` to disable Swagger |
| `FORCE_HTTPS` | No | Set to `true` to redirect HTTP to HTTPS |

## Deployment (Docker)

```bash
docker build -t myapp .
docker run -p 8000:8000 \
  -e SECRET_KEY=your-secret \
  -e DATABASE_URL=postgresql://... \
  -e RESEND_API_KEY=re_... \
  -e ENVIRONMENT=production \
  myapp
```

For Railway: connect your repo, set env vars, and it auto-deploys from the Dockerfile.

## Project Structure

```
├── src/                    # React frontend
│   ├── api/client.js       # API client (auth endpoints)
│   ├── components/         # React components
│   ├── utils/              # Constants, toast system
│   ├── App.jsx             # Main app with auth state
│   ├── App.css             # Core styles
│   ├── index.css           # CSS variables (light theme)
│   └── main.jsx            # Entry point
├── backend/
│   ├── app/
│   │   ├── auth.py         # JWT + bcrypt utilities
│   │   ├── database.py     # SQLAlchemy setup
│   │   ├── email.py        # Resend email functions
│   │   ├── limiter.py      # Rate limiter config
│   │   ├── logging_config.py
│   │   ├── main.py         # FastAPI app + middleware
│   │   ├── models.py       # User + BlacklistedToken
│   │   ├── schemas.py      # Pydantic validation
│   │   └── routers/auth.py # Auth endpoints
│   ├── requirements.txt
│   ├── migrate.py
│   └── .env.example
├── alembic/                # Database migrations
├── Dockerfile              # 2-stage build
├── package.json
└── vite.config.js
```

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/signup` | No | Create account (sends verification email) |
| POST | `/api/auth/verify-email` | No | Verify email with 6-digit code |
| POST | `/api/auth/resend-code` | No | Resend verification code |
| POST | `/api/auth/login` | No | Login with email/username + password |
| POST | `/api/auth/logout` | Yes | Logout (blacklists token) |
| GET | `/api/auth/me` | Yes | Get current user profile |
| GET | `/api/auth/check-username` | No | Check username availability |
| POST | `/api/auth/forgot-password` | No | Request password reset code |
| POST | `/api/auth/reset-password` | No | Reset password with code |
| PUT | `/api/auth/change-password` | Yes | Change password (requires current) |
| POST | `/api/auth/delete-account` | Yes | Delete account (requires password) |
| GET | `/api/health` | No | Health check |
