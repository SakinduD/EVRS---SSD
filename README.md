# Electronic Vaccination Record System
The Electronic Vaccination Record System is a full-stack web application designed to manage vaccination records and assess vaccination risks for citizens in Sri Lanka. The system supports five user roles: Citizen, Admin, Healthcare Provider, Hospital, and MOH (Ministry of Health). It integrates a machine learning model to predict vaccination adherence risks and provides actionable recommendations.

## Structure
- `client/`: Next.js frontend with React.
- `server/`: Node.js/Express backend.
- `risk-scorer-ml/`: FastAPI backend for machine learning risk scoring.
- `blackbox/`: Dynamic (DAST) security testing artifacts — OWASP ZAP scans.
- `whitebox/`: Static (SAST) security testing artifacts — dependency and code audits.

## Prerequisites
- Node.js and npm
- Python
- MongoDB

## Cloning the Repository
Clone the repository to your machine:
```
git clone https://github.com/IshanArdithya/EVRS.git
cd evrs
```
## Setting Up the Web Client (Frontend)
1. Navigate to the `client` directory:
```
cd client
```
2. Install dependencies:
```
npm install
```
3. Create a `.env.local` file with:
```
NEXT_PUBLIC_API_BASE_URL=
```
4. Run the development server:
```
npm run dev
```

## Setting Up the Server (Backend)
1. Navigate to the `server` directory:
```
cd server
```
2. Install dependencies:
```
npm install
```
3. Create a `.env` file with:
```
PORT=
MONGO_URI=
JWT_SECRET=
SMTP_HOST=
SMTP_PORT=
SMTP_SECURE=
SMTP_USER=
SMTP_PASS=
TWILIO_ACCOUNT_SID=
TWILIO_AUTH_TOKEN=
TWILIO_WHATSAPP_FROM=
FAST_API_URL=
INTERNAL_API_TOKEN=
FRONTEND_URL=
NODE_ENV=development
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URI=
TRUST_PROXY=
DNS_SERVERS=
```
4. Run the backend server:
```
npm run dev
```

`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `GOOGLE_REDIRECT_URI` are required
for Google OAuth (OpenID Connect + PKCE) login. `INTERNAL_API_TOKEN` authorizes
internal server-to-server calls to the ML service. `TRUST_PROXY` and
`DNS_SERVERS` are optional and only needed for specific deployment setups.

For production, set `NODE_ENV=production` and `FRONTEND_URL` to the exact
frontend origin (for example, `https://app.example.com`) in the deployment
environment. The backend rejects browser origins when `FRONTEND_URL` is absent.
Do not use a trailing slash in the origin.
Start the production backend with `npm run start:production`.

## Setting Up the Risk Scorer ML (FastAPI Backend)
1. Navigate to the `risk-scorer-ml` directory:
```
cd risk-scorer-ml
```
2. Create and activate a virtual environment:
```
python -m venv venv
.\venv\Scripts\activate
```
3. Install dependencies:
```
pip install -r requirements.txt
```
4. Create a `.env` file with:
```
MODEL_PATH=./evrs_miss_next_model.pkl
SCHEMA_PATH=./evrs_feature_schema.json
HORIZON_DAYS=
HIGH_THR=
MED_THR=
INTERNAL_API_TOKEN=
ALLOWED_ORIGINS=
HOST=127.0.0.1
PORT=8081
DEBUG_MODE=false
ALLOW_UNVERIFIED_ARTIFACTS=false
MAX_BODY_BYTES=
MAX_EVENTS_PER_REQUEST=
LOG_LEVEL=INFO
LOG_FILE=
```
`INTERNAL_API_TOKEN` must match the same value configured on the Node backend,
since it authenticates server-to-server calls between them. `ALLOWED_ORIGINS`
is a comma-separated list of allowed CORS origins (no `*`). `DEBUG_MODE` and
`ALLOW_UNVERIFIED_ARTIFACTS` must stay `false` outside local development;
model/schema integrity digests are pinned in `artifacts.lock.json` rather than
in `.env`.
5. Run the FastAPI server:
```
uvicorn app:app --reload
```

## Security Testing
Security testing artifacts for the three services are kept outside the
application code, split by testing approach:

- `blackbox/`: Dynamic Application Security Testing (DAST) with OWASP ZAP,
  run against the live frontend, backend, and risk scorer. Contains
  before/after scan reports (`blackbox-before/`, `blackbox-after/`), proof
  files documenting how each finding was verified or triaged, and the seed
  payloads used against the risk scorer. See `blackbox/README.md` for the
  full methodology, results, and known false positives.
- `whitebox/`: Static Application Security Testing (SAST) — `npm audit` and
  Semgrep results for `client/` and `server/`, and `pip-audit`/Semgrep
  results for `risk-scorer-ml/`, again split into before/after fix
  snapshots (`whitebox-before/`, `whitebox-after/`).
