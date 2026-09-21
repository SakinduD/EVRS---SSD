import io
import os
import json
import hashlib
import logging
import secrets
from typing import List, Optional, Literal, Any, Dict

import numpy as np
import pandas as pd
import joblib

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

# config and paths
load_dotenv()
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Audit logging. The integrity results below are security events, so they need a
# handler of their own: uvicorn configures only its own loggers, and Python's
# fallback handler silently discards anything under WARNING. Without this block
# a successful verification would leave no trace at all.
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_FILE = os.getenv("LOG_FILE") or os.path.join(BASE_DIR, "logs", "scorer.log")

logger = logging.getLogger("evrs.scorer")
logger.setLevel(LOG_LEVEL)
logger.propagate = False
if not logger.handlers:
    _formatter = logging.Formatter(
        "%(asctime)s %(levelname)s [%(name)s] %(message)s"
    )
    _console = logging.StreamHandler()
    _console.setFormatter(_formatter)
    logger.addHandler(_console)
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        _file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
        _file_handler.setFormatter(_formatter)
        logger.addHandler(_file_handler)
    except OSError:
        # A read-only or missing log directory must not stop the service from
        # starting; console logging still covers the audit trail.
        logger.warning("Could not open log file %s; logging to console only", LOG_FILE)

# Local-development escape hatch for the integrity checks below. Must stay false
# in any deployed environment - it is the difference between "verified" and "trusted".
ALLOW_UNVERIFIED_ARTIFACTS = os.getenv("ALLOW_UNVERIFIED_ARTIFACTS", "false").lower() == "true"


def _resolve_trusted_path(env_var: str, default_name: str) -> str:
    """Resolve an artifact path, rejecting anything that escapes BASE_DIR.

    MODEL_PATH and SCHEMA_PATH are read from the environment. Without this guard,
    anyone able to influence the environment (a leaked .env, a compromised CI
    variable, a container misconfiguration) could aim the loader at a file they
    control anywhere on disk and get it deserialised. See _read_verified_bytes()
    for why that is remote code execution rather than a mere bad-data problem.
    """
    raw = os.getenv(env_var) or default_name
    candidate = raw if os.path.isabs(raw) else os.path.join(BASE_DIR, raw)
    resolved = os.path.realpath(candidate)
    base = os.path.realpath(BASE_DIR)
    if resolved != base and not resolved.startswith(base + os.sep):
        raise RuntimeError(
            f"{env_var} resolves outside the service directory; refusing to load it."
        )
    return resolved


# V14: the pinned digests live in a git-tracked lock file rather than in .env.
# A digest is not a secret, and keeping it under version control means that
# altering a pin shows up in `git diff` and in code review. A digest sitting in
# an untracked .env can be rewritten by the same attacker who swapped the model,
# leaving no trace - which defeats the point of pinning it at all.
LOCK_PATH = os.path.join(BASE_DIR, "artifacts.lock.json")


def _load_lockfile() -> tuple:
    """Read the pinned filenames and SHA-256 digests from the git-tracked lock file.

    Returns (paths, digests) keyed by artifact name.
    """
    try:
        with open(LOCK_PATH, "r", encoding="utf-8") as fh:
            lock = json.load(fh)
    except FileNotFoundError:
        logger.warning(
            "No artifacts.lock.json found; falling back to *_SHA256 environment variables."
        )
        return {}, {}
    except (OSError, ValueError) as e:
        logger.exception("Could not parse artifacts.lock.json")
        raise RuntimeError("artifacts.lock.json could not be parsed.") from e

    artifacts = lock.get("artifacts")
    if not isinstance(artifacts, dict):
        raise RuntimeError("artifacts.lock.json is missing its 'artifacts' object.")

    paths: Dict[str, str] = {}
    digests: Dict[str, str] = {}
    for name, entry in artifacts.items():
        if not isinstance(entry, dict) or not entry.get("sha256"):
            raise RuntimeError(
                f"artifacts.lock.json entry '{name}' has no sha256 value."
            )
        key = str(name).upper()
        digests[key] = str(entry["sha256"]).strip().lower()
        if entry.get("path"):
            paths[key] = str(entry["path"])
    return paths, digests


PINNED_PATHS, PINNED_DIGESTS = _load_lockfile()


def _read_verified_bytes(path: str, env_prefix: str) -> bytes:
    """Read an artifact once and return its bytes only if the SHA-256 matches.

    joblib.load() unpickles, and unpickling executes arbitrary code that the file
    itself chooses - a hostile model file is code execution at startup, before a
    single request is served (OWASP A08, Software and Data Integrity Failures).
    Verifying the digest BEFORE the load is what downgrades that from RCE to a
    startup failure, so this must run first and must fail closed.

    The file is read exactly once and the caller deserialises the returned buffer
    rather than re-opening the path. Hashing the file and then loading it from
    disk would leave a TOCTOU window: anyone able to write to the path between
    the two reads could pass the check and still have different bytes executed.
    Returning the verified bytes removes that window, because the bytes that were
    hashed are the only bytes that ever get deserialised.
    """
    with open(path, "rb") as fh:
        payload = fh.read()
    actual = hashlib.sha256(payload).hexdigest()

    # The lock file is the source of truth; the environment variable remains only
    # as a fallback for deployments that inject digests out of band.
    expected = PINNED_DIGESTS.get(env_prefix) or (
        os.getenv(f"{env_prefix}_SHA256") or ""
    ).strip().lower()

    if not expected:
        if ALLOW_UNVERIFIED_ARTIFACTS:
            logger.warning(
                "%s integrity check SKIPPED because ALLOW_UNVERIFIED_ARTIFACTS=true. "
                "Observed SHA-256 is %s - pin it in artifacts.lock.json with "
                "`python tools/checksum_artifacts.py --write` and clear the override "
                "before deploying.",
                env_prefix, actual,
            )
            return payload
        raise RuntimeError(
            f"No pinned digest for {env_prefix}, so the artifact cannot be "
            f"verified. Add it to artifacts.lock.json (observed: {actual}) with "
            f"`python tools/checksum_artifacts.py --write`, or set "
            f"ALLOW_UNVERIFIED_ARTIFACTS=true for local development only."
        )

    if actual != expected:
        # Deliberately does not echo the observed digest: on a mismatch we are
        # possibly talking to an attacker, and confirming what we computed only
        # helps them iterate.
        logger.error("%s integrity check failed for %s", env_prefix, path)
        raise RuntimeError(
            f"{env_prefix} failed integrity verification; refusing to load it."
        )

    logger.info("%s integrity verified (sha256=%s)", env_prefix, actual)
    return payload


# model and schema paths. The filename defaults come from the lock file so that
# artifacts.lock.json is the single place describing what this service loads.
MODEL_PATH = _resolve_trusted_path("MODEL_PATH", PINNED_PATHS.get("MODEL", "evrs_miss_next_model.pkl"))

SCHEMA_PATH = _resolve_trusted_path("SCHEMA_PATH", PINNED_PATHS.get("SCHEMA", "evrs_feature_schema.json"))

HORIZON_DAYS = int(os.getenv("HORIZON_DAYS", "120"))
HIGH_THR = float(os.getenv("HIGH_THR", "0.65"))
MED_THR = float(os.getenv("MED_THR", "0.35"))

# V13: authentication for the scoring endpoints.
#
# This service holds a model trained on citizen vaccination records and will
# score anyone it is asked about. It previously accepted every request that
# reached its port, which made the Node backend's admin-only check decorative:
# an attacker who could reach 8081 simply bypassed it. The service is only ever
# called server-to-server by the Node backend, so a shared secret in a header is
# proportionate - there is no browser, user session or consent flow involved.
# nosec B105 - this is the NAME of the HTTP header, not a credential. The
# secret itself is read from the environment on the next few lines.
INTERNAL_TOKEN_HEADER = "X-Internal-Token"  # nosec B105
MIN_TOKEN_LENGTH = 32

INTERNAL_API_TOKEN = (os.getenv("INTERNAL_API_TOKEN") or "").strip()

if not INTERNAL_API_TOKEN:
    raise RuntimeError(
        "INTERNAL_API_TOKEN is not set. The scorer will not start without it, "
        "because an unauthenticated scoring endpoint exposes citizen health "
        "data to anyone who can reach the port. Generate one with: "
        "python -c \"import secrets; print(secrets.token_urlsafe(32))\""
    )

if len(INTERNAL_API_TOKEN) < MIN_TOKEN_LENGTH:
    raise RuntimeError(
        f"INTERNAL_API_TOKEN is shorter than {MIN_TOKEN_LENGTH} characters. A "
        f"guessable shared secret is barely better than none; generate one with: "
        f"python -c \"import secrets; print(secrets.token_urlsafe(32))\""
    )


def require_internal_token(
    request: Request,
    provided: str = Header(default="", alias=INTERNAL_TOKEN_HEADER),
) -> None:
    """Reject any caller that cannot present the shared internal token.

    secrets.compare_digest() is used rather than == because a plain comparison
    short-circuits on the first differing byte, and the time it takes leaks how
    much of the token was correct - enough, over many attempts, to recover it
    one character at a time.
    """
    expected = INTERNAL_API_TOKEN.encode("utf-8")
    supplied = (provided or "").encode("utf-8", "ignore")

    if not secrets.compare_digest(supplied, expected):
        client = request.client.host if request.client else "unknown"
        logger.warning(
            "Rejected request to %s from %s: %s internal token",
            request.url.path,
            client,
            "missing" if not provided else "invalid",
        )
        # The response says nothing about which part was wrong, and carries no
        # hint that a valid token exists at all.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
        )


# app init
app = FastAPI(title="EVRS Miss-Next Vaccine Scorer (XGBoost)", version="1.0.0")

# V13: CORS was allow_origins=["*"] with allow_credentials=True - a combination
# browsers reject outright, so it was both insecure in intent and broken in
# practice. Nothing in this service is called from a browser; the Node backend
# reaches it server-to-server, where CORS plays no part. The middleware is
# therefore only mounted when an origin is explicitly configured, and defaults
# to not being mounted at all.
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in (os.getenv("ALLOWED_ORIGINS") or "").split(",")
    if origin.strip()
]

if ALLOWED_ORIGINS:
    if "*" in ALLOWED_ORIGINS:
        raise RuntimeError(
            "ALLOWED_ORIGINS must name explicit origins; '*' would re-open the "
            "service to every site a victim's browser visits."
        )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        # No cookies or browser credentials are involved; the caller
        # authenticates with an explicit header instead.
        allow_credentials=False,
        allow_methods=["POST"],
        allow_headers=["Content-Type", INTERNAL_TOKEN_HEADER],
    )
    logger.info("CORS enabled for %s", ", ".join(ALLOWED_ORIGINS))
else:
    logger.info(
        "CORS middleware not mounted; this service is called server-to-server only."
    )

# load model and schema - deserialise the verified buffer, never the path again
try:
    model = joblib.load(io.BytesIO(_read_verified_bytes(MODEL_PATH, "MODEL")))
except RuntimeError:
    raise
except Exception as e:
    # Log the detail locally; the raised message stays generic so filesystem
    # paths and library internals never reach a caller or a shared log sink.
    logger.exception("Failed to load model")
    raise RuntimeError("Failed to load the scoring model.") from e

try:
    schema = json.loads(_read_verified_bytes(SCHEMA_PATH, "SCHEMA").decode("utf-8"))
except RuntimeError:
    raise
except Exception as e:
    logger.exception("Failed to read feature schema")
    raise RuntimeError("Failed to read the feature schema.") from e

if "input_columns" not in schema or not isinstance(schema["input_columns"], dict):
    raise RuntimeError("Schema file missing 'input_columns' mapping.")

EXPECTED_COLS = [c for c in schema["input_columns"].keys() if c != "y_missed"]

# pydantic payloads
class Citizen(BaseModel):
    citizenId: str
    birthDate: Optional[str] = None
    district: Optional[str] = None
    division: Optional[str] = None
    bloodType: Optional[str] = None
    allergies: Optional[List[str]] = None
    medicalConditions: Optional[List[str]] = None
    guardianPhone: Optional[str] = None
    guardianEmail: Optional[str] = None
    hospitalId: Optional[str] = None
    mohId: Optional[str] = None
    v1Code: Optional[str] = None
    v1Date: Optional[str] = None
    v1Location: Optional[str] = None
    v1HcpId: Optional[str] = None
    v2Code: Optional[str] = None
    v2Date: Optional[str] = None
    v2Location: Optional[str] = None
    v2HcpId: Optional[str] = None
    v3Code: Optional[str] = None
    v3Date: Optional[str] = None
    v3Location: Optional[str] = None
    v3HcpId: Optional[str] = None
    v4Code: Optional[str] = None
    v4Date: Optional[str] = None
    v4Location: Optional[str] = None
    v4HcpId: Optional[str] = None

class ScoreRequest(BaseModel):
    events: List[Citizen]
    mode: Literal["latest", "all"] = "latest"

# helper func
def _parse_date(x: Optional[str]):
    if not x:
        return None
    try:
        return pd.to_datetime(x)
    except Exception:
        return None

def _has_val(x: Optional[str]) -> int:
    if not x:
        return 0
    s = str(x).strip()
    return 1 if len(s) >= 5 else 0

def _canon(s: Optional[str]) -> str:
    return (str(s).strip() if s is not None else "Unknown")

def _canon_upper(s: Optional[str]) -> str:
    return (str(s).strip().upper() if s is not None else "Unknown")

def _canon_title(s: Optional[str]) -> str:
    return (str(s).strip().title() if s is not None else "Unknown")

def _tier(p: float) -> str:
    if p >= HIGH_THR:
        return "High"
    if p >= MED_THR:
        return "Medium"
    return "Low"

def _engineer_events_from_wide(c: Citizen, mode: str) -> List[Dict[str, Any]]:
    """Build index-dose events from wide v1..v4 for a citizen."""
    doses = []
    for i in range(1, 5):
        doses.append({
            "n": i,
            "code": getattr(c, f"v{i}Code"),
            "date": _parse_date(getattr(c, f"v{i}Date")),
            "loc": getattr(c, f"v{i}Location"),
            "hcp": getattr(c, f"v{i}HcpId"),
        })

    # select index positions
    idx_positions: List[int] = []
    if mode == "all":
        idx_positions = [1, 2, 3]
    else:
        for n in [3, 2, 1]:
            if doses[n-1]["date"] is not None:
                idx_positions = [n]
                break
        if not idx_positions:
            return []

    out: List[Dict[str, Any]] = []
    for n in idx_positions:
        cur = doses[n-1]
        if cur["date"] is None:
            continue

        rec: Dict[str, Any] = {
            "citizenId": c.citizenId,
            "dose_number": n,
            "index_v_code": _canon_upper(cur["code"]) if cur["code"] else None,
            "index_v_date": cur["date"],
            "index_loc": _canon(cur["loc"]),
            "index_hcp": _canon_upper(cur["hcp"]),
            "district": _canon_title(c.district),
            "division": _canon_title(c.division),
            "bloodType": _canon_upper(c.bloodType),
            "hospitalId": _canon_upper(c.hospitalId),
            "mohId": _canon_upper(c.mohId),
            "age_days": None,
            "index_month": int(cur["date"].month),
            "index_dow": int(cur["date"].dayofweek),
            "has_phone": _has_val(c.guardianPhone),
            "has_email": _has_val(c.guardianEmail),
            "prev_gap_days": None,
            "same_hospitalId_as_prev": 0,
            "same_mohId_as_prev": 0,
            "same_index_loc_as_prev": 0,
            "same_index_hcp_as_prev": 0,
            "allergy_count": 0,
            "condition_count": 0,
        }

        birth = _parse_date(c.birthDate)
        if birth is not None:
            rec["age_days"] = int((cur["date"] - birth).days)

        prev = doses[n-2] if n >= 2 else None
        if prev and prev["date"] is not None:
            rec["prev_gap_days"] = (cur["date"] - prev["date"]).days
            rec["same_index_loc_as_prev"] = int(bool(prev["loc"] and cur["loc"] and _canon(prev["loc"]) == _canon(cur["loc"])))
            rec["same_index_hcp_as_prev"] = int(bool(prev["hcp"] and cur["hcp"] and _canon_upper(prev["hcp"]) == _canon_upper(cur["hcp"])))

        alls = [a.strip().lower() for a in (c.allergies or []) if a]
        mcs = [m.strip().lower() for m in (c.medicalConditions or []) if m]
        rec["allergy_count"] = len(alls)
        rec["condition_count"] = len(mcs)

        # one hot encoded allergy and condition features
        for tok in ["gelatin", "eggs", "yeast", "latex", "peanuts"]:
            rec[f"allergy_{tok}"] = int(tok in alls)
        for tok in ["asthma", "epilepsy", "congenital_heart", "eczema"]:
            rec[f"cond_{tok}"] = int(tok in mcs)

        out.append(rec)

    return out

def _complete_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Add any expected columns the model saw during training, with safe defaults; cast types."""
    for col, _dtype in schema["input_columns"].items():
        if col == "y_missed":
            continue
        if col not in df.columns:
            if col == "citizenId":
                df[col] = ""
            elif col == "index_v_date":
                df[col] = pd.NaT
            elif col in ["dose_number", "age_days", "prev_gap_days", "index_month", "index_dow"]:
                df[col] = np.nan
            elif col in ["district", "division", "bloodType", "hospitalId", "mohId", "index_v_code", "index_loc", "index_hcp"]:
                df[col] = "Unknown"
            elif col.startswith(("allergy_", "cond_", "same_")) or col in ["has_phone", "has_email", "allergy_count", "condition_count"]:
                df[col] = 0
            else:
                df[col] = np.nan

    ordered = [c for c in EXPECTED_COLS if c in df.columns]
    df = df[ordered]

    num_like = {
        "dose_number", "age_days", "prev_gap_days", "index_month", "index_dow",
        "has_phone", "has_email", "allergy_count", "condition_count",
        "same_hospitalId_as_prev", "same_mohId_as_prev", "same_index_loc_as_prev", "same_index_hcp_as_prev",
        "allergy_gelatin", "allergy_eggs", "allergy_yeast", "allergy_latex", "allergy_peanuts",
        "cond_asthma", "cond_epilepsy", "cond_congenital_heart", "cond_eczema"
    }
    for c in (set(num_like) & set(df.columns)):
        df[c] = pd.to_numeric(df[c], errors="coerce")

    if "index_v_date" in df.columns:
        df["index_v_date"] = pd.to_datetime(df["index_v_date"], errors="coerce")

    return df

def _score_dataframe(df_events: pd.DataFrame) -> List[Dict[str, Any]]:
    df_events = _complete_columns(df_events.copy())
    X = df_events[[c for c in df_events.columns if c != "y_missed"]]
    probs = model.predict_proba(X)[:, 1]

    out: List[Dict[str, Any]] = []
    for (_, r), p in zip(df_events.iterrows(), probs):
        due_by = None
        if pd.notna(r.get("index_v_date", pd.NaT)):
            due_by = (r["index_v_date"] + pd.Timedelta(days=HORIZON_DAYS)).date().isoformat()

        t = _tier(float(p))
        out.append({
            "citizenId": r.get("citizenId"),
            "dose_number": int(r["dose_number"]) if pd.notna(r.get("dose_number")) else None,
            "index_v_code": r.get("index_v_code"),
            "index_v_date": r["index_v_date"].date().isoformat() if pd.notna(r.get("index_v_date")) else None,
            "risk_prob": float(p),
            "risk_tier": t,
            "due_by": due_by,
            "recommended_action": {"High": "Call + WhatsApp + SMS", "Medium": "WhatsApp + SMS", "Low": "SMS"}[t],
        })
    return out

# routes
@app.get("/health")
def health():
    import sklearn
    return {
        "ok": True,
        "horizon_days": HORIZON_DAYS,
        "high_threshold": HIGH_THR,
        "med_threshold": MED_THR,
        "sklearn": sklearn.__version__,
        "model_path": MODEL_PATH,
        "schema_path": SCHEMA_PATH,
    }

@app.post("/score", dependencies=[Depends(require_internal_token)])
def score_events(req: ScoreRequest):
    if not req.events:
        raise HTTPException(status_code=400, detail="No events provided")
    rows: List[Dict[str, Any]] = []
    for c in req.events:
        rows.extend(_engineer_events_from_wide(c, req.mode))
    if not rows:
        return {"results": []}
    df = pd.DataFrame(rows)
    results = _score_dataframe(df)
    return {"results": results}

@app.post("/score/events_debug", dependencies=[Depends(require_internal_token)])
def score_events_debug(req: ScoreRequest):
    if not req.events:
        raise HTTPException(status_code=400, detail="No events provided")
    rows: List[Dict[str, Any]] = []
    for c in req.events:
        rows.extend(_engineer_events_from_wide(c, req.mode))
    if not rows:
        return {"features": []}
    df = pd.DataFrame(rows)
    df = _complete_columns(df)
    return {
        "features": df.to_dict(orient="records"),
        "n_features": len(df.columns),
        "columns": list(df.columns),
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=int(os.getenv("PORT", "8081")), reload=True)