"""Check that the scorer still refuses what the security work made it refuse.

`contract_test.py` proves the service answers the Node backend correctly. This
one proves the opposite half: that the controls added for V13, V15 and V16 are
still in place, by sending the requests they were written to reject and
asserting on the status code rather than on the source.

It uses the standard library only, on purpose. Adding pytest and httpx would
pull new packages into an environment whose versions are pinned and whose
behaviour has already been recorded in a black-box scan.

    python tools/security_test.py                  # against localhost:8081
    python tools/security_test.py --url http://127.0.0.1:8085

Exit code 0 means every control held. Run it against a service started with
DEBUG_MODE=false; several checks assert the development surfaces are gone.
"""
import argparse
import http.client
import json
import os
import sys
import urllib.parse

from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(BASE_DIR, ".env"))

TOKEN_HEADER = "X-Internal-Token"

# A payload the service accepts, so that a refusal below is the control firing
# and not the payload being malformed.
GOOD_PAYLOAD = {
    "mode": "latest",
    "events": [
        {
            "citizenId": "SEC-0001",
            "birthDate": "2023-01-10",
            "district": "Colombo",
            "division": "Dehiwala",
            "v1Code": "BCG",
            "v1Date": "2023-01-15",
        },
        {
            # No vaccine code: this makes the batch mixed, which is the only
            # shape that produced a NaN in the response. See nan-fix-proof.txt.
            "citizenId": "SEC-0002",
            "birthDate": "2023-02-10",
            "district": "Gampaha",
            "division": "Negombo",
            "v1Code": None,
            "v1Date": "2023-02-15",
        },
    ],
}

# Appears only inside a payload that will be rejected. If it comes back in the
# error response, the validation handler is echoing input (V15).
CANARY = "CANARY-a7f3e1-DO-NOT-ECHO"


class Response:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = {k.lower(): v for k, v in headers}
        self.body = body

    def json(self):
        try:
            return json.loads(self.body.decode("utf-8"))
        except Exception:
            return None


def request(url, method="GET", body=None, headers=None, raw_content_length=None):
    """One request, with full control over the headers the server sees."""
    parts = urllib.parse.urlparse(url)
    if parts.scheme != "http":
        print(f"FAIL  refusing non-HTTP url: {url}")
        sys.exit(2)
    conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=30)
    payload = json.dumps(body).encode("utf-8") if body is not None else None
    send_headers = dict(headers or {})
    if payload is not None:
        send_headers.setdefault("Content-Type", "application/json")
    try:
        conn.putrequest(method, parts.path or "/", skip_accept_encoding=True)
        for key, value in send_headers.items():
            conn.putheader(key, value)
        if raw_content_length is not None:
            # A declared length that does not match the body. This is exactly
            # what the V15 middleware inspects, before it reads anything.
            conn.putheader("Content-Length", str(raw_content_length))
        elif payload is not None:
            conn.putheader("Content-Length", str(len(payload)))
        conn.endheaders()
        if payload is not None:
            conn.send(payload)
        response = conn.getresponse()
        return Response(response.status, response.getheaders(), response.read())
    except OSError as err:
        print(f"FAIL  cannot reach {url}: {err}")
        sys.exit(2)
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8081")
    args = parser.parse_args()
    base = args.url.rstrip("/")

    token = (os.getenv("INTERNAL_API_TOKEN") or "").strip()
    if not token:
        print("FAIL  INTERNAL_API_TOKEN is not set; cannot run the auth checks.")
        return 2
    auth = {TOKEN_HEADER: token}
    max_events = int(os.getenv("MAX_EVENTS_PER_REQUEST") or 1000)

    failures = []
    seen = []

    def check(label, passed, detail="", fail_detail=""):
        shown = detail if passed else (fail_detail or detail)
        print(f"{'pass' if passed else 'FAIL'}  {label}{'  ' + shown if shown else ''}")
        if not passed:
            failures.append(label.strip())

    def probe(label, *a, app_level=True, **kw):
        """app_level=False marks a response the ASGI app never produced, so the
        sweeps below do not hold our middleware responsible for its headers."""
        response = request(*a, **kw)
        seen.append((label, response, app_level))
        return response

    print("V13  authentication on the scoring surface")
    r = probe("/score no token", f"{base}/score", "POST", GOOD_PAYLOAD)
    check("  /score without a token is refused", r.status == 401, f"HTTP {r.status}")

    r = probe("/score wrong token", f"{base}/score", "POST", GOOD_PAYLOAD,
              {TOKEN_HEADER: "not-the-token-" + "x" * 40})
    check("  /score with a wrong token is refused", r.status == 401, f"HTTP {r.status}")

    r = probe("/score good token", f"{base}/score", "POST", GOOD_PAYLOAD, auth)
    check("  /score with the token is accepted", r.status == 200, f"HTTP {r.status}")

    r = probe("/health/detail no token", f"{base}/health/detail")
    check("  /health/detail without a token is refused", r.status == 401, f"HTTP {r.status}")

    print()
    print("V16  development and disclosure surfaces are gone")
    for path in ("/docs", "/redoc", "/openapi.json"):
        r = probe(path, f"{base}{path}")
        check(f"  {path} is not served", r.status == 404, f"HTTP {r.status}")

    # The registration sits inside `if DEBUG_MODE`, so outside development the
    # path must be indistinguishable from one the service never had: 404 with
    # no token, not 401, which would confirm the endpoint is there.
    r = probe("events_debug no token", f"{base}/score/events_debug", "POST", GOOD_PAYLOAD)
    check("  /score/events_debug is not registered (404, not 401)",
          r.status == 404, f"HTTP {r.status}")
    r = probe("events_debug with token", f"{base}/score/events_debug", "POST",
              GOOD_PAYLOAD, auth)
    check("  /score/events_debug returns no features to a valid token",
          r.status == 404, f"HTTP {r.status}")

    r = probe("/health", f"{base}/health")
    health = r.json() or {}
    check("  /health is a liveness probe only", set(health) == {"ok"},
          f"keys {sorted(health)}")
    leaked = [k for k in ("sklearn_version", "model_path", "schema_path", "version", "path")
              if k in health]
    check("  /health leaks no version or path", not leaked,
          f"leaked {leaked}" if leaked else "")

    advertised = [f"{lbl}: {resp.headers['server']}" for lbl, resp, _ in seen
                  if "server" in resp.headers]
    check("  no Server header on any response", not advertised,
          f"{len(seen)} responses checked", ", ".join(advertised))

    print()
    print("V15  input bounds")
    r = probe("oversized length", f"{base}/score", "POST", {"mode": "latest", "events": []},
              auth, raw_content_length=64 * 1024 * 1024)
    check("  an oversized Content-Length is refused before the body is read",
          r.status == 413, f"HTTP {r.status}")

    # uvicorn's HTTP parser rejects this one before the ASGI app is reached
    # ("Invalid HTTP request received.", text/plain, no headers of ours). The
    # middleware's own negative-length branch is the backstop for a server that
    # passes it through, so what is asserted here is only that it is refused.
    r = probe("negative length", f"{base}/score", "POST", {"mode": "latest", "events": []},
              auth, raw_content_length=-1, app_level=False)
    check("  a negative Content-Length is refused", r.status == 400, f"HTTP {r.status}")

    too_many = {"mode": "latest",
                "events": [dict(GOOD_PAYLOAD["events"][0]) for _ in range(max_events + 1)]}
    r = probe("too many events", f"{base}/score", "POST", too_many, auth)
    check(f"  more than {max_events} events is refused", r.status == 422, f"HTTP {r.status}")

    # Every field but citizenId is optional, so a missing field is not a
    # rejection. A list field given a string is, and it carries the canary as
    # the value the handler must not repeat.
    r = probe("canary", f"{base}/score", "POST",
              {"mode": "latest",
               "events": [{"citizenId": "SEC-0003", "allergies": CANARY}]}, auth)
    check("  a payload that fails validation is refused", r.status == 422, f"HTTP {r.status}")
    check("  the rejection does not echo the submitted value back",
          CANARY.encode() not in r.body,
          "error body carries loc/type/msg only",
          "the canary appeared in the error response")

    print()
    print("Response hygiene")
    missing = [lbl for lbl, resp, app_level in seen
               if app_level and resp.headers.get("x-content-type-options") != "nosniff"]
    checked = sum(1 for _, _, app_level in seen if app_level)
    check("  every response from the app carries X-Content-Type-Options: nosniff",
          not missing, f"{checked} responses checked", f"missing on {missing}")

    scored = probe("/score good token (again)", f"{base}/score", "POST", GOOD_PAYLOAD, auth)
    results = (scored.json() or {}).get("results") or []
    nan_fields = sorted({f"result[{i}].{k}" for i, row in enumerate(results)
                         for k, v in row.items() if isinstance(v, float) and v != v})
    check("  a mixed batch scores without a NaN reaching the response",
          bool(results) and not nan_fields,
          f"NaN at {nan_fields}" if nan_fields else f"{len(results)} results")

    print()
    if failures:
        print(f"{len(failures)} control(s) failed.")
        return 1
    print("Every control held.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
