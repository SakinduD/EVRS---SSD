# Black-box testing (OWASP ZAP)

Dynamic scans of the three EVRS services, run before and after the security
fixes so the two can be compared.

- Tool: **OWASP ZAP 2.16.0**
- Baseline scanned: commit **`41e13ae`** (the last upstream commit before any of
  this team's changes), extracted to a separate directory so that nothing from
  a working tree could leak into the "before" run.

## Layout

```
blackbox-before/reports/    HTML reports for the unfixed baseline
blackbox-after/reports/     HTML reports for the fixed code
```

ZAP's own `.session` databases are **not** committed. They are working files,
not evidence — the backend session alone is 1.2 GB, and the sessions store
captured request and response bodies including the test-account credentials.
They are excluded by `blackbox/**/session-data/` in the root `.gitignore`.

## Targets and results (before)

| Service | Target | Scanned | High | Med | Low | Info |
|---|---|---|---:|---:|---:|---:|
| Frontend (Next.js) | `http://localhost:3000` | 25 Sep 2026 00:59 | 0 | 2 | 2 | 4 |
| Backend (Express)  | `http://localhost:5000` | 25 Sep 2026 04:48 | 0 | 4 | 4 | 2 |
| Risk scorer (FastAPI) | `http://127.0.0.1:8081` | 24 Sep 2026 22:36 | 1 | 2 | 5 | 0 |

## How each scan was set up

**Backend** — authenticated. Six accounts (one per role) were created in a
throwaway `evrs_zaptest` database and their JWTs registered with ZAP's Header
Based Session Management method. This is why the crawl reached role-restricted
endpoints such as `/api/admin/patients` and `/api/moh/vaccinations/*` instead of
stopping at the login pages. See `blackbox-before/reports/zap_backend_accounts.redacted.txt`.

**Frontend** — unauthenticated spider plus active scan, run against the Next.js
**development** server (`npm run dev`). The after-scan must use the same mode:
production builds hash their chunk filenames differently, so a dev-vs-prod
comparison would be comparing two different URL sets rather than two states of
the same application.

**Risk scorer** — the service exposes only four endpoints, so the whole surface
was covered by importing `/openapi.json` and scanning the resulting requests.

## Reading the reports honestly

Three things in the before-reports need stating plainly rather than being taken
at face value:

1. **Four of the risk-scorer alerts were raised manually.** `V13a`, `V13b`,
   `V16` and `ZAP-2` carry no Plugin Id, because ZAP has no scan rule for
   "this API has no authentication". They were confirmed by sending the request
   and reading the response, then recorded in ZAP so they appear alongside the
   automated findings. Only `10021`, `90022` and `10023` came from ZAP's own
   rules.

2. **"Buffer Overflow" (30001, ×5 on the backend) is a false positive.** ZAP
   raises it whenever an oversized parameter produces a 500 and a closed
   connection; Node has no C buffers to overflow. The genuine defect underneath
   is an unhandled exception on oversized input (CWE-20 / CWE-755), and it is
   reported under that name.

3. **"Suspicious Comments" (10027, ×11 on the frontend) are all vendor code.**
   Every hit is inside Next.js's own development bundles, not application
   source. Triaged as a false positive.

## Reproducing

```
# 1. Check out the baseline into a separate directory
git worktree add ../evrs-baseline 41e13ae

# 2. Start the service under test from that directory

# 3. Run ZAP against the target, then:
#    Report > Generate Report > HTML, into the matching reports/ folder
```

For the **after** scan of the risk scorer, run it twice: once with no
`X-Internal-Token` header (every request should be refused, which is what
demonstrates the fix) and once with the token set as a ZAP Replacer rule (which
shows no new defects behind the authentication).
