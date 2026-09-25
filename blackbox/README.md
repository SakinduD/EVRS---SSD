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

## Targets and results (after)

| Service | Target | Scanned | High | Med | Low | Info |
|---|---|---|---:|---:|---:|---:|
| Frontend (Next.js) | `http://localhost:3000` | 25 Sep 2026 22:41 | 0 | 3 | 1 | 4 |
| Backend (Express) | `http://localhost:5000` | 25 Sep 2026 21:41 | 2 | 0 | 6 | 3 |
| Risk scorer, no token | `http://127.0.0.1:8081` | 25 Sep 2026 20:03 | 0 | 0 | 0 | 0 |
| Risk scorer, with token | `http://127.0.0.1:8081` | 25 Sep 2026 19:59 | 1 | 0 | 0 | 0 |

The backend's two Highs are also false positives — see below. Both services
therefore finish with no High-risk finding that survives triage.

### Frontend, before against after

Scoped to `http://localhost:3000`. Traditional spider plus AJAX spider plus
active scan, unauthenticated, against the Next.js development server, matching
the before-scan.

| Alert | Risk | Before | After | |
|---|---|---:|---:|---|
| Content Security Policy (CSP) Header Not Set | Medium | 45 | – | fixed |
| Missing Anti-clickjacking Header | Medium | 42 | – | fixed |
| Server Leaks Information via `X-Powered-By` | Low | 45 | – | fixed |
| `X-Content-Type-Options` Header Missing | Low | 75 | 1 | see below |
| CSP: script-src unsafe-inline | Medium | – | 5 | new, see below |
| CSP: style-src unsafe-inline | Medium | – | 5 | new, see below |
| CSP: script-src unsafe-eval | Medium | – | 5 | new, development only |

The Medium count goes from 2 to 3, and that number on its own is misleading.
The frontend had no security headers at all: `client/next.config.ts` was an
empty object. It now sets a CSP, `X-Frame-Options`, `X-Content-Type-Options`,
`Referrer-Policy` and `Permissions-Policy`, and no longer advertises its
framework version. ZAP has stopped reporting the *absence* of a policy and
started reporting the *weaknesses* of the one that is there.

Those weaknesses are real and are not hidden here. Two of them - `unsafe-inline`
on script and on style - are what it costs to serve Next.js without a
per-request nonce, and the decision not to take the nonce route is explained in
`blackbox-after/reports/frontend-headers-proof.txt`. The third, `unsafe-eval`,
is emitted only under `isDev`; a production build does not carry it, and it
appears here because the scan runs against the development server so that it
compares against the before-scan rather than against a different application.

The single remaining `X-Content-Type-Options` instance is on
`POST /__nextjs_original-stack-frames`, a Next.js development-only internal
route that the dev server answers before `next.config`'s `headers()` apply. It
does not exist in a production build.

### Backend, before against after

The backend after-scan was far wider than the before-scan: 22,956 requests
against a browse that covered all five roles, every list and detail page, the
search and filter parameters, one create/edit/delete of each entity type and a
password change. Counts are only comparable with that in mind — several of the
new Lows are new because the scan reached code the before-scan never did.

| Alert | Before | After | |
|---|---:|---:|---|
| Buffer Overflow | 5 (Med) | – | fixed |
| CSP: Wildcard Directive | 1 (Med) | – | fixed |
| Content Security Policy Header Not Set | 1 (Med) | – | fixed |
| Missing Anti-clickjacking Header | 1 (Med) | – | fixed |
| Application Error Disclosure | 10 (Low) | 1 (Low) | mostly fixed |
| XSS Weakness (Persistent in JSON Response) | 20 (Low) | 9 (Low) | reduced |
| Server Leaks Information via `X-Powered-By` | 74 (Low) | 81 (Low) | still open |
| `X-Content-Type-Options` Header Missing | 53 (Low) | 62 (Low) | still open |
| Information Disclosure - Debug Error Messages | – | 1 (Low) | newly reached |
| Private IP Disclosure | – | 10 (Low) | newly reached |
| Path Traversal | – | 3 (High) | **false positive** |
| SQL Injection - SQLite | – | 2 (High) | **false positive** |

**Every Medium is gone.** The four in the before-scan — the unhandled exception
on oversized input that ZAP labels "Buffer Overflow", and the three
security-header findings — no longer fire.

**Still open on the backend**, and owned by the backend hardening work rather
than by this scan: `X-Powered-By` is still advertised, `X-Content-Type-Options`
is still absent on 62 responses, and one error path still returns a debug
message and a private IP. `server/server.js` mounts `express.json`,
`cookieParser` and `cors` but no `helmet`, and `helmet` is not in
`server/package.json`; adding it would clear four of the six remaining Lows. After triage the risk scorer has **no genuine
findings**. The no-token report contains no alerts at all, which is the point of
running it: the surface an unauthenticated caller can reach is now empty.

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

**Backend, after-scan** — the before-scan registered six JWTs with ZAP's Header
Based Session Management method. That no longer works: login now sets an
httpOnly cookie and the response body carries no token. The after-scan was
therefore driven from a real browser launched by ZAP's Manual Explore, logging
in as each of the five roles in turn, so the cookies flow the way the
application actually issues them.

The browse deliberately covered the parameterised surface rather than only the
landing pages: the citizen search and district/division filters, one detail
page per entity type, one edit and one delete of a hospital and an MOH, a
registration of each entity type, the admin password change, the Calculate Risk
action (which is what puts `/api/admin/risks` and the ML integration into the
scan), and a failed login. Without those the scan would not reach the access
control that was fixed.

`/api/auth/logout/*` was excluded from the active scan. ZAP will happily call a
logout endpoint mid-scan, and every request after that would run
unauthenticated and report 401 rather than anything useful.

The scan ran against a throwaway `evrs_zaptest` database, never the shared one:
an active scan sends thousands of `PUT` and `DELETE` requests to endpoints that
really do delete records.

Active scan: 22,956 requests against `http://localhost:5000` only. The
`localhost:3000` node and the font and Mozilla CDNs picked up by the browser
were left out of scope.

**Risk scorer, after-scan** — run twice, from a fresh ZAP session each time, with
`curl` sending the seed requests through the ZAP proxy on `localhost:8082`:

- **Run A, no token.** `/score` and `/score/events_debug` without the internal
  token, plus `/health`, `/health/detail`, `/docs` and `/openapi.json`. Expected
  and observed: `200, 401, 404, 404, 401, 404`. Report: `ZAP_after_ML_noauth.html`.
- **Run B, with token.** The same surface authenticated, seeded with three
  payloads from `scan-inputs/`: the ordinary one the backend sends, the mixed
  batch that reproduced the NaN crash, and the traversal probe. All five requests
  returned 200. Report: `ZAP_after_ML.html`.

`/openapi.json` could not be imported this time — it now returns 404, because the
schema is no longer published. The endpoint list was therefore driven by `curl`
rather than by ZAP's OpenAPI import.

A ZAP Replacer rule was tried first for the token and did not apply; sending the
`X-Internal-Token` header directly from `curl` through the proxy worked and is
what the reports reflect.

## Reading the reports honestly

Some findings in these reports are not what their titles say. Each one below is
stated plainly rather than left for a reader to take at face value.

### Before-scan

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

### After-scan

4. **"Path Traversal" (6, High, ×3 on `POST /score`) is a false positive.** The
   handler performs no file operation. An AST walk over `app.py` shows the four
   request handlers contain zero file-opening calls: every read is either at
   import time or inside the integrity helpers, which no request can reach. Sent
   a traversal sequence in every string field the endpoint accepts and the
   response echoed the value back as a citizen id with no file content anywhere.
   ZAP is matching on the reflection, not on a read.
   Evidence: `blackbox-after/reports/traversal-fp-proof.txt`.

5. **`ZAP-2` was still present when the after-scan began, and was fixed on
   25 Sep 2026 before the reports above were generated.** The before-scan found
   an unhandled `ValueError` ("NaN values are not JSON compliant") on
   `/score/events_debug`. That endpoint was removed, but the same defect survived
   in the response builder of `POST /score`, the endpoint the Node backend
   actually calls, and surfaced as a 500 on the admin Manage Risks page against
   real data. Reporting `ZAP-2` as fixed while `/score` still carried it would
   have been wrong, so it was fixed and a regression test added.
   Evidence: `blackbox-after/reports/nan-fix-proof.txt`.

6. **"SQL Injection - SQLite" (High, ×2 on the backend) is a false positive.**
   There is no SQL engine in the stack. `server/package.json` declares Mongoose
   and no SQL driver, ORM or SQLite binding, so there is no statement for an
   injection to alter. ZAP substituted the request path into a JSON body field
   and inferred a database from the response shape; the Evidence field is empty.
   Evidence: `blackbox-after/reports/backend-fp-proof.txt`.

7. **"Path Traversal" (High, ×3 on the backend) is a false positive, for the
   same reason as on the ML service.** All 50 JavaScript files under `server/`
   were searched for every filesystem entry point — `fs.*`, `readFile`,
   `writeFile`, `createReadStream`, `sendFile`, `res.download`, `path.join`,
   `path.resolve`, `__dirname` — with no match. A sanity check on the same file
   set matches "express" in 8 files, so the search ran over real source. A
   traversal sequence needs a file operation to traverse into, and the process
   never opens a path.
   Evidence: `blackbox-after/reports/backend-fp-proof.txt`.

## Reproducing

```
# 1. Check out the baseline into a separate directory
git worktree add ../evrs-baseline 41e13ae

# 2. Start the service under test from that directory

# 3. Run ZAP against the target, then:
#    Report > Generate Report > HTML, into the matching reports/ folder
```

The seed payloads for the risk-scorer after-scan are committed under
`scan-inputs/`, so both runs can be repeated exactly:

| File | What it is for |
|---|---|
| `score-payload.json` | One citizen, shaped the way `adminController.js` sends them |
| `nan-probe.json` | Two citizens, one with a vaccine code and one without — a *mixed* batch, which is the only case that reproduced the NaN crash |
| `traversal-probe.json` | A traversal sequence in every string field the endpoint accepts |

## Two changes made between the before and after scans

Both were found while preparing the after-scan rather than by ZAP itself, and
both are in `risk-scorer-ml/app.py`:

- `_json_safe()` in the response builder, which maps a pandas missing value onto
  `None`. pandas only produces `NaN` for a *mixed* column, so a single-citizen
  fixture never reproduced it and every batch from the backend did. This is the
  `ZAP-2` fix described above.
- `security_headers()` middleware, setting `X-Content-Type-Options: nosniff`.
  ZAP reported the missing header on `/health`, `/health/detail` and `/score`.
  The practical risk was close to nil — the scorer listens on loopback, only the
  backend calls it, and no browser renders its JSON — but that reasoning depends
  on the current deployment, and the header costs one line. It is registered
  outside the body-size middleware so it reaches every response, including the
  401s, the 413 and the validation 422s.
  Evidence: `blackbox-after/reports/nosniff-proof.txt`.

A third change was made in `client/next.config.ts`: `poweredByHeader: false`
plus a `headers()` block carrying the CSP, `X-Frame-Options`,
`X-Content-Type-Options`, `Referrer-Policy` and `Permissions-Policy` on
`/:path*`, so they reach static chunks as well as pages. The frontend had no
security headers before this. `src/middleware.ts` was deliberately left alone:
it exists to guard routes, and widening its matcher to every request just to
attach a header would put the role checks in the path of traffic they were
never written for.
Evidence: `blackbox-after/reports/frontend-headers-proof.txt`.

Each change was made *before* the after-scan report for that service was
generated, so every report describes the code as it stands.
