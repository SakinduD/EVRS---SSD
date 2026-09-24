"""Check the scorer against the contract the Node backend actually relies on.

The unit and black-box tests prove the service rejects what it should. They do
not prove it still answers correctly for the one caller that matters. This
script builds a payload with the exact shape `getRisks()` in
server/controllers/adminController.js produces, sends it the way that controller
sends it, and asserts the response carries every field the controller then reads.

It is the cheapest way to catch a break in the integration without standing up
MongoDB, the Node server and the Next.js client.

    python tools/contract_test.py                  # against localhost:8081
    python tools/contract_test.py --url http://127.0.0.1:8085

Exit code 0 means the contract holds.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request

from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(BASE_DIR, ".env"))

TOKEN_HEADER = "X-Internal-Token"

# Exactly the keys adminController.js sets on patientData, including the ones it
# sets to null, so a change in how the scorer treats missing values shows up here.
NODE_PAYLOAD = {
    "mode": "latest",
    "events": [
        {
            "citizenId": "CTR-0001",
            "birthDate": "2023-01-10",
            "district": "Colombo",
            "division": "Dehiwala",
            "bloodType": "O+",
            "allergies": ["eggs"],
            "medicalConditions": ["asthma"],
            "guardianPhone": "0771234567",
            "guardianEmail": "guardian@example.com",
            "hospitalId": "HOSP001",
            "mohId": None,
            "v1Code": "BCG",
            "v1Date": "2023-01-15",
            "v1Location": "Colombo General Hospital",
            "v1HcpId": "HCP001",
            "v2Code": "OPV",
            "v2Date": "2023-03-20",
            "v2Location": "Colombo General Hospital",
            "v2HcpId": "HCP001",
        },
        {
            # A citizen with no vaccination history at all: the controller still
            # sends them, and the scorer must not fall over.
            "citizenId": "CTR-0002",
            "birthDate": "2024-06-01",
            "district": "Gampaha",
            "division": "Negombo",
            "bloodType": None,
            "allergies": [],
            "medicalConditions": [],
            "guardianPhone": None,
            "guardianEmail": None,
            "hospitalId": None,
            "mohId": None,
        },
    ],
}

# The fields adminController.js reads off each result in mapRiskData().
REQUIRED_RESULT_FIELDS = [
    "citizenId",
    "dose_number",
    "risk_prob",
    "risk_tier",
    "due_by",
    "recommended_action",
]

# The controller buckets on these exact strings.
VALID_TIERS = {"High", "Medium", "Low"}


def post(url: str, body: dict, token: str | None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers[TOKEN_HEADER] = token
    request = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        return err.code, None
    except urllib.error.URLError as err:
        print(f"FAIL  cannot reach {url}: {err.reason}")
        sys.exit(2)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8081")
    args = parser.parse_args()

    token = (os.getenv("INTERNAL_API_TOKEN") or "").strip()
    if not token:
        print("FAIL  INTERNAL_API_TOKEN is not set; cannot run the contract test.")
        return 2

    endpoint = f"{args.url.rstrip('/')}/score"
    failures = []

    def check(label: str, passed: bool, detail: str = ""):
        print(f"{'pass' if passed else 'FAIL'}  {label}{'  ' + detail if detail else ''}")
        if not passed:
            failures.append(label)

    # 1. The shape the Node backend sends is accepted.
    status, payload = post(endpoint, NODE_PAYLOAD, token)
    check("Node-shaped payload accepted", status == 200, f"HTTP {status}")
    if status != 200:
        print("\nThe scorer rejected the payload the backend sends. Nothing below "
              "can be checked until that is fixed.")
        return 1

    # 2. The envelope the controller destructures is present.
    check("response has a 'results' array", isinstance(payload.get("results"), list))
    results = payload.get("results") or []

    # 3. Every field mapRiskData() reads exists on every result.
    for index, result in enumerate(results):
        missing = [f for f in REQUIRED_RESULT_FIELDS if f not in result]
        check(f"result[{index}] has all mapped fields",
              not missing,
              f"missing {missing}" if missing else "")

    # 4. risk_tier matches the strings the controller buckets on. A typo or a
    #    casing change here silently empties the dashboard rather than erroring.
    tiers = {r.get("risk_tier") for r in results}
    check("risk_tier values are High/Medium/Low",
          tiers <= VALID_TIERS,
          f"got {sorted(t for t in tiers if t)}")

    # 5. risk_prob must be a number the frontend can format.
    check("risk_prob is numeric",
          all(isinstance(r.get("risk_prob"), (int, float)) for r in results))

    # 6. A citizen with no doses must not crash the scorer. The current model
    #    skips them, so they are simply absent from results - the controller
    #    tolerates that, but it must not be an error.
    scored_ids = {r.get("citizenId") for r in results}
    check("citizen with no vaccination history handled",
          "CTR-0001" in scored_ids,
          f"scored: {sorted(i for i in scored_ids if i)}")

    # 7. The auth contract itself: the same payload without the header is refused.
    status_noauth, _ = post(endpoint, NODE_PAYLOAD, None)
    check("same payload without the token is refused",
          status_noauth == 401,
          f"HTTP {status_noauth}")

    print()
    if failures:
        print(f"{len(failures)} contract check(s) failed.")
        return 1
    print("Contract holds: the scorer answers what adminController.js expects.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
