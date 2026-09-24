"""Print or rewrite the pinned SHA-256 digests in artifacts.lock.json.

The scorer refuses to deserialise a model or schema whose digest does not match
the pin recorded in artifacts.lock.json (V14). Run this after retraining:

    python tools/checksum_artifacts.py            # show the current digests
    python tools/checksum_artifacts.py --write    # update the lock file

The lock file is tracked in git on purpose. A digest is not a secret, and
version control makes any change to a pin reviewable.
"""
import argparse
import hashlib
import json
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOCK_PATH = os.path.join(BASE_DIR, "artifacts.lock.json")


def sha256_of(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write",
        action="store_true",
        help="rewrite artifacts.lock.json with the digests observed on disk",
    )
    args = parser.parse_args()

    with open(LOCK_PATH, "r", encoding="utf-8") as fh:
        lock = json.load(fh)

    changed = False
    for name, entry in lock["artifacts"].items():
        full_path = os.path.join(BASE_DIR, entry["path"])
        if not os.path.exists(full_path):
            print(f"{name}: {entry['path']} not found - skipping")
            continue

        observed = sha256_of(full_path)
        status = "unchanged" if observed == entry.get("sha256") else "CHANGED"
        print(f"{name}: {observed}  ({status})")

        if observed != entry.get("sha256"):
            entry["sha256"] = observed
            changed = True

    if not args.write:
        if changed:
            print("\nLock file is out of date. Re-run with --write to update it.")
        return 0

    if not changed:
        print("\nLock file already matches the artifacts on disk; nothing written.")
        return 0

    with open(LOCK_PATH, "w", encoding="utf-8") as fh:
        json.dump(lock, fh, indent=2)
        fh.write("\n")
    print(f"\nUpdated {LOCK_PATH}")
    print("Review the change with `git diff` before committing it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
