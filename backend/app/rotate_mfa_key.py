from __future__ import annotations

import argparse
import os
import sys

from app.db.database import SessionLocal
from app.services.mfa_key_rotation import (
    MFAKeyRotationError,
    rotate_mfa_encryption_key,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Safely rotate encrypted VulnScan TOTP secrets."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Commit the rotation. Without this flag, perform a validation-only dry run.",
    )
    args = parser.parse_args()
    old_key = os.environ.get("OLD_MFA_ENCRYPTION_KEY", "")
    new_key = os.environ.get("NEW_MFA_ENCRYPTION_KEY", "")
    if not old_key or not new_key:
        parser.error("Set OLD_MFA_ENCRYPTION_KEY and NEW_MFA_ENCRYPTION_KEY in the process environment.")

    try:
        with SessionLocal() as db:
            counts = rotate_mfa_encryption_key(
                db,
                old_key=old_key,
                new_key=new_key,
                apply=args.apply,
            )
    except MFAKeyRotationError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    action = "Rotated" if args.apply else "Validated"
    suffix = "changes committed" if args.apply else "dry run; no changes committed"
    print(f"{action} {counts['secrets']} encrypted MFA secrets across {counts['accounts']} accounts ({suffix}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
