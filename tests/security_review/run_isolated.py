"""Run existing review probes against this review's disposable stack only."""

import os
import runpy
import sys
from pathlib import Path


if __name__ == "__main__":
    probe = sys.argv[1]
    if probe not in {"live_probe", "browser_probe"}:
        raise SystemExit("Unknown review probe")
    os.environ["SECURITY_AUDIT_CONFIRM"] = "isolated"
    namespace = runpy.run_path(str(Path(__file__).with_name(probe + ".py")))
    context = namespace["main"].__globals__
    context["BASE"] = os.environ.get(
        "AUDIT_BASE",
        "http://notes-review-final-917-api-1:8000",
    )
    if probe == "live_probe":
        context["DB_HOST"] = os.environ.get(
            "AUDIT_DB_HOST",
            "notes-review-final-917-db-1",
        )
    namespace["main"]()
