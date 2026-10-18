"""Apify actor entry for FenrirLVX — zero-dependency wrapper (stdlib only).

INPUT: {"targets_text": "https://a.com\nhttps://b.com"}
For each target runs `fenrir scan -t <url>` and pushes the output plus the
vuln-DB coverage as one dataset item. Authorized targets only.
"""

from __future__ import annotations

import json
import os
import subprocess
import urllib.request
from pathlib import Path

APIFY_TOKEN = os.environ.get("APIFY_TOKEN", "")
APIFY_DEFAULT_DATASET_ID = os.environ.get("APIFY_DEFAULT_DATASET_ID", "")
APIFY_DEFAULT_KEY_VALUE_STORE_ID = os.environ.get("APIFY_DEFAULT_KEY_VALUE_STORE_ID", "")
APP = Path(__file__).resolve().parent


def _api(url: str, method: str = "GET", body: dict | None = None) -> dict:
    sep = "&" if "?" in url else "?"
    full = f"{url}{sep}token={APIFY_TOKEN}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        full, data=data, method=method,
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode())


def get_input() -> dict:
    if APIFY_DEFAULT_KEY_VALUE_STORE_ID:
        try:
            doc = _api(f"https://api.apify.com/v2/key-value-stores/"
                       f"{APIFY_DEFAULT_KEY_VALUE_STORE_ID}/records/INPUT")
            if isinstance(doc, dict):
                return doc
        except Exception:  # noqa: BLE001
            pass
    p = APP / "storage/key_value_stores/default/INPUT.json"
    return json.loads(p.read_text()) if p.exists() else {}


def push_item(item: dict) -> None:
    if APIFY_DEFAULT_DATASET_ID:
        _api(f"https://api.apify.com/v2/datasets/{APIFY_DEFAULT_DATASET_ID}/items",
             method="POST", body=item)


def get_input_local() -> dict:
    p = APP / "storage/key_value_stores/default/INPUT.json"
    return json.loads(p.read_text()) if p.exists() else {}


def valid_target(url: str) -> bool:
    return url.startswith(("http://", "https://"))


def main() -> None:
    inp = get_input()
    raw = inp.get("targets_text") or ""
    targets = [t.strip() for t in raw.splitlines()
               if t.strip() and valid_target(t.strip())]
    if not targets:
        raise RuntimeError("no valid targets — one URL (http/https) per line")
    if len(targets) > 50:
        raise RuntimeError("max 50 targets per run — this is an authorized-testing tool")

    binaries_ok = (APP / "fenrir").exists() and (APP / "vuln_db.json").exists()
    if not binaries_ok:
        raise RuntimeError("fenrir binary or vuln_db.json missing from build")

    results = []
    for t in targets:
        proc = subprocess.run(
            [str(APP / "fenrir"), "scan", "-t", t],
            capture_output=True, text=True, timeout=300,
            cwd=str(APP)  # fenrir loads vuln_db.json relative to cwd
        )
        item = {
            "target": t,
            "exit_code": proc.returncode,
            "output": (proc.stdout or "")[-12000:],
            "stderr": (proc.stderr or "")[-2000:],
            "disclaimer": "Authorized-targets-only tool. Output is evidence, not a verdict.",
        }
        results.append(item)
        push_item(item)

    summary = {"mode": "scan", "targets": len(targets), "ok": sum(
        1 for r in results if r["exit_code"] == 0)}
    try:
        if APIFY_DEFAULT_KEY_VALUE_STORE_ID:
            _api(f"https://api.apify.com/v2/key-value-stores/"
                 f"{APIFY_DEFAULT_KEY_VALUE_STORE_ID}/records/SUMMARY",
                 method="PUT", body=summary)
    except Exception:  # noqa: BLE001
        pass
    print(f"done: {summary}")


if __name__ == "__main__":
    main()
