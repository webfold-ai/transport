#!/usr/bin/env python3
"""Five SYNTHETIC negative controls. Run on a disposable box-run mirror only.

Each mutation must compile and fail the named existing contract test; a build
error is not evidence of sensitivity. Every source is restored byte-for-byte in
finally, including when cargo raises. No local build, server or production I/O.
Operately: lift-hosting-runtime-edge-BNoBncQ7r82CFL0wVLiIBn
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if not os.environ.get("BOXRUN_WORK"):
    sys.exit("refused: run through box-run, not on the workstation")
OUT = Path(os.environ["BOXRUN_WORK"]) / "edge-lift-controls"
OUT.mkdir(parents=True, exist_ok=True)
CONTROLS = [
    ("tas-lb", "src/signed_config.rs",
     "if !signer.verify(&preimage(signer.as_bytes(), seq, body), &sig) {",
     "if signer.verify(&preimage(signer.as_bytes(), seq, body), &sig) {",
     "signed_config::tests::every_altered_byte_breaks_the_document"),
    ("tas-dns", "src/names.rs",
     'if c != apex_s && !c.ends_with(&format!(".{apex_s}")) {',
     'if false && c != apex_s && !c.ends_with(&format!(".{apex_s}")) {',
     "names::tests::owners_resolve_inside_the_apex_only"),
    ("edge-lb", "src/control.rs",
     ".is_some_and(|s| hashtrinity::crypto::ct_eq(s.as_bytes(), secret.as_bytes()))",
     ".is_some_and(|s| !hashtrinity::crypto::ct_eq(s.as_bytes(), secret.as_bytes()))",
     "control::tests::every_route_demands_the_control_secret"),
    ("mesh-acl-reconciler", "src/lib.rs",
     ".filter(|r| !desired_set.contains(&(r.user_id, r.deployment_id)))",
     ".filter(|r| desired_set.contains(&(r.user_id, r.deployment_id)))",
     "diff_tests::desired_and_actual_diff_adds_missing_revokes_stale_and_preserves_the_exact_pair"),
    ("console-ws-proxy", "src/lib.rs",
     "if !ct_eq(&expected, &sig) {", "if ct_eq(&expected, &sig) {",
     "tests::signer_rejects_tampered_signature"),
]
only = sys.argv[1:]
if only and (len(only) != 1 or only[0] not in {c[0] for c in CONTROLS}):
    sys.exit("usage: edge-lift-negative-controls.py [crate]")
summary = OUT / "summary.json"
receipts = json.loads(summary.read_text()) if only and summary.exists() else []
for crate, relative, old, new, test in CONTROLS:
    if only and crate != only[0]:
        # Reuse receipts only while their exact source remains unchanged.
        prior = next((r for r in receipts if r["crate"] == crate), None)
        if prior and hashlib.sha256((ROOT / "crates" / crate / relative).read_bytes()).hexdigest() != prior["original_sha256"]:
            sys.exit(f"refused: stale negative-control receipt for {crate}")
        continue
    path = ROOT / "crates" / crate / relative
    original = path.read_bytes()
    text = original.decode()
    if text.count(old) != 1:
        sys.exit(f"refused: expected one mutation location in {crate}")
    try:
        path.write_text(text.replace(old, new, 1))
        proc = subprocess.run(
            # Match the positive gate's feature-unified dependency graph, avoiding
            # five redundant builds of transitive dependencies on the shared box.
            ["cargo", "test", *[arg for c in CONTROLS for arg in ("-p", c[0])],
             "--lib", test, "--", "--exact"],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=180,
        )
        (OUT / (crate + ".log")).write_text(proc.stdout)
        detected = proc.returncode != 0 and f"test {test} ... FAILED" in proc.stdout
        receipt = {"crate": crate, "test": test, "exit": proc.returncode,
                   "intended_test_failed": detected, "synthetic": True}
    finally:
        path.write_bytes(original)
    receipt["restored_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    receipt["original_sha256"] = hashlib.sha256(original).hexdigest()
    assert receipt["restored_sha256"] == receipt["original_sha256"]
    receipts = [r for r in receipts if r["crate"] != crate]
    receipts.append(receipt)
    print(json.dumps(receipt), flush=True)
(OUT / "summary.json").write_text(json.dumps(receipts, indent=2) + "\n")
sys.exit(0 if all(r["intended_test_failed"] for r in receipts) else 1)
