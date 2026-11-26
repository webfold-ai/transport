#!/usr/bin/env python3
"""Reject hosting-runtime in every Cargo edge (including dev/build) and Nix input.

Run on the build box. This resolves metadata, never compiles or runs a service.
Operately: lift-hosting-runtime-edge-BNoBncQ7r82CFL0wVLiIBn
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = re.compile(r"[/ :]hosting[-_]runtime(?:\.git)?(?:[/?#\s]|$)", re.I)


def check_urls(value, context):
    if isinstance(value, str):
        if FORBIDDEN.search(unquote(value)):
            raise ValueError(f"{context}: forbidden hosting-runtime reference: {value}")
    elif isinstance(value, dict):
        for key, child in value.items():
            check_urls(child, f"{context}.{key}")
    elif isinstance(value, list):
        for child in value:
            check_urls(child, context)


def check_graph(metadata, lock, root):
    for package in metadata["packages"]:
        check_urls(package.get("source"), package["name"])
        if package.get("source") is None:
            manifest = Path(package["manifest_path"]).resolve()
            if not manifest.is_relative_to(root):
                raise ValueError(f"external path dependency: {manifest}")
            with manifest.open("rb") as handle:
                check_urls(tomllib.load(handle), str(manifest))
    check_urls(lock, "flake.lock")


def self_test():
    # Negative controls exercise git aliases, dev/build metadata sources and
    # Nix input payloads; there is no ignore list for test-only dependencies.
    for source in (
        "git+https://github.com/Tasmanian-Cloud/hosting-runtime?rev=deadbeef",
        "ssh://git@github.com/webfold-ai/hosting-runtime.git#deadbeef",
        "https://github.com/Tasmanian-Cloud/hosting%2Druntime",
    ):
        try:
            check_urls({"dev-dependencies": {"fixture": {"git": source}}}, "mutant")
        except ValueError:
            pass
        else:
            raise AssertionError(f"guard accepted forbidden source {source}")
    try:
        check_graph(
            {"packages": []},
            {"nodes": {"fixture": {"locked": {"url": "https://github.com/Tasmanian-Cloud/hosting-runtime"}}}},
            ROOT,
        )
    except ValueError:
        pass
    else:
        raise AssertionError("guard accepted forbidden Nix input")
    check_urls("https://github.com/webfold-ai/transport", "positive")
    print("PASS: four forbidden-source controls rejected; canonical source accepted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, help="reuse captured all-features Cargo metadata")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if args.metadata:
        metadata = json.loads(args.metadata.read_text())
    else:
        metadata = json.loads(subprocess.check_output(
            ["cargo", "metadata", "--locked", "--all-features", "--format-version", "1"],
            cwd=ROOT,
        ))
    lock = json.loads((ROOT / "flake.lock").read_text())
    check_graph(metadata, lock, ROOT)
    check_urls((ROOT / "flake.nix").read_text(), "flake.nix")
    print(f"PASS: {len(metadata['packages'])} resolved Cargo packages (all features, dev/build included) and Nix inputs contain no hosting-runtime dependency")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, AssertionError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
