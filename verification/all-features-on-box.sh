#!/bin/sh
# FIPS needs Go as well as CMake. Obtain Go from this flake's locked
# nixpkgs, not an unpinned registry or a host-wide package installation.
set -eu
: "${BOXRUN_WORK:?run through box-run, never build on the workstation}"
export PATH="$HOME/.cargo/bin:/nix/var/nix/profiles/default/bin:$PATH"
ulimit -n 8192
exec nix shell --impure --expr \
  "let f = builtins.getFlake \"path:$PWD\"; in f.inputs.tas-nix.inputs.nixpkgs.legacyPackages.x86_64-linux.go" \
  --command cargo test --locked --all-features "$@"
