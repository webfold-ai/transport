#!/usr/bin/env bash
# Print the flake `inputs` and `gitInputs` blocks for every git source in Cargo.lock, so flake.nix
# can be re-synced after Cargo.lock moves (a dependency bump, a rebase). The build fails if a rev
# here differs from Cargo.lock, so this is the one place to look when it does.
#
#   nix/git-inputs.sh [Cargo.lock]
#
# Paste the two blocks into flake.nix, then `nix flake lock`.
set -euo pipefail
lock="${1:-Cargo.lock}"
mapfile -t srcs < <(grep -oE 'source = "git\+[^"]+' "$lock" | sed 's/^source = "git+//' | sort -u)
declare -A seen
inputs="" gi=""
for s in "${srcs[@]}"; do
  frag="${s##*#}"; base="${s%%#*}"; base="${base%%\?*}"; base="${base%.git}"
  name="$(basename "$base" | tr -c 'A-Za-z0-9\n_-' '-')"
  key="$base#$frag"
  [ -n "${seen[$key]:-}" ] && continue; seen[$key]=1
  n="$name"; i=2; while grep -q "^    $n = " <<<"$inputs"; do n="$name-$i"; i=$((i+1)); done
  inputs+="    $n = {"$'\n'"      url = \"git+$base?rev=$frag&shallow=1\";"$'\n'"      flake = false;"$'\n'"    };"$'\n'
  gi+="        \"$base#$frag\" = inputs.$n;"$'\n'
done
printf '# inputs\n%s\n# gitInputs\n%s' "$inputs" "$gi"
