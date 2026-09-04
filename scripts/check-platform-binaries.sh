#!/usr/bin/env bash
# check-platform-binaries.sh — every prebuilt NAPI `.node` binary must sit in
# the platform directory it was built for, under a filename that names that
# same platform, and `file(1)` must agree with both.
#
# Why: the `commit-binaries` jobs in .github/workflows/build-*.yml copy CI
# artifacts into `<crate>/npm/<platform>/` and force-add them. A `find …
# | head -1` in the per-platform build step once picked up an already
# committed foreign binary instead of the fresh build, which is how
# `npm/linux-arm64-gnu/ruvector-gnn.darwin-arm64.node` and 14 siblings
# ended up in git. This script fails the job before such a file is
# committed.
#
# Usage:
#   scripts/check-platform-binaries.sh [ROOT ...]
# ROOT defaults to `crates npm`. node_modules/, target/ and artifacts/ are
# skipped. Exit 0 when every binary is consistent, 1 on any mismatch, and 1
# when no `.node` file was found at all (a check that inspects nothing must
# not report success).
#
# Directory / filename platform tokens follow napi-rs naming:
#   linux-x64-gnu linux-x64-musl linux-arm64-gnu linux-arm64-musl
#   darwin-x64 darwin-arm64 win32-x64-msvc win32-arm64-msvc
# plus the bare `linux-x64` / `linux-arm64` forms used under npm/core/native.
# `file` cannot tell glibc from musl; the libc suffix is checked by name only.

set -euo pipefail

roots=("$@")
if [ ${#roots[@]} -eq 0 ]; then
  roots=(crates npm)
fi

if ! command -v file >/dev/null 2>&1; then
  echo "check-platform-binaries: 'file' is required" >&2
  exit 1
fi

platform_re='^(linux|darwin|win32)-(x64|arm64)(-(gnu|musl|msvc))?$'

# os-arch (no libc) from a `file -b` description, or "" if unrecognised.
file_platform() {
  local desc="$1" os="" arch=""
  case "$desc" in
    *"Mach-O"*)        os=darwin ;;
    *"ELF "*)          os=linux ;;
    *"PE32+"*|*"PE32"*) os=win32 ;;
  esac
  case "$desc" in
    *x86-64*|*x86_64*|*x86-64*)      arch=x64 ;;
    *aarch64*|*arm64*|*Aarch64*)     arch=arm64 ;;
  esac
  if [ -n "$os" ] && [ -n "$arch" ]; then
    echo "${os}-${arch}"
  fi
}

# Strip a libc suffix: linux-x64-gnu -> linux-x64.
base_platform() {
  local p="$1"
  p="${p%-gnu}"; p="${p%-musl}"; p="${p%-msvc}"
  echo "$p"
}

checked=0
bad=0
printf '%-8s %-16s %-16s %-14s %s\n' STATUS DIR NAME FILE PATH

while IFS= read -r -d '' path; do
  checked=$((checked + 1))
  dir_platform=$(basename "$(dirname "$path")")
  if ! [[ "$dir_platform" =~ $platform_re ]]; then
    dir_platform=""
  fi

  fname=$(basename "$path")
  name_platform=""
  stem="${fname%.node}"
  candidate="${stem##*.}"
  if [ "$candidate" != "$stem" ] && [[ "$candidate" =~ $platform_re ]]; then
    name_platform="$candidate"
  fi

  desc=$(file -b "$path")
  file_plat=$(file_platform "$desc")

  status=OK
  reasons=()

  if [ -z "$dir_platform" ] && [ -z "$name_platform" ]; then
    status=SKIP
    reasons+=("neither directory nor filename names a platform")
  else
    expected="${dir_platform:-$name_platform}"
    if [ -n "$dir_platform" ] && [ -n "$name_platform" ] && [ "$dir_platform" != "$name_platform" ]; then
      status=MISMATCH
      reasons+=("filename platform '$name_platform' != directory platform '$dir_platform'")
    fi
    if [ -z "$file_plat" ]; then
      status=MISMATCH
      reasons+=("unrecognised binary type: $desc")
    elif [ "$file_plat" != "$(base_platform "$expected")" ]; then
      status=MISMATCH
      reasons+=("file(1) reports '$file_plat' but expected '$(base_platform "$expected")'")
    fi
  fi

  [ "$status" = MISMATCH ] && bad=$((bad + 1))
  printf '%-8s %-16s %-16s %-14s %s\n' "$status" "${dir_platform:--}" "${name_platform:--}" "${file_plat:-?}" "$path"
  for r in "${reasons[@]:-}"; do
    [ -n "$r" ] && printf '         -> %s\n' "$r"
  done
done < <(find "${roots[@]}" -type f -name '*.node' \
           -not -path '*/node_modules/*' -not -path '*/target/*' -not -path '*/artifacts/*' \
           -print0 2>/dev/null | sort -z)

echo
if [ "$checked" -eq 0 ]; then
  echo "check-platform-binaries: no .node files found under: ${roots[*]}" >&2
  exit 1
fi
if [ "$bad" -gt 0 ]; then
  echo "check-platform-binaries: $bad of $checked binaries are in the wrong place or built for the wrong platform" >&2
  exit 1
fi
echo "check-platform-binaries: $checked binaries consistent"
