#!/usr/bin/env bash
set -euo pipefail

# ============================================
# Offline Trivy Bulk Scanner (Podman) + SBOMs
# ============================================
# Requires: podman, trivy, (optional) coreutils 'timeout'
# Assumes: ~/.cache/trivy/db/{trivy.db,metadata.json} already present
# Output:
#   ./trivy-reports-YYYYmmdd-HHMMSS/*.json   (vuln scan results)
#   ./sboms-YYYYmmdd-HHMMSS/*.json           (SBOMs per image)
#
# Env you can override:
#   SEVERITY=""                      # default empty => include ALL severities
#   CACHE_DIR="$HOME/.cache/trivy"
#   ONLY_TAGGED="true"               # skip <none>:<none>
#   TRIVY_PKG_TYPES="os,library"     # scan both OS & app deps by default
#   TRIVY_SCANNERS="vuln"            # add "secret,config" if desired
#   FORCE_ARCHIVE="true"             # default: reliable archive mode
#   SAVE_TIMEOUT="120s"              # timeout for 'podman save'
#   TRIVY_TIMEOUT="10m"              # Trivy's internal timeout per image
#   EXTERNAL_TIMEOUT=""              # outer timeout per scan, e.g. "12m"
#   GENERATE_SBOM="true"             # generate SBOMs per image
#   SBOM_FORMAT="cyclonedx"          # "cyclonedx" or "spdx-json"
# ============================================

SEVERITY="${SEVERITY:-}"   # empty => include all
CACHE_DIR="${CACHE_DIR:-$HOME/.cache/trivy}"
ONLY_TAGGED="${ONLY_TAGGED:-true}"
TRIVY_PKG_TYPES="${TRIVY_PKG_TYPES:-os,library}"
TRIVY_SCANNERS="${TRIVY_SCANNERS:-vuln}"
FORCE_ARCHIVE="${FORCE_ARCHIVE:-true}"
SAVE_TIMEOUT="${SAVE_TIMEOUT:-120s}"
TRIVY_TIMEOUT="${TRIVY_TIMEOUT:-10m}"
EXTERNAL_TIMEOUT="${EXTERNAL_TIMEOUT:-}"
GENERATE_SBOM="${GENERATE_SBOM:-true}"
SBOM_FORMAT="${SBOM_FORMAT:-cyclonedx}"   # or "spdx-json"

# --- sanity checks ---
command -v podman >/dev/null || { echo "podman not found"; exit 1; }
command -v trivy  >/dev/null || { echo "trivy not found";  exit 1; }
[[ -f "$CACHE_DIR/db/trivy.db" && -f "$CACHE_DIR/db/metadata.json" ]] || {
  echo "Trivy offline DB not found in $CACHE_DIR/db (need trivy.db and metadata.json)"; exit 1;
}

# optional: 'timeout' command (from coreutils)
if command -v timeout >/dev/null 2>&1; then
  HAVE_TIMEOUT=1
else
  HAVE_TIMEOUT=0
  if [[ -n "$EXTERNAL_TIMEOUT" || -n "$SAVE_TIMEOUT" ]]; then
    echo "[!] 'timeout' not found; external timeouts will be skipped. Install coreutils if needed."
  fi
fi

# --- detect Trivy version ---
TRIVY_VER_RAW="$(trivy --version 2>/dev/null || true)"
# Expect "Version: 0.61.1"
TRIVY_VER="$(awk -F': ' '/Version:/{print $2}' <<<"$TRIVY_VER_RAW" | tr -d '\r')"
TRIVY_MAJOR="$(cut -d. -f1 <<<"${TRIVY_VER#v}")"
TRIVY_MINOR="$(cut -d. -f2 <<<"${TRIVY_VER#v}")"
TRIVY_PATCH="$(cut -d. -f3 <<<"${TRIVY_VER#v}")"
# Flag: supports 'trivy sbom --input' (>= 0.62.0)
supports_sbom_input=false
if [[ -n "$TRIVY_VER" ]]; then
  if (( TRIVY_MAJOR > 0 )) || (( TRIVY_MAJOR == 0 && TRIVY_MINOR >= 62 )); then
    supports_sbom_input=true
  fi
fi
echo "[*] Trivy detected: ${TRIVY_VER:-unknown} (sbom --input supported: $supports_sbom_input)"

timestamp="$(date +%Y%m%d-%H%M%S)"
WORKDIR="$(pwd)"
REPORT_DIR="${WORKDIR}/trivy-reports-${timestamp}"
SBOM_DIR="${WORKDIR}/sboms-${timestamp}"
mkdir -p "$REPORT_DIR" "$SBOM_DIR"

# Common Trivy flags for vulnerability scanning
TRIVY_FLAGS_COMMON=(
  --skip-db-update
  --offline-scan
  --cache-dir "$CACHE_DIR"
  --format json
  --timeout "$TRIVY_TIMEOUT"
)
[[ -n "$SEVERITY"        ]] && TRIVY_FLAGS_COMMON+=( --severity "$SEVERITY" )
[[ -n "$TRIVY_PKG_TYPES" ]] && TRIVY_FLAGS_COMMON+=( --pkg-types "$TRIVY_PKG_TYPES" )
[[ -n "$TRIVY_SCANNERS"  ]] && TRIVY_FLAGS_COMMON+=( --scanners "$TRIVY_SCANNERS" )

TRIVY_FLAGS_BY_NAME=("${TRIVY_FLAGS_COMMON[@]}" --image-src podman)
TRIVY_FLAGS_BY_ARCHIVE=("${TRIVY_FLAGS_COMMON[@]}")  # --image-src not needed with --input/--file

# SBOM flags (minimal; avoid severity/scanner noise)
SBOM_FLAGS_COMMON=(
  --skip-db-update
  --offline-scan
  --cache-dir "$CACHE_DIR"
  --timeout "$TRIVY_TIMEOUT"
  --format "$SBOM_FORMAT"
)
# For older Trivy (0.61.1), SBOM via `trivy image --format cyclonedx|spdx-json`
SBOM_IMAGE_BY_NAME=("${SBOM_FLAGS_COMMON[@]}" --image-src podman)
SBOM_IMAGE_BY_ARCHIVE=("${SBOM_FLAGS_COMMON[@]}")  # + (--input or --file) decided below

# --- Socket detection (if not forcing archive) ---
: "${XDG_RUNTIME_DIR:=/run/user/$(id -u)}"
USER_SOCK="$XDG_RUNTIME_DIR/podman/podman.sock"
ROOT_SOCK="/run/podman/podman.sock"

USE_ARCHIVE_FALLBACK="$FORCE_ARCHIVE"
if [[ "$FORCE_ARCHIVE" != "true" ]]; then
  if   [[ -S "$USER_SOCK" ]]; then export DOCKER_HOST="unix://$USER_SOCK"
  elif [[ -S "$ROOT_SOCK" ]]; then export DOCKER_HOST="unix://$ROOT_SOCK"
  else USE_ARCHIVE_FALLBACK="true"
  fi
fi

# --- Image discovery ---
echo "[*] Listing local Podman images..."
if [[ "$ONLY_TAGGED" == "true" ]]; then
  mapfile -t IMAGE_NAMES < <(
    podman images --format '{{.Repository}}:{{.Tag}}' \
    | grep -v '^<none>:<none>$' | sort -u
  )
else
  mapfile -t IMAGE_NAMES < <(podman images --format '{{.Repository}}:{{.Tag}} {{.ID}}' | sort -u)
fi

if [[ "$ONLY_TAGGED" == "true" && ${#IMAGE_NAMES[@]} -eq 0 ]]; then
  echo "No tagged images found. Tag images or set ONLY_TAGGED=false."
  exit 0
fi

sanitize() { echo "$1" | tr '/:@' '_' ; }

echo "[*] Found ${#IMAGE_NAMES[@]} images."
echo "[*] Mode: $([[ "$USE_ARCHIVE_FALLBACK" == "true" ]] && echo ARCHIVE || echo API)"

# --- helpers for timeouts ---
run_with_timeout() {
  local dur="${1:-}"; shift || true
  if [[ -n "$dur" && $HAVE_TIMEOUT -eq 1 ]]; then
    timeout --preserve-status "$dur" "$@"
  else
    "$@"
  fi
}

# Temp workspace for archives (auto-clean)
TMPDIR="$(mktemp -d -t trivy-archive-XXXXXX)"
cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

# --- Scan & SBOM functions ---
scan_vuln_by_name() {
  local name="$1" safe out
  safe="$(sanitize "$name")"
  out="$REPORT_DIR/${safe}.json"
  echo "  - [SCAN] ${name} (API)"
  run_with_timeout "$EXTERNAL_TIMEOUT" trivy image "${TRIVY_FLAGS_BY_NAME[@]}" -o "$out" "$name"
}

scan_vuln_by_archive_ref() {
  local ref="$1" safe tar out
  safe="$(sanitize "$ref")"
  tar="$TMPDIR/${safe}.tar"
  out="$REPORT_DIR/${safe}.json"
  echo "  - [SAVE] ${ref} → ${tar}"
  run_with_timeout "$SAVE_TIMEOUT" podman save -o "$tar" "$ref"
  echo "    [SCAN] ${ref} (archive)"
  # In 0.61.1, `trivy image --input` works; fall back to --file if --input is not supported
  if trivy image --help 2>/dev/null | grep -q -- '--input'; then
    run_with_timeout "$EXTERNAL_TIMEOUT" trivy image "${TRIVY_FLAGS_BY_ARCHIVE[@]}" --input "$tar" -o "$out"
  else
    # Older behavior: --file is less ideal but available
    run_with_timeout "$EXTERNAL_TIMEOUT" trivy image "${TRIVY_FLAGS_BY_ARCHIVE[@]}" --file "$tar" -o "$out"
  fi
  echo "    [CLEAN] ${tar}"
  rm -f "$tar"
}

# SBOM creation (version-aware)
sbom_by_name() {
  local name="$1" safe out
  [[ "$GENERATE_SBOM" == "true" ]] || return 0
  safe="$(sanitize "$name")"
  out="$SBOM_DIR/${safe}.json"
  if $supports_sbom_input; then
    echo "    [SBOM] ${name} (API, $SBOM_FORMAT via 'trivy sbom')"
    run_with_timeout "$EXTERNAL_TIMEOUT" trivy sbom "${SBOM_FLAGS_COMMON[@]}" --image-src podman -o "$out" "$name"
  else
    echo "    [SBOM] ${name} (API, $SBOM_FORMAT via 'trivy image')"
    run_with_timeout "$EXTERNAL_TIMEOUT" trivy image "${SBOM_IMAGE_BY_NAME[@]}" -o "$out" "$name"
  fi
}

sbom_by_archive_ref() {
  local ref="$1" safe tar out
  [[ "$GENERATE_SBOM" == "true" ]] || return 0
  safe="$(sanitize "$ref")"
  tar="$TMPDIR/${safe}.tar"
  out="$SBOM_DIR/${safe}.json"
  echo "  - [SAVE] ${ref} → ${tar} (for SBOM)"
  run_with_timeout "$SAVE_TIMEOUT" podman save -o "$tar" "$ref"
  if $supports_sbom_input; then
    echo "    [SBOM] ${ref} (archive, $SBOM_FORMAT via 'trivy sbom --input')"
    run_with_timeout "$EXTERNAL_TIMEOUT" trivy sbom "${SBOM_FLAGS_COMMON[@]}" --input "$tar" -o "$out"
  else
    echo "    [SBOM] ${ref} (archive, $SBOM_FORMAT via 'trivy image --format ...')"
    if trivy image --help 2>/dev/null | grep -q -- '--input'; then
      run_with_timeout "$EXTERNAL_TIMEOUT" trivy image "${SBOM_IMAGE_BY_ARCHIVE[@]}" --input "$tar" -o "$out"
    else
      run_with_timeout "$EXTERNAL_TIMEOUT" trivy image "${SBOM_IMAGE_BY_ARCHIVE[@]}" --file "$tar" -o "$out"
    fi
  fi
  echo "    [CLEAN] ${tar}"
  rm -f "$tar"
}

# --- Main loop ---
if [[ "$ONLY_TAGGED" == "true" ]]; then
  for NAME in "${IMAGE_NAMES[@]}"; do
    if [[ "$USE_ARCHIVE_FALLBACK" == "true" ]]; then
      { scan_vuln_by_archive_ref "$NAME" || echo "    ! Scan failed for $NAME"; }
      { sbom_by_archive_ref "$NAME" || echo "    ! SBOM failed for $NAME"; }
    else
      { scan_vuln_by_name "$NAME" || echo "    ! Scan failed for $NAME"; }
      { sbom_by_name "$NAME" || echo "    ! SBOM failed for $NAME"; }
    fi
  done
else
  while IFS= read -r LINE; do
    NAME="$(awk '{print $1}' <<<"$LINE")"
    ID="$(awk '{print $2}' <<<"$LINE")"
    REF="$([[ "$NAME" == "<none>:<none>" || -z "$NAME" ]] && echo "$ID" || echo "$NAME")"
    if [[ "$USE_ARCHIVE_FALLBACK" == "true" ]]; then
      { scan_vuln_by_archive_ref "$REF" || echo "    ! Scan failed for $REF"; }
      { sbom_by_archive_ref "$REF" || echo "    ! SBOM failed for $REF"; }
    else
      { scan_vuln_by_name "$REF" || echo "    ! Scan failed for $REF"; }
      { sbom_by_name "$REF" || echo "    ! SBOM failed for $REF"; }
    fi
  done <<<"$(printf '%s\n' "${IMAGE_NAMES[@]}")"
fi

echo "[*] Done."
echo "[*] Vulnerability reports: $REPORT_DIR"
echo "[*] SBOMs:                 $SBOM_DIR"
