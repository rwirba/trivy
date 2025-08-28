#!/usr/bin/env bash
set -euo pipefail

# ============================================
# Offline Trivy Bulk Scanner (Podman) with archive fallback + timeouts
# ============================================
# Requires: podman, trivy, (optional) coreutils 'timeout'
# Assumes: ~/.cache/trivy/db/{trivy.db,metadata.json} already present
# Output:  ./trivy-reports-YYYYmmdd-HHMMSS/*.json
#
# Env you can override:
#   SEVERITY="HIGH,CRITICAL"          # e.g. "LOW,MEDIUM,HIGH,CRITICAL"
#   CACHE_DIR="$HOME/.cache/trivy"
#   ONLY_TAGGED="true"                # skip <none>:<none>
#   TRIVY_PKG_TYPES="os"              # e.g. "os,library" (default empty = Trivy default)
#   TRIVY_SCANNERS="vuln"             # e.g. "vuln,secret,config" (default empty = Trivy default)
#   FORCE_ARCHIVE="true"              # **default true** -> use podman save + trivy --input
#   SAVE_TIMEOUT="120s"               # timeout for 'podman save' each image
#   TRIVY_TIMEOUT="10m"               # Trivy's internal --timeout (per image)
#   EXTERNAL_TIMEOUT=""               # optional outer 'timeout' wrapper per scan, e.g. "12m"
# ============================================

SEVERITY="${SEVERITY:-}"
CACHE_DIR="${CACHE_DIR:-$HOME/.cache/trivy}"
ONLY_TAGGED="${ONLY_TAGGED:-true}"
FORCE_ARCHIVE="${FORCE_ARCHIVE:-true}"     # default to archive mode for reliability
SAVE_TIMEOUT="${SAVE_TIMEOUT:-120s}"
TRIVY_TIMEOUT="${TRIVY_TIMEOUT:-10m}"
EXTERNAL_TIMEOUT="${EXTERNAL_TIMEOUT:-}"   # empty = no outer wrapper

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

timestamp="$(date +%Y%m%d-%H%M%S)"
WORKDIR="$(pwd)"
REPORT_DIR="${WORKDIR}/trivy-reports-${timestamp}"
mkdir -p "$REPORT_DIR"

# Common Trivy flags
TRIVY_FLAGS_COMMON=(
  --skip-db-update
  --offline-scan
  --cache-dir "$CACHE_DIR"
  --format json
  --timeout "$TRIVY_TIMEOUT"
)
# Optional tuning from env 
[[ -n "$SEVERITY"        ]] && TRIVY_FLAGS_COMMON+=( --severity "$SEVERITY" )
[[ -n "${TRIVY_PKG_TYPES:-}" ]] && TRIVY_FLAGS_COMMON+=( --pkg-types "$TRIVY_PKG_TYPES" )
[[ -n "${TRIVY_SCANNERS:-}"  ]] && TRIVY_FLAGS_COMMON+=( --scanners "$TRIVY_SCANNERS" )

# Two modes:
TRIVY_FLAGS_BY_NAME=("${TRIVY_FLAGS_COMMON[@]}" --image-src podman)
TRIVY_FLAGS_BY_ARCHIVE=("${TRIVY_FLAGS_COMMON[@]}")  # --image-src not needed for --input

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

# --- Image discovery (works without socket) ---
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
  echo "No tagged images found. Tag images (e.g., 'podman tag <ID> localhost/myimg:v1') or set ONLY_TAGGED=false."
  exit 0
fi

sanitize() { echo "$1" | tr '/:@' '_' ; }

echo "[*] Found ${#IMAGE_NAMES[@]} images."
if [[ "$USE_ARCHIVE_FALLBACK" == "true" ]]; then
  echo "[*] Using ARCHIVE mode (podman save → trivy --input)."
else
  echo "[*] Using API mode (scan by image name via Podman socket)."
fi

# --- helpers for timeouts ---
run_with_timeout() {
  # $1: timeout_duration (may be empty), remaining args: command...
  local dur="$1"; shift || true
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

# --- Scan functions ---
scan_by_name() {
  local name="$1" safe out
  safe="$(sanitize "$name")"
  out="$REPORT_DIR/${safe}.json"
  echo "  - Scanning ${name} (API) ..."
  if ! run_with_timeout "$EXTERNAL_TIMEOUT" trivy image "${TRIVY_FLAGS_BY_NAME[@]}" -o "$out" "$name"; then
    echo "    ! Scan timed out/failed for $name (continuing)"
    return 1
  fi
}

scan_by_archive_name() {
  local name="$1" safe tar out
  safe="$(sanitize "$name")"
  tar="$TMPDIR/${safe}.tar"
  out="$REPORT_DIR/${safe}.json"
  echo "  - Saving ${name} → ${tar}"
  if ! run_with_timeout "$SAVE_TIMEOUT" podman save -o "$tar" "$name"; then
    echo "    ! podman save timed out/failed for $name (skipping)"
    return 1
  fi
  echo "    Scanning ${name} (archive) ..."
  if ! run_with_timeout "$EXTERNAL_TIMEOUT" trivy image "${TRIVY_FLAGS_BY_ARCHIVE[@]}" --input "$tar" -o "$out"; then
    echo "    ! Scan timed out/failed for $name (continuing)"
    rm -f "$tar"
    return 1
  fi
  rm -f "$tar"
}

scan_by_archive_id_or_name() {
  local nm="$1" id="$2" ref safe tar out
  if [[ "$nm" == "<none>:<none>" || -z "$nm" ]]; then
    ref="$id"; safe="$(sanitize "$id")"
  else
    ref="$nm"; safe="$(sanitize "$nm")"
  fi
  tar="$TMPDIR/${safe}.tar"
  out="$REPORT_DIR/${safe}.json"
  echo "  - Saving ${ref} → ${tar}"
  if ! run_with_timeout "$SAVE_TIMEOUT" podman save -o "$tar" "$ref"; then
    echo "    ! podman save timed out/failed for $ref (skipping)"
    return 1
  fi
  echo "    Scanning ${ref} (archive) ..."
  if ! run_with_timeout "$EXTERNAL_TIMEOUT" trivy image "${TRIVY_FLAGS_BY_ARCHIVE[@]}" --input "$tar" -o "$out"; then
    echo "    ! Scan timed out/failed for $ref (continuing)"
    rm -f "$tar"
    return 1
  fi
  rm -f "$tar"
}

# --- Main loop ---
if [[ "$ONLY_TAGGED" == "true" ]]; then
  for NAME in "${IMAGE_NAMES[@]}"; do
    if [[ "$USE_ARCHIVE_FALLBACK" == "true" ]]; then
      scan_by_archive_name "$NAME" || true
    else
      scan_by_name "$NAME" || true
    fi
  done
else
  while IFS= read -r LINE; do
    NAME="$(awk '{print $1}' <<<"$LINE")"
    ID="$(awk '{print $2}' <<<"$LINE")"
    if [[ "$USE_ARCHIVE_FALLBACK" == "true" ]]; then
      scan_by_archive_id_or_name "$NAME" "$ID" || true
    else
      # prefer name if available, else ID
      if [[ "$NAME" == "<none>:<none>" || -z "$NAME" ]]; then
        scan_by_name "$ID" || true
      else
        scan_by_name "$NAME" || true
      fi
    fi
  done <<<"$(printf '%s\n' "${IMAGE_NAMES[@]}")"
fi

echo "[*] Done. Reports saved to: $REPORT_DIR"
echo "[*] Example: jq '.Results[] | {Target, Vulnerabilities}' '$REPORT_DIR/some-image.json' | less"
