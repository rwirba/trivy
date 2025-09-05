#!/usr/bin/env bash
set -euo pipefail

# ============================================
# Offline Trivy Bulk Scanner (Podman) + SBOMs
# ============================================
# Requires: podman, trivy, (optional) coreutils 'timeout'
# Assumes: ~/.cache/trivy/db/{trivy.db,metadata.json} already present
#
# Local Output (per run):
#   ./trivy-reports-YYYYmmdd-HHMMSS/*.json   (vulnerability scan results)
#   ./sboms-YYYYmmdd-HHMMSS/*.json           (SBOMs per image)
#
# Also copies the same to destination tree:
#   /srv/trivy/reports/<SERVER_NAME>/trivy-reports-YYYYmmdd-HHMMSS/<image>.json
#   /srv/trivy/reports/<SERVER_NAME>/sboms-YYYYmmdd-HHMMSS/<image>-sbom.json
#
# ---- Tunables (env) ----
#   SERVER_NAME="server1"            # subfolder name under DEST_BASE
#   DEST_BASE="/srv/trivy/reports"   # where to mirror/copy reports
#
#   SEVERITY=""                      # empty => include ALL severities
#   CACHE_DIR="$HOME/.cache/trivy"
#   ONLY_TAGGED="true"               # skip <none>:<none>
#   TRIVY_PKG_TYPES="os,library"     # scan both OS & app deps
#   TRIVY_SCANNERS="vuln"            # add "secret,config" if desired
#   FORCE_ARCHIVE="true"             # default reliable archive mode
#   SAVE_TIMEOUT="120s"              # timeout for 'podman save'
#   TRIVY_TIMEOUT="10m"              # Trivy's internal timeout per image
#   EXTERNAL_TIMEOUT=""              # outer timeout per scan, e.g. "12m"
#   GENERATE_SBOM="true"             # generate SBOMs per image
#   SBOM_FORMAT="cyclonedx"          # "cyclonedx" or "spdx-json"
# ============================================

SERVER_NAME="${SERVER_NAME:-server1}"
DEST_BASE="${DEST_BASE:-/srv/trivy/reports}"

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

# --- Step 1: Extract offline DB if tarball exists ---
DB_TARBALL=$(ls -1 trivy-offline.db-*.tgz 2>/dev/null | sort -r | head -n1 || true)
if [[ -n "$DB_TARBALL" ]]; then
  echo "[*] Found DB tarball: $DB_TARBALL"
  mkdir -p "$CACHE_DIR/db"
  echo "    Cleaning old DB files..."
  rm -f "$CACHE_DIR/db/trivy.db" "$CACHE_DIR/db/metadata.json"
  echo "    Extracting into $CACHE_DIR/db"
  tar -xzf "$DB_TARBALL" -C "$CACHE_DIR"
else
  echo "[!] No trivy-offline.db-*.tgz found in $(pwd). Assuming DB already exists in $CACHE_DIR/db."
fi

# --- Step 2: Verify DB is present ---
if [[ ! -f "$CACHE_DIR/db/trivy.db" || ! -f "$CACHE_DIR/db/metadata.json" ]]; then
  echo "[ERROR] Trivy offline DB not found in $CACHE_DIR/db (need trivy.db and metadata.json)."
  exit 1
fi

echo "[*] Using offline DB from $CACHE_DIR/db"
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
TRIVY_VER="$(awk -F': ' '/Version:/{print $2}' <<<"$TRIVY_VER_RAW" | tr -d '\r')"
TRIVY_MAJOR="$(cut -d. -f1 <<<"${TRIVY_VER#v}")"
TRIVY_MINOR="$(cut -d. -f2 <<<"${TRIVY_VER#v}")"
supports_sbom_input=false   # trivy sbom --input is >= 0.62.0
if [[ -n "$TRIVY_VER" ]]; then
  if (( TRIVY_MAJOR > 0 )) || (( TRIVY_MAJOR == 0 && TRIVY_MINOR >= 62 )); then
    supports_sbom_input=true
  fi
fi
echo "[*] Trivy detected: ${TRIVY_VER:-unknown} (sbom --input supported: $supports_sbom_input)"

timestamp="$(date +%Y%m%d)"
WORKDIR="$(pwd)"
REPORT_DIR="${WORKDIR}/trivy-reports-${timestamp}"
SBOM_DIR="${WORKDIR}/sboms-${timestamp}"
mkdir -p "$REPORT_DIR" "$SBOM_DIR"

# Destination (mirrored)
DEST_TRIVY_DIR="${DEST_BASE}/${SERVER_NAME}/trivy-reports-${timestamp}"
DEST_SBOM_DIR="${DEST_BASE}/${SERVER_NAME}/sboms-${timestamp}"
mkdir -p "$DEST_TRIVY_DIR"
[[ "$GENERATE_SBOM" == "true" ]] && mkdir -p "$DEST_SBOM_DIR"

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

# SBOM flags
SBOM_FLAGS_COMMON=(
  --skip-db-update
  --offline-scan
  --cache-dir "$CACHE_DIR"
  --timeout "$TRIVY_TIMEOUT"
  --format "$SBOM_FORMAT"
)
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

# --- helpers ---
sanitize_for_file() { tr -c 'A-Za-z0-9._-@:' '_' <<<"$1"; }

# Build a clean, user-friendly base filename from an image ref:
#   - Last path segment of repository (e.g., "nginx" from "docker.io/library/nginx")
#   - Append "-<tag>" if tag exists and is not "latest"
#   - If ref looks like a digest only, reduce to simple safe string
base_from_ref() {
  local ref="$1" last tag repo part
  # strip any @digest first for naming
  local no_digest="${ref%@*}"
  # last path segment
  last="${no_digest##*/}"         # e.g., "nginx:1.25" or "ubi9"
  # if still empty (weird), fallback to whole ref
  [[ -z "$last" ]] && last="$no_digest"
  # separate tag if present
  if [[ "$last" == *:* ]]; then
    repo="${last%%:*}"
    tag="${last##*:}"
    if [[ -n "$tag" && "$tag" != "latest" ]]; then
      part="${repo}-${tag}"
    else
      part="${repo}"
    fi
  else
    part="$last"
  fi
  # sanitize to safe filename (keep dots/dashes/underscores)
  part="$(tr -c 'A-Za-z0-9._-+' '_' <<<"$part")"
  echo "$part"
}

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
  local ref="$1" base out
  base="$(base_from_ref "$ref")"
  out="$REPORT_DIR/${base}.json"
  echo "  - [SCAN] ${ref} (API) → $(basename "$out")"
  run_with_timeout "$EXTERNAL_TIMEOUT" trivy image "${TRIVY_FLAGS_BY_NAME[@]}" -o "$out" "$ref"
  # mirror copy
  cp -f "$out" "${DEST_TRIVY_DIR}/${base}.json"
}

scan_vuln_by_archive_ref() {
  local ref="$1" base tar out
  base="$(base_from_ref "$ref")"
  tar="$TMPDIR/${base}.tar"
  out="$REPORT_DIR/${base}.json"
  echo "  - [SAVE] ${ref} → ${tar}"
  run_with_timeout "$SAVE_TIMEOUT" podman save -o "$tar" "$ref"
  echo "    [SCAN] ${ref} (archive) → $(basename "$out")"
  if trivy image --help 2>/dev/null | grep -q -- '--input'; then
    run_with_timeout "$EXTERNAL_TIMEOUT" trivy image "${TRIVY_FLAGS_BY_ARCHIVE[@]}" --input "$tar" -o "$out"
  else
    run_with_timeout "$EXTERNAL_TIMEOUT" trivy image "${TRIVY_FLAGS_BY_ARCHIVE[@]}" --file "$tar"  -o "$out"
  fi
  rm -f "$tar"
  # mirror copy
  cp -f "$out" "${DEST_TRIVY_DIR}/${base}.json"
}

sbom_by_name() {
  local ref="$1" base out
  [[ "$GENERATE_SBOM" == "true" ]] || return 0
  base="$(base_from_ref "$ref")"
  out="$SBOM_DIR/${base}-sbom.json"
  if $supports_sbom_input; then
    echo "    [SBOM] ${ref} (API, $SBOM_FORMAT via 'trivy sbom') → $(basename "$out")"
    run_with_timeout "$EXTERNAL_TIMEOUT" trivy sbom "${SBOM_FLAGS_COMMON[@]}" --image-src podman -o "$out" "$ref"
  else
    echo "    [SBOM] ${ref} (API, $SBOM_FORMAT via 'trivy image') → $(basename "$out")"
    run_with_timeout "$EXTERNAL_TIMEOUT" trivy image "${SBOM_IMAGE_BY_NAME[@]}" -o "$out" "$ref"
  fi
  # mirror copy
  cp -f "$out" "${DEST_SBOM_DIR}/${base}-sbom.json"
}

sbom_by_archive_ref() {
  local ref="$1" base tar out
  [[ "$GENERATE_SBOM" == "true" ]] || return 0
  base="$(base_from_ref "$ref")"
  tar="$TMPDIR/${base}.tar"
  out="$SBOM_DIR/${base}-sbom.json"
  echo "  - [SAVE] ${ref} → ${tar} (for SBOM)"
  run_with_timeout "$SAVE_TIMEOUT" podman save -o "$tar" "$ref"
  if $supports_sbom_input; then
    echo "    [SBOM] ${ref} (archive, $SBOM_FORMAT via 'trivy sbom --input') → $(basename "$out")"
    run_with_timeout "$EXTERNAL_TIMEOUT" trivy sbom "${SBOM_FLAGS_COMMON[@]}" --input "$tar" -o "$out"
  else
    echo "    [SBOM] ${ref} (archive, $SBOM_FORMAT via 'trivy image --format ...') → $(basename "$out")"
    if trivy image --help 2>/dev/null | grep -q -- '--input'; then
      run_with_timeout "$EXTERNAL_TIMEOUT" trivy image "${SBOM_IMAGE_BY_ARCHIVE[@]}" --input "$tar" -o "$out"
    else
      run_with_timeout "$EXTERNAL_TIMEOUT" trivy image "${SBOM_IMAGE_BY_ARCHIVE[@]}" --file  "$tar" -o "$out"
    fi
  fi
  rm -f "$tar"
  # mirror copy
  cp -f "$out" "${DEST_SBOM_DIR}/${base}-sbom.json"
}

# --- Main loop ---
echo "[*] Found ${#IMAGE_NAMES[@]} images."
echo "[*] Mode: $([[ "$USE_ARCHIVE_FALLBACK" == "true" ]] && echo ARCHIVE || echo API)"
echo "[*] Local output:    $REPORT_DIR , $SBOM_DIR"
echo "[*] Mirrored output: ${DEST_TRIVY_DIR} , ${DEST_SBOM_DIR}"

if [[ "$ONLY_TAGGED" == "true" ]]; then
  for NAME in "${IMAGE_NAMES[@]}"; do
    if [[ "$USE_ARCHIVE_FALLBACK" == "true" ]]; then
      { scan_vuln_by_archive_ref "$NAME" || echo "    ! Scan failed for $NAME"; }
      { sbom_by_archive_ref "$NAME"      || echo "    ! SBOM failed for $NAME"; }
    else
      { scan_vuln_by_name "$NAME" || echo "    ! Scan failed for $NAME"; }
      { sbom_by_name "$NAME"      || echo "    ! SBOM failed for $NAME"; }
    fi
  done
else
  while IFS= read -r LINE; do
    NAME="$(awk '{print $1}' <<<"$LINE")"
    ID="$(awk '{print $2}' <<<"$LINE")"
    REF="$([[ "$NAME" == "<none>:<none>" || -z "$NAME" ]] && echo "$ID" || echo "$NAME")"
    if [[ "$USE_ARCHIVE_FALLBACK" == "true" ]]; then
      { scan_vuln_by_archive_ref "$REF" || echo "    ! Scan failed for $REF"; }
      { sbom_by_archive_ref "$REF"      || echo "    ! SBOM failed for $REF"; }
    else
      { scan_vuln_by_name "$REF" || echo "    ! Scan failed for $REF"; }
      { sbom_by_name "$REF"      || echo "    ! SBOM failed for $REF"; }
    fi
  done <<<"$(printf '%s\n' "${IMAGE_NAMES[@]}")"
fi

echo
echo "[*] Done."
echo "    Vulnerability reports (local): $REPORT_DIR"
echo "    SBOMs (local):                 $SBOM_DIR"
echo "    Vulnerability reports (dst):   $DEST_TRIVY_DIR"
[[ "$GENERATE_SBOM" == "true" ]] && echo "    SBOMs (dst):                   $DEST_SBOM_DIR"
