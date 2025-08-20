# #!/usr/bin/env bash
# set -euo pipefail

# # ================================
# # Offline Trivy Bulk Scanner (Podman)
# # ================================
# # Requires: podman, trivy
# # Assumes: ~/.cache/trivy/db/{trivy.db,metadata.json} already present
# # Output:  ./trivy-reports-YYYYmmdd-HHMMSS/*.json
# # Env you can override:
# #   SEVERITY="HIGH,CRITICAL"          # e.g. "LOW,MEDIUM,HIGH,CRITICAL"
# #   CACHE_DIR="$HOME/.cache/trivy"
# #   ONLY_TAGGED="true"                # skip <none>:<none>
# #   TRIVY_PKG_TYPES="os"              # optional: limit to OS packages
# #   TRIVY_SCANNERS="vuln"             # optional: disable secret/config scans if you want
# # ================================

# SEVERITY="${SEVERITY:-HIGH,CRITICAL}"
# CACHE_DIR="${CACHE_DIR:-$HOME/.cache/trivy}"
# ONLY_TAGGED="${ONLY_TAGGED:-true}"

# # --- sanity checks ---
# command -v podman >/dev/null || { echo "podman not found"; exit 1; }
# command -v trivy  >/dev/null || { echo "trivy not found";  exit 1; }
# [[ -f "$CACHE_DIR/db/trivy.db" && -f "$CACHE_DIR/db/metadata.json" ]] || {
#   echo "Trivy offline DB not found in $CACHE_DIR/db (need trivy.db and metadata.json)"; exit 1;
# }

# timestamp="$(date +%Y%m%d-%H%M%S)"
# REPORT_DIR="$(pwd)/trivy-reports-$timestamp"
# mkdir -p "$REPORT_DIR"

# # Common Trivy flags
# TRIVY_FLAGS=(
#   --skip-db-update
#   --offline-scan
#   --image-src podman
#   --cache-dir "$CACHE_DIR"
#   --severity "$SEVERITY"
#   --format json
# )
# # Optional tuning from env (don’t add if not set)
# [[ -n "${TRIVY_PKG_TYPES:-}" ]] && TRIVY_FLAGS+=( --pkg-types "$TRIVY_PKG_TYPES" )
# [[ -n "${TRIVY_SCANNERS:-}"  ]] && TRIVY_FLAGS+=( --scanners "$TRIVY_SCANNERS" )

# echo "[*] Listing local Podman images..."

# if [[ "$ONLY_TAGGED" == "true" ]]; then
#   # unique list of repo:tag (skip <none>:<none>)
#   mapfile -t IMAGE_NAMES < <(
#     podman images --format '{{.Repository}}:{{.Tag}}' \
#     | grep -v '^<none>:<none>$' | sort -u
#   )
# else
#   # include untagged; keep a pair "name id" per line
#   mapfile -t IMAGE_NAMES < <(podman images --format '{{.Repository}}:{{.Tag}} {{.ID}}' | sort -u)
# fi

# if [[ "$ONLY_TAGGED" == "true" && ${#IMAGE_NAMES[@]} -eq 0 ]]; then
#   echo "No tagged images found. Tag images (e.g., 'podman tag <ID> localhost/myimg:v1') or set ONLY_TAGGED=false."
#   exit 0
# fi

# sanitize() { echo "$1" | tr '/:@' '_' ; }

# echo "[*] Found ${#IMAGE_NAMES[@]} images. Scanning with Trivy (offline)..."

# if [[ "$ONLY_TAGGED" == "true" ]]; then
#   # Scan by NAME (repo:tag), name files by NAME
#   for NAME in "${IMAGE_NAMES[@]}"; do
#     SAFE_NAME="$(sanitize "$NAME")"
#     OUT_JSON="$REPORT_DIR/${SAFE_NAME}.json"
#     echo "  - Scanning ${NAME} ..."
#     trivy image "${TRIVY_FLAGS[@]}" -o "$OUT_JSON" "$NAME" \
#       || echo "    ! Scan failed for $NAME (continuing)"
#   done
# else
#   # Include untagged: prefer name; if <none>:<none>, use ID
#   while IFS= read -r LINE; do
#     NAME="$(awk '{print $1}' <<<"$LINE")"
#     ID="$(awk '{print $2}' <<<"$LINE")"
#     if [[ "$NAME" == "<none>:<none>" || -z "$NAME" ]]; then
#       SCAN_REF="$ID"
#       SAFE_NAME="$(sanitize "$ID")"
#     else
#       SCAN_REF="$NAME"
#       SAFE_NAME="$(sanitize "$NAME")"
#     fi
#     OUT_JSON="$REPORT_DIR/${SAFE_NAME}.json"
#     echo "  - Scanning ${SCAN_REF} ..."
#     trivy image "${TRIVY_FLAGS[@]}" -o "$OUT_JSON" "$SCAN_REF" \
#       || echo "    ! Scan failed for $SCAN_REF (continuing)"
#   done <<<"$(printf '%s\n' "${IMAGE_NAMES[@]}")"
# fi

# echo "[*] Done. Reports saved to: $REPORT_DIR"
# echo "[*] Example: jq '.Results[] | {Target, Vulnerabilities}' '$REPORT_DIR/some-image.json' | less"

#!/usr/bin/env bash
set -euo pipefail

# ============================================
# Offline Trivy Bulk Scanner (Podman)
# ============================================
# Requires: podman, trivy
# Assumes: ~/.cache/trivy/db/{trivy.db,metadata.json} already present
# Output:  <WORKDIR>/trivy-reports-YYYYmmdd-HHMMSS/*.json
#
# Env you can override:
#   SEVERITY="HIGH,CRITICAL"          # e.g. "LOW,MEDIUM,HIGH,CRITICAL"
#   CACHE_DIR="$HOME/.cache/trivy"
#   ONLY_TAGGED="true"                # skip <none>:<none>
#   TRIVY_PKG_TYPES="os"              # optional: limit to OS packages
#   TRIVY_SCANNERS="vuln"             # optional: disable secret/config scans if you want
#   EXPORT_ROOT=""                    # optional: if set, also mirror to $EXPORT_ROOT/<host>/<dated_run>/
# ============================================

SEVERITY="${SEVERITY:-HIGH,CRITICAL}"
CACHE_DIR="${CACHE_DIR:-$HOME/.cache/trivy}"
ONLY_TAGGED="${ONLY_TAGGED:-true}"
EXPORT_ROOT="${EXPORT_ROOT:-}"

# --- sanity checks ---
command -v podman >/dev/null || { echo "podman not found"; exit 1; }
command -v trivy  >/dev/null || { echo "trivy not found";  exit 1; }
[[ -f "$CACHE_DIR/db/trivy.db" && -f "$CACHE_DIR/db/metadata.json" ]] || {
  echo "Trivy offline DB not found in $CACHE_DIR/db (need trivy.db and metadata.json)"; exit 1;
}

# Host label (for metadata / optional export tree)
HOST_LABEL="$(hostname -f 2>/dev/null || hostname)"

timestamp="$(date +%Y%m%d-%H%M%S)"
WORKDIR="$(pwd)"
REPORT_DIR="${WORKDIR}/trivy-reports-${timestamp}"
mkdir -p "$REPORT_DIR"

# Keep a 'latest' symlink for convenience on the scanner host
ln -sfn "$REPORT_DIR" "${WORKDIR}/latest"

# Common Trivy flags
TRIVY_FLAGS=(
  --skip-db-update
  --offline-scan
  --image-src podman
  --cache-dir "$CACHE_DIR"
  --severity "$SEVERITY"
  --format json
)
# Optional tuning from env
[[ -n "${TRIVY_PKG_TYPES:-}" ]] && TRIVY_FLAGS+=( --pkg-types "$TRIVY_PKG_TYPES" )
[[ -n "${TRIVY_SCANNERS:-}"  ]] && TRIVY_FLAGS+=( --scanners "$TRIVY_SCANNERS" )

echo "[*] Host: ${HOST_LABEL}"
echo "[*] Listing local Podman images..."

if [[ "$ONLY_TAGGED" == "true" ]]; then
  # unique list of repo:tag (skip <none>:<none>)
  mapfile -t IMAGE_NAMES < <(
    podman images --format '{{.Repository}}:{{.Tag}}' \
    | grep -v '^<none>:<none>$' | sort -u
  )
else
  # include untagged; keep a pair "name id" per line
  mapfile -t IMAGE_NAMES < <(podman images --format '{{.Repository}}:{{.Tag}} {{.ID}}' | sort -u)
fi

if [[ "$ONLY_TAGGED" == "true" && ${#IMAGE_NAMES[@]} -eq 0 ]]; then
  echo "No tagged images found. Tag images (e.g., 'podman tag <ID> localhost/myimg:v1') or set ONLY_TAGGED=false."
  exit 0
fi

sanitize() { echo "$1" | tr '/:@' '_' ; }

echo "[*] Found ${#IMAGE_NAMES[@]} images. Scanning with Trivy (offline)..."

# Track what we actually scanned for metadata
SCANNED=()

if [[ "$ONLY_TAGGED" == "true" ]]; then
  # Scan by NAME (repo:tag), name files by NAME
  for NAME in "${IMAGE_NAMES[@]}"; do
    SAFE_NAME="$(sanitize "$NAME")"
    OUT_JSON="$REPORT_DIR/${SAFE_NAME}.json"
    echo "  - Scanning ${NAME} ..."
    if trivy image "${TRIVY_FLAGS[@]}" -o "$OUT_JSON" "$NAME"; then
      SCANNED+=("$NAME")
    else
      echo "    ! Scan failed for $NAME (continuing)"
    fi
  done
else
  # Include untagged: prefer name; if <none>:<none>, use ID
  while IFS= read -r LINE; do
    NAME="$(awk '{print $1}' <<<"$LINE")"
    ID="$(awk '{print $2}' <<<"$LINE")"
    if [[ "$NAME" == "<none>:<none>" || -z "$NAME" ]]; then
      SCAN_REF="$ID"
      SAFE_NAME="$(sanitize "$ID")"
    else
      SCAN_REF="$NAME"
      SAFE_NAME="$(sanitize "$NAME")"
    fi
    OUT_JSON="$REPORT_DIR/${SAFE_NAME}.json"
    echo "  - Scanning ${SCAN_REF} ..."
    if trivy image "${TRIVY_FLAGS[@]}" -o "$OUT_JSON" "$SCAN_REF"; then
      SCANNED+=("$SCAN_REF")
    else
      echo "    ! Scan failed for $SCAN_REF (continuing)"
    fi
  done <<<"$(printf '%s\n' "${IMAGE_NAMES[@]}")"
fi

# ---- Metadata for the run (host + timestamp + images) ----
{
  echo '{'
  echo "  \"host\": \"${HOST_LABEL}\","
  echo "  \"timestamp\": \"${timestamp}\","
  echo '  "images": ['
  for i in "${!SCANNED[@]}"; do
    sep=$([[ $i -lt $((${#SCANNED[@]}-1)) ]] && echo "," || echo "")
    printf '    "%s"%s\n' "${SCANNED[$i]}" "$sep"
  done
  echo '  ]'
  echo '}'
} > "${REPORT_DIR}/run.meta.json"

# Also drop a simple host marker (handy for quick checks)
echo "${HOST_LABEL}" > "${REPORT_DIR}/HOST.txt"

# ---- Optional: mirror into EXPORT_ROOT/<host>/<dated_run>/ ----
if [[ -n "$EXPORT_ROOT" ]]; then
  DEST="${EXPORT_ROOT}/${HOST_LABEL}/$(basename "$REPORT_DIR")"
  mkdir -p "$DEST"
  cp -a "${REPORT_DIR}/." "$DEST/"
  echo "[*] Mirrored to: $DEST"
fi

# ---- Archive the run so you can fetch one dated file if needed ----
tar -C "${WORKDIR}" -czf "${REPORT_DIR}.tar.gz" "$(basename "$REPORT_DIR")"
echo "[*] Archive created: ${REPORT_DIR}.tar.gz"

echo "[*] Done. Reports saved to: ${REPORT_DIR}"
echo "[*] Example: jq '.Results[] | {Target, Vulnerabilities}' '${REPORT_DIR}/some-image.json' | less"
