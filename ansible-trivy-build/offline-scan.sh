# #!/usr/bin/env bash
# set -euo pipefail

# # ================================
# # Offline Trivy Bulk Scanner (Podman)
# # ================================
# # Requires: podman, trivy
# # Assumes: ~/.cache/trivy/db/{trivy.db,metadata.json} already present
# # Output:  ./trivy-reports-YYYYmmdd-HHMMSS/*.json
# # Env vars you can override:
# #   SEVERITY="HIGH,CRITICAL"   # e.g., "LOW,MEDIUM,HIGH,CRITICAL"
# #   CACHE_DIR="$HOME/.cache/trivy"
# # ================================

# SEVERITY="${SEVERITY:-HIGH,CRITICAL}"
# CACHE_DIR="${CACHE_DIR:-$HOME/.cache/trivy}"

# # --- sanity checks ---
# command -v podman >/dev/null || { echo "podman not found"; exit 1; }
# command -v trivy  >/dev/null || { echo "trivy not found";  exit 1; }
# [[ -f "$CACHE_DIR/db/trivy.db" && -f "$CACHE_DIR/db/metadata.json" ]] || {
#   echo "Trivy offline DB not found in $CACHE_DIR/db (need trivy.db and metadata.json)"; exit 1;
# }

# timestamp="$(date +%Y%m%d-%H%M%S)"
# REPORT_DIR="$(pwd)/trivy-reports-$timestamp"
# mkdir -p "$REPORT_DIR"

# echo "[*] Listing local Podman images..."
# # Collect unique image IDs (avoid duplicates when multiple tags point to same image)
# mapfile -t IMAGE_IDS < <(podman images --format "{{.ID}}" | sort -u)

# if [[ ${#IMAGE_IDS[@]} -eq 0 ]]; then
#   echo "No local images found."
#   exit 0
# fi

# echo "[*] Found ${#IMAGE_IDS[@]} images. Scanning with Trivy (offline)..."
# for IMG_ID in "${IMAGE_IDS[@]}"; do
#   # Build a friendly name from first tag (if any), else use ID
#   TAGS=$(podman images --format "{{.Repository}}:{{.Tag}} {{.ID}}" | awk -v id="$IMG_ID" '$2==id {print $1}')
#   if [[ -n "$TAGS" && "$TAGS" != "<none>:<none>" ]]; then
#     NAME="$(echo "$TAGS" | head -n1)"
#     SAFE_NAME="$(echo "$NAME" | tr '/:@' '_')"
#   else
#     SAFE_NAME="${IMG_ID}"
#   fi

#   OUT_JSON="$REPORT_DIR/${SAFE_NAME}.json"
#   echo "  - Scanning $IMG_ID (${SAFE_NAME}) ..."
#   trivy image \
#     --skip-update \
#     --cache-dir "$CACHE_DIR" \
#     --severity "$SEVERITY" \
#     --format json \
#     -o "$OUT_JSON" \
#     "$IMG_ID" || echo "    ! Scan failed for $IMG_ID (continuing)"
# done

# echo "[*] Done. Reports saved to: $REPORT_DIR"
# echo "[*] Example: jq '.Results[] | {Target, Vulnerabilities}' '$REPORT_DIR/some-image.json' | less"

#!/usr/bin/env bash
set -euo pipefail

# ================================
# Offline Trivy Bulk Scanner (Podman)
# ================================
# Requires: podman, trivy
# Assumes: ~/.cache/trivy/db/{trivy.db,metadata.json} already present
# Output:  ./trivy-reports-YYYYmmdd-HHMMSS/*.json
# Env vars you can override:
#   SEVERITY="HIGH,CRITICAL"   # e.g., "LOW,MEDIUM,HIGH,CRITICAL"
#   CACHE_DIR="$HOME/.cache/trivy"
#   ONLY_TAGGED=true           # skip untagged images (<none>:<none>)
# ================================

SEVERITY="${SEVERITY:-HIGH,CRITICAL}"
CACHE_DIR="${CACHE_DIR:-$HOME/.cache/trivy}"
ONLY_TAGGED="${ONLY_TAGGED:-true}"

# --- sanity checks ---
command -v podman >/dev/null || { echo "podman not found"; exit 1; }
command -v trivy  >/dev/null || { echo "trivy not found";  exit 1; }
[[ -f "$CACHE_DIR/db/trivy.db" && -f "$CACHE_DIR/db/metadata.json" ]] || {
  echo "Trivy offline DB not found in $CACHE_DIR/db (need trivy.db and metadata.json)"; exit 1;
}

timestamp="$(date +%Y%m%d-%H%M%S)"
REPORT_DIR="$(pwd)/trivy-reports-$timestamp"
mkdir -p "$REPORT_DIR"

echo "[*] Listing local Podman images..."

# Build a unique list of TAGGED names (repo:tag). Skip <none>:<none>.
# If you want to include untagged images, set ONLY_TAGGED=false and we’ll
# fall back to scanning by ID (filenames would then show the ID).
if [[ "$ONLY_TAGGED" == "true" ]]; then
  mapfile -t IMAGE_NAMES < <(
    podman images --format '{{.Repository}}:{{.Tag}}' \
    | grep -v '^<none>:<none>$' \
    | sort -u
  )
else
  # Include everything by name; if name is <none>:<none>, later we’ll fill by ID.
  mapfile -t IMAGE_NAMES < <(podman images --format '{{.Repository}}:{{.Tag}} {{.ID}}' | sort -u)
fi

# If ONLY_TAGGED=true and we have zero names, suggest tagging.
if [[ "$ONLY_TAGGED" == "true" && ${#IMAGE_NAMES[@]} -eq 0 ]]; then
  echo "No tagged images found. Tag your images (e.g., 'podman tag <ID> localhost/myimg:v1') or set ONLY_TAGGED=false."
  exit 0
fi

# Helper: sanitize a repo:tag into a safe filename
sanitize() { echo "$1" | tr '/:@' '_' ; }

echo "[*] Found ${#IMAGE_NAMES[@]} images. Scanning with Trivy (offline)..."

if [[ "$ONLY_TAGGED" == "true" ]]; then
  # Scan by NAME (repo:tag), name files by NAME
  for NAME in "${IMAGE_NAMES[@]}"; do
    SAFE_NAME="$(sanitize "$NAME")"
    OUT_JSON="$REPORT_DIR/${SAFE_NAME}.json"
    echo "  - Scanning ${NAME} ..."
    trivy image \
      --skip-update \
      --cache-dir "$CACHE_DIR" \
      --severity "$SEVERITY" \
      --format json \
      -o "$OUT_JSON" \
      "$NAME" || echo "    ! Scan failed for $NAME (continuing)"
  done
else
  # Include untagged: we have "name id" per line. Prefer name; if <none>:<none>, use id.
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
    trivy image \
      --skip-update \
      --cache-dir "$CACHE_DIR" \
      --severity "$SEVERITY" \
      --format json \
      -o "$OUT_JSON" \
      "$SCAN_REF" || echo "    ! Scan failed for $SCAN_REF (continuing)"
  done <<<"$(printf '%s\n' "${IMAGE_NAMES[@]}")"
fi

echo "[*] Done. Reports saved to: $REPORT_DIR"
echo "[*] Example: jq '.Results[] | {Target, Vulnerabilities}' '$REPORT_DIR/some-image.json' | less"
