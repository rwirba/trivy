#!/usr/bin/env bash
set -euo pipefail

# =========================
# Trivy Offline DB Builder (macOS + Linux)
# =========================
# Output: trivy-offline.db.tgz with ./db/{trivy.db,metadata.json}
# Interactive: choose OS-only vs Full (langs+OS)
# Flags:  --os-only | --full | --install
# Env:    WORKROOT=/big/disk   TMPDIR=/big/disk/tmp
# =========================

# --- normalize line endings if file was saved with CRLF (safe no-op otherwise)
if file "$0" 2>/dev/null | grep -qi 'CRLF'; then
  sed -i 's/\r$//' "$0" 2>/dev/null || true
fi

INSTALL=false
MODE=""   # "os" or "full"

# ---- robust arg parsing (no fake empty arg)
while [[ $# -gt 0 ]]; do
  case "$1" in
    --install) INSTALL=true; shift ;;
    --os-only) MODE="os"; shift ;;
    --full)    MODE="full"; shift ;;
    --)        shift; break ;;
    *) echo "Unknown flag: $1" >&2; exit 1 ;;
  esac
done

uname_s="$(uname -s)"
uname_m="$(uname -m)"
is_mac=false; is_linux=false
case "$uname_s" in
  Darwin) is_mac=true ;;
  Linux)  is_linux=true ;;
  *) echo "Unsupported OS: $uname_s" >&2; exit 1 ;;
esac

# ---------- helpers ----------
have(){ command -v "$1" >/dev/null 2>&1; }
msg(){ printf '%s\n' "$*" >&2; }
sed_inplace(){ if $is_mac; then sed -i '' "$@"; else sed -i "$@"; fi; }
free_gb(){
  if $is_mac; then df -g . | awk 'NR==2{print $4}'; else df --output=avail -BG . | tail -1 | tr -dc '0-9'; fi
}

# ---------- prerequisites ----------
if $is_mac; then
  if ! xcode-select -p >/dev/null 2>&1; then
    msg "[*] Installing Xcode Command Line Tools (one-time)..."
    xcode-select --install || true
    msg "If a GUI prompt appeared, finish it and rerun this script."
  fi
  if ! have brew; then
    msg "[*] Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    eval "$(/opt/homebrew/bin/brew shellenv 2>/dev/null || true)"
    eval "$(/usr/local/bin/brew shellenv 2>/dev/null || true)"
  fi
  for pkg in git make coreutils gnu-tar curl; do
    brew list --versions "$pkg" >/dev/null 2>&1 || brew install "$pkg"
  done
  # prefer GNU tar if available
  if brew --prefix gnu-tar >/dev/null 2>&1; then
    export PATH="$(brew --prefix gnu-tar)/bin:$PATH"
  fi
else
  DISTRO=unknown; [ -f /etc/os-release ] && . /etc/os-release && DISTRO=$ID
  install_pkg(){
    case "$DISTRO" in
      ubuntu|debian) sudo apt-get update -y && sudo apt-get install -y "$@" ;;
      rhel|centos|rocky|almalinux|fedora) sudo dnf install -y "$@" ;;
      *) msg "Unsupported Linux distro: $DISTRO. Please install: $*"; return 1 ;;
    esac
  }
  have git  || install_pkg git
  have make || install_pkg make
  have tar  || install_pkg tar
  if ! have curl && ! have wget; then install_pkg curl || install_pkg wget; fi
fi

# ---------- Go >= 1.20 ----------
need_minor=20
install_go_official(){
  GO_VER="$(curl -fsSL https://go.dev/VERSION?m=text | head -n1 | tr -d '\r')"
  if $is_mac; then os_name="darwin"; else os_name="linux"; fi
  case "$uname_m" in
    arm64|aarch64) arch_name="arm64" ;;
    x86_64|amd64)  arch_name="amd64" ;;
    *) msg "Unsupported CPU arch: $uname_m"; exit 1 ;;
  esac
  TARBALL="${GO_VER}.${os_name}-${arch_name}.tar.gz"
  msg "[*] Installing ${GO_VER} for ${os_name}-${arch_name}"
  curl -fsSL "https://go.dev/dl/${TARBALL}" -o /tmp/go.tgz
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf /tmp/go.tgz
  export PATH="/usr/local/go/bin:$PATH"
  grep -qs '/usr/local/go/bin' ~/.bashrc 2>/dev/null || echo 'export PATH=/usr/local/go/bin:$PATH' >> ~/.bashrc || true
  if $is_mac; then
    grep -qs '/usr/local/go/bin' ~/.zshrc 2>/dev/null || echo 'export PATH=/usr/local/go/bin:$PATH' >> ~/.zshrc || true
  fi
}
ensure_go(){
  if have go; then
    minor="$(go version | awk '{print $3}' | sed -E 's/^go1\.([0-9]+).*/\1/')"
    if [ -z "$minor" ] || [ "$minor" -lt "$need_minor" ]; then
      install_go_official
    fi
  else
    install_go_official
  fi
  msg "[*] Go version: $(go version)"
}
ensure_go

# ---------- optional: ensure bbolt (for DB compaction) ----------
ensure_bbolt(){
  if ! have bbolt; then
    msg "[*] Installing bbolt CLI for DB compaction..."
    GOPATH_DIR="$(go env GOPATH 2>/dev/null || true)"; [ -z "$GOPATH_DIR" ] && GOPATH_DIR="$HOME/go"
    go install go.etcd.io/bbolt/cmd/bbolt@v1.3.5 || true
    export PATH="$GOPATH_DIR/bin:/usr/local/go/bin:$PATH"
  fi
  if have bbolt; then msg "[*] bbolt present: $(command -v bbolt)"; else msg "[*] bbolt not available; compaction will be skipped"; fi
}
ensure_bbolt

# ---------- choose mode (interactive if not set) ----------
if [ -z "$MODE" ]; then
  echo ""
  echo "Choose Trivy DB build mode:"
  echo "  1) OS-only (smaller/faster)  [default]"
  echo "  2) Full (OS + language advisories)"
  read -r -p "Enter 1 or 2 [1]: " ans
  case "${ans:-1}" in
    2) MODE="full" ;;
    *) MODE="os" ;;
  esac
fi
msg "[*] Build mode selected: $MODE"

# ---------- space check ----------
avail="$(free_gb)"
need=8; [ "$MODE" = "full" ] && need=20
if [ "${avail:-0}" -lt "$need" ]; then
  msg "ERROR: Only ${avail:-0}G free in $(pwd). Need >= ${need}G for '$MODE' build."
  msg "Tip: WORKROOT=/path/to/large/volume TMPDIR=/path/to/large/volume/tmp $0 [--full|--os-only]"
  exit 1
fi

# ---------- work dir ----------
WORKROOT="${WORKROOT:-$(pwd)}"
[ -n "${TMPDIR:-}" ] || export TMPDIR="$WORKROOT/tmp"
mkdir -p "$TMPDIR"

WORKDIR="$WORKROOT/_trivy-db-build"
rm -rf "$WORKDIR"; mkdir -p "$WORKDIR"; cd "$WORKDIR"

# ---------- clone ----------
msg "[*] Cloning aquasecurity/trivy-db..."
git clone --depth=1 https://github.com/aquasecurity/trivy-db.git
cd trivy-db

# Patch go.mod if line is 'go 1.24.0' (older toolchains prefer 'go 1.24')
if grep -qE '^go 1\.24\.0$' go.mod; then
  msg "[*] Patching go.mod 'go 1.24.0' -> 'go 1.24'"
  sed_inplace 's/^go 1\.24\.0$/go 1.24/' go.mod
fi

# ---------- fetch advisories ----------
if [ "$MODE" = "full" ]; then
  msg "[*] Fetching advisories (languages + OS)..."
  make db-fetch-langs || msg "WARN: db-fetch-langs failed; continuing with OS DB only"
  make db-fetch-vuln-list
else
  msg "[*] Fetching OS vuln advisories only..."
  make db-fetch-vuln-list
fi

# ---------- build DB ----------
msg "[*] Building trivy-db binary..."
make build
msg "[*] Building SQLite DB..."
make db-build

OUT_DIR="$(pwd)/out"
DB_SRC="$OUT_DIR/trivy.db"
META_SRC="$OUT_DIR/metadata.json"

# Verify artifacts exist BEFORE any optimization
if [[ ! -f "$DB_SRC" || ! -f "$META_SRC" ]]; then
  msg "ERROR: DB artifacts missing in ./out (need trivy.db and metadata.json)"
  exit 1
fi

# ---------- optional compaction with bbolt ----------
COMPACTED_DIR="$(pwd)/assets"
mkdir -p "$COMPACTED_DIR"
DB_FINAL="$COMPACTED_DIR/trivy.db"
META_FINAL="$COMPACTED_DIR/metadata.json"

if have bbolt; then
  msg "[*] Compacting DB with bbolt (optional)…"
  if bbolt compact -o "$DB_FINAL" "$DB_SRC"; then
    cp "$META_SRC" "$META_FINAL"
  else
    msg "WARN: bbolt compact failed; using uncompressed DB"
    cp "$DB_SRC"  "$DB_FINAL"
    cp "$META_SRC" "$META_FINAL"
  fi
else
  msg "[*] bbolt not found; skipping compaction"
  cp "$DB_SRC"  "$DB_FINAL"
  cp "$META_SRC" "$META_FINAL"
fi

# Double-check staged files before packaging
if [[ ! -f "$DB_FINAL" || ! -f "$META_FINAL" ]]; then
  msg "ERROR: Staged DB or metadata missing in $COMPACTED_DIR"
  exit 1
fi

# ---------- package ----------
BUNDLE_DIR="$(pwd)/offline_bundle"
rm -rf "$BUNDLE_DIR"; mkdir -p "$BUNDLE_DIR/db"
cp "$DB_FINAL"  "$BUNDLE_DIR/db/trivy.db"
cp "$META_FINAL" "$BUNDLE_DIR/db/metadata.json"

cd "$BUNDLE_DIR"
tar -czf ../../trivy-offline.db.tgz db
cd - >/dev/null

abs_tgz="$(cd ../.. && pwd)/trivy-offline.db.tgz"
msg "[*] Built offline DB archive: $abs_tgz"

# Safe to clean original out now (optional)
rm -rf "$OUT_DIR"

# ---------- optional install (for local testing) ----------
if $INSTALL; then
  CACHE_DIR="${HOME}/.cache/trivy/db"
  mkdir -p "$CACHE_DIR"
  tar -xzf "$abs_tgz" -C "${HOME}/.cache/trivy"
  msg "[*] Installed to ${HOME}/.cache/trivy/db"
  msg "[*] Example test later on RHEL: trivy image --skip-update --cache-dir ~/.cache/trivy alpine:3.18"
fi

msg "[*] Done."