# ---- Stage 1: Build & prefetch Trivy DBs (online) ---------------------------
FROM registry.access.redhat.com/ubi8/ubi as builder

ARG TRIVY_VERSION=0.61.1
ENV TRIVY_VERSION=${TRIVY_VERSION}
ENV TRIVY_CACHE_DIR=/trivy-cache

# Minimal tools to fetch and pack
RUN dnf -y install curl tar gzip ca-certificates && dnf clean all

# Get Trivy static binary to avoid rpm/gpg deps
RUN curl -fsSL -o /tmp/trivy.tar.gz \
      https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz \
 && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
 && chmod +x /usr/local/bin/trivy \
 && rm -f /tmp/trivy.tar.gz

RUN trivy --version 

# Prepare cache dir and prefetch both DBs (main + Java)
RUN mkdir -p ${TRIVY_CACHE_DIR} \
 && trivy --cache-dir ${TRIVY_CACHE_DIR} image image --download-db-only \
 && trivy --cache-dir ${TRIVY_CACHE_DIR} image image --download-java-db-only

# Pack cache as a portable artifact
RUN mkdir -p /out \
 && tar -C / -czf /out/trivy-cache.tar.gz trivy-cache

# ---- Stage 2: Handy carrier image with artifacts ----------------------------
FROM registry.access.redhat.com/ubi8/ubi

# Copy Trivy binary and the pre-built offline cache artifact
COPY --from=builder /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /out/trivy-cache.tar.gz /out/trivy-cache.tar.gz

# Helper to re-export the cache if you modify it inside a container
ADD <<'EOF' /usr/local/bin/export-cache.sh
#!/usr/bin/env bash
set -euo pipefail
OUT="${1:-/out/trivy-cache.tar.gz}"
mkdir -p "$(dirname "$OUT")"
/usr/bin/tar -C / -czf "$OUT" trivy-cache
echo "Wrote $OUT"
EOF
RUN chmod +x /usr/local/bin/export-cache.sh

# Not required to run; this image is primarily for artifact export
CMD ["bash","-lc","echo 'Artifacts: /usr/local/bin/trivy and /out/trivy-cache.tar.gz'; ls -l /out"]
