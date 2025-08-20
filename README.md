scp -i ../Downloads/dev-key.pem -r ubuntu@controler-ip:/home/ubuntu/trivy/ansible-trivy-build/reports/remote-server-ip trivy-reports/

sudo -iu sapuser bash -lc '
  export XDG_RUNTIME_DIR="/run/user/$(id -u)"
  systemctl --user enable --now podman.socke


sudo loginctl enable-linger sapuser

sudo -iu ec2-user bash -lc '
  export XDG_RUNTIME_DIR=/run/user/$(id -u)
  systemctl --user enable --now podman.socket
  test -S "$XDG_RUNTIME_DIR/podman/podman.sock" && echo "Podman user socket is up"
'

sudo -iu ec2-user bash -lc '
  export XDG_RUNTIME_DIR=/run/user/$(id -u)
  SEVERITY="HIGH,CRITICAL" \
  CACHE_DIR="$HOME/.cache/trivy" \
  TRIVY_PKG_TYPES="os" TRIVY_SCANNERS="vuln" \
  /usr/local/bin/offline-trivy-scan.sh
'