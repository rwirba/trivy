scp -i ../Downloads/dev-key.pem -r ubuntu@controler-ip:/home/ubuntu/trivy/ansible-trivy-build/reports/remote-server-ip trivy-reports/

sudo -iu sapuser bash -lc '
  export XDG_RUNTIME_DIR="/run/user/$(id -u)"
  systemctl --user enable --now podman.socket