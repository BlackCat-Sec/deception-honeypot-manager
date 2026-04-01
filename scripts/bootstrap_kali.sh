#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[*] Installing Kali/Linux prerequisites"
sudo apt-get update
sudo apt-get install -y \
  python3 \
  python3-venv \
  python3-pip \
  docker.io \
  docker-compose-plugin \
  git \
  curl

if ! command -v gh >/dev/null 2>&1; then
  echo "[*] GitHub CLI not found; installing gh"
  sudo apt-get install -y gh
fi

if [ ! -d ".venv" ]; then
  echo "[*] Creating virtual environment"
  python3 -m venv .venv
fi

echo "[*] Installing Python dependencies"
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt

if [ ! -f ".env" ]; then
  echo "[*] Creating .env from .env.example"
  cp .env.example .env
fi

echo "[*] Enabling docker service"
sudo systemctl enable --now docker

if id -nG "$USER" | grep -qw docker; then
  echo "[*] User already in docker group"
else
  echo "[*] Adding $USER to docker group"
  sudo usermod -aG docker "$USER"
  echo "[!] Log out and back in, or run: newgrp docker"
fi

echo
echo "[+] Kali bootstrap complete"
echo "[+] Next steps:"
echo "    source .venv/bin/activate"
echo "    python main.py doctor"
echo "    python main.py deploy ssh --port 2222"
