#!/usr/bin/env bash
# Preparação do laboratório: PKI + segredos locais (nenhum deles é versionado).
set -euo pipefail

bash /repo/pki/pki.sh init

SEG=/repo/segredos
mkdir -p "$SEG"
if [ ! -f "$SEG/db.env" ]; then
  admin="$(openssl rand -hex 24)"
  ingest="$(openssl rand -hex 24)"
  painel="$(openssl rand -hex 24)"
  printf 'POSTGRES_PASSWORD=%s\nINGEST_DB_SENHA=%s\nPAINEL_DB_SENHA=%s\n' "$admin" "$ingest" "$painel" > "$SEG/db.env"
  printf 'INGEST_DB_SENHA=%s\n' "$ingest" > "$SEG/ingest.env"
  printf 'PAINEL_DB_SENHA=%s\n' "$painel" > "$SEG/painel.env"
  chmod 600 "$SEG"/*.env
  echo "[setup] segredos gerados em segredos/ (aleatórios, fora do Git)."
else
  echo "[setup] segredos já existem — mantidos."
fi
echo "[setup] pronto. Agora rode: docker compose up -d --build"
