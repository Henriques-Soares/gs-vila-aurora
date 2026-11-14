#!/usr/bin/env bash
# Instalação nova: define a senha do papel siem_rw (criado em 04-siem.sql).
# Em um banco que já existia, quem faz isso é `docker compose run --rm admin migrar`.
set -e
if [ -n "${SIEM_DB_SENHA:-}" ]; then
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
       -v siem_senha="$SIEM_DB_SENHA" <<'SQL'
ALTER ROLE siem_rw PASSWORD :'siem_senha';
SQL
fi
