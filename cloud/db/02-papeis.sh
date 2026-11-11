#!/usr/bin/env bash
# Papéis de banco com privilégio mínimo (RT-08): cada serviço só faz o que precisa.
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v ingest_senha="$INGEST_DB_SENHA" -v painel_senha="$PAINEL_DB_SENHA" <<'SQL'
CREATE ROLE ingest_rw LOGIN PASSWORD :'ingest_senha';
CREATE ROLE painel_ro LOGIN PASSWORD :'painel_senha';

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO ingest_rw, painel_ro;

-- ingest: só insere (e enxerga apenas a coluna id, usada para descartar duplicatas)
GRANT INSERT ON leituras, alarmes, comandos TO ingest_rw;
GRANT SELECT (id) ON leituras, alarmes, comandos TO ingest_rw;

-- painel: só leitura
GRANT SELECT ON leituras, alarmes, comandos TO painel_ro;
SQL
