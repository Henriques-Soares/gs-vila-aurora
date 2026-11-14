#!/usr/bin/env bash
# Preparação do laboratório: PKI, segredos do banco e chaves da VPN.
# Nada do que é gerado aqui vai para o Git (pki/out e segredos/ estão no .gitignore).
# Pode ser executado de novo sem risco: só cria o que ainda não existe.
set -euo pipefail

bash /repo/pki/pki.sh init

SEG=/repo/segredos
mkdir -p "$SEG"

# ---------------------------------------------------------------- banco de dados
if [ ! -f "$SEG/db.env" ]; then
  admin="$(openssl rand -hex 24)"
  ingest="$(openssl rand -hex 24)"
  painel="$(openssl rand -hex 24)"
  printf 'POSTGRES_PASSWORD=%s\nINGEST_DB_SENHA=%s\nPAINEL_DB_SENHA=%s\n' "$admin" "$ingest" "$painel" > "$SEG/db.env"
  siem="$(openssl rand -hex 24)"
  printf 'INGEST_DB_SENHA=%s\n' "$ingest" > "$SEG/ingest.env"
  printf 'PAINEL_DB_SENHA=%s\n' "$painel" > "$SEG/painel.env"
  printf 'SIEM_DB_SENHA=%s\n' "$siem" > "$SEG/siem.env"
  printf 'SIEM_DB_SENHA=%s\n' "$siem" >> "$SEG/db.env"
  chmod 600 "$SEG"/*.env
  echo "[setup] segredos do banco gerados em segredos/."
else
  echo "[setup] segredos do banco já existem — mantidos."
  if ! grep -q '^SIEM_DB_SENHA=' "$SEG/db.env"; then
    siem="$(openssl rand -hex 24)"
    printf 'SIEM_DB_SENHA=%s\n' "$siem" > "$SEG/siem.env"
    printf 'SIEM_DB_SENHA=%s\n' "$siem" >> "$SEG/db.env"
    echo "[setup] senha do SIEM gerada e anexada."
  fi
fi

# ---------------------------------------------------------------- painel: chave das sessões
if ! grep -q '^PAINEL_CHAVE_SESSAO=' "$SEG/painel.env"; then
  printf 'PAINEL_CHAVE_SESSAO=%s\n' "$(openssl rand -hex 32)" >> "$SEG/painel.env"
  echo "[setup] chave de assinatura das sessões do painel gerada."
fi

# ---------------------------------------------------------------- VPN WireGuard (RT-06)
# Um par de chaves Curve25519 por nó + uma chave pré-compartilhada por enlace.
chave_privada() { openssl genpkey -algorithm X25519 -outform DER | tail -c 32 | base64; }
chave_publica() {  # recebe a privada (base64) e devolve a pública (base64)
  { printf '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x6e\x04\x22\x04\x20'; printf '%s' "$1" | base64 -d; } \
    | openssl pkey -inform DER -pubout -outform DER | tail -c 32 | base64
}

WG="$SEG/wg"
if [ ! -f "$WG/nuvem/wg0.conf" ]; then
  mkdir -p "$WG/nuvem"
  hub_priv="$(chave_privada)"
  hub_pub="$(chave_publica "$hub_priv")"
  printf '[Interface]\nPrivateKey = %s\nListenPort = 51820\n' "$hub_priv" > "$WG/nuvem/wg0.conf"
  n=11
  for e in centro escola ubs horta abrigo; do
    priv="$(chave_privada)"
    pub="$(chave_publica "$priv")"
    psk="$(openssl rand -base64 32)"
    mkdir -p "$WG/$e"
    printf '[Interface]\nPrivateKey = %s\n\n[Peer]\n# concentrador da nuvem\nPublicKey = %s\nPresharedKey = %s\nEndpoint = nuvem-vpn:51820\nAllowedIPs = 10.8.0.1/32\nPersistentKeepalive = 25\n' \
      "$priv" "$hub_pub" "$psk" > "$WG/$e/wg0.conf"
    printf '\n[Peer]\n# borda: %s\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = 10.8.0.%s/32\n' \
      "$e" "$pub" "$psk" "$n" >> "$WG/nuvem/wg0.conf"
    n=$((n + 1))
  done
  chmod 600 "$WG"/*/wg0.conf
  echo "[setup] chaves da VPN geradas em segredos/wg/ (1 par por nó + chave pré-compartilhada por enlace)."
else
  echo "[setup] chaves da VPN já existem — mantidas."
fi

echo "[setup] pronto. Agora rode: docker compose up -d --build"
