#!/bin/sh
# Túnel WireGuard do projeto Vila Aurora (RT-06).
# O mesmo script serve ao concentrador da nuvem e aos nós de borda: o papel é
# definido pelo arquivo /wg/wg0.conf (gerado pelo setup, fora do Git).
set -eu

: "${WG_ENDERECO:?defina WG_ENDERECO (ex.: 10.8.0.13/24)}"
CONF=/wg/wg0.conf
[ -f "$CONF" ] || { echo "[vpn] ERRO: $CONF não encontrado. Rode: docker compose run --rm --build setup" >&2; exit 1; }

ip link del wg0 2>/dev/null || true
ip link add wg0 type wireguard
wg setconf wg0 "$CONF"
ip addr add "$WG_ENDERECO" dev wg0
ip link set wg0 up
echo "[vpn] wg0 ativo em $WG_ENDERECO ($(wg show wg0 peers | wc -l) par(es) configurado(s))"

# Nós de borda: se o túnel ficar sem handshake (queda de link, concentrador reiniciado),
# resolve de novo o endereço do concentrador. O concentrador só aguarda.
ENDPOINT="$(sed -n 's/^Endpoint *= *//p' "$CONF" | head -n 1)"
while sleep 30; do
  [ -n "$ENDPOINT" ] || continue
  PAR="$(wg show wg0 peers | head -n 1)"
  ULTIMO="$(wg show wg0 latest-handshakes | awk 'NR==1 {print $2}')"
  AGORA="$(date +%s)"
  if [ "${ULTIMO:-0}" -eq 0 ] || [ $((AGORA - ULTIMO)) -gt 150 ]; then
    WG_ENDPOINT_RESOLUTION_RETRIES=1 wg set wg0 peer "$PAR" endpoint "$ENDPOINT" 2>/dev/null \
      && echo "[vpn] sem handshake recente; endpoint $ENDPOINT resolvido novamente" || true
  fi
done
