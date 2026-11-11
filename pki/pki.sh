#!/usr/bin/env bash
# PKI do projeto Vila Aurora (laboratório) — RT-04 (identidade única) e RT-05 (revogação/rotação)
#
#   pki.sh init                 cria a CA e emite todos os certificados do inventário
#   pki.sh listar               mostra os certificados emitidos e o estado (válido/revogado)
#   pki.sh revogar <cn>         revoga o certificado e publica nova CRL
#   pki.sh rotacionar <cn>      revoga o atual e emite um novo par de chave/certificado
set -euo pipefail

RAIZ="${PKI_RAIZ:-/repo/pki}"
OUT="$RAIZ/out"
export PKI_CA_DIR="$OUT/ca"
PUB="$OUT/publico"
CNF="$RAIZ/ca.cnf"
REG="$PKI_CA_DIR/registro.csv"
ORG="Rede Comunitaria Vila Aurora"
ESPACOS="centro escola ubs horta abrigo"
UID_BROKER=1883   # usuário do Mosquitto no container
UID_APP=10001     # usuário sem privilégios dos serviços Python

log()  { printf '[pki] %s\n' "$*"; }
erro() { printf '[pki] ERRO: %s\n' "$*" >&2; exit 1; }

ossl_ca() {
  local saida
  if ! saida="$(openssl ca -batch -config "$CNF" "$@" 2>&1)"; then
    printf '%s\n' "$saida" >&2
    erro "openssl ca falhou"
  fi
}

gerar_crl() {
  ossl_ca -gencrl -out "$PUB/ca.crl"
  chmod 644 "$PUB/ca.crl"
}

# emitir <cn> <servidor|cliente> <destino relativo a out/> <nome base> <uid dono da chave> [SAN]
emitir() {
  local cn="$1" tipo="$2" rel="$3" base="$4" dono="$5" san="${6:-}"
  local destino="$OUT/$rel" csr
  mkdir -p "$destino"
  csr="$(mktemp)"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$destino/$base.key" 2>/dev/null
  if [ -n "$san" ]; then
    openssl req -new -config "$CNF" -key "$destino/$base.key" -subj "/O=$ORG/CN=$cn" \
      -addext "subjectAltName=$san" -out "$csr"
  else
    openssl req -new -config "$CNF" -key "$destino/$base.key" -subj "/O=$ORG/CN=$cn" -out "$csr"
  fi
  ossl_ca -extensions "ext_$tipo" -notext -in "$csr" -out "$destino/$base.crt"
  rm -f "$csr"
  chmod 600 "$destino/$base.key"
  chmod 644 "$destino/$base.crt"
  chown "$dono:$dono" "$destino/$base.key" 2>/dev/null || true
  # registro: uma linha por identidade (substitui a anterior em caso de rotação)
  if [ -f "$REG" ]; then grep -v "^$cn;" "$REG" > "$REG.tmp" || true; mv "$REG.tmp" "$REG"; fi
  printf '%s;%s;%s;%s;%s;%s\n' "$cn" "$tipo" "$rel" "$base" "$dono" "$san" >> "$REG"
  log "emitido: $cn ($tipo)"
}

buscar() {
  [ -f "$REG" ] || erro "PKI não inicializada. Rode: docker compose run --rm setup"
  grep "^$1;" "$REG" || erro "identidade não encontrada: $1 (use 'listar')"
}

cmd_init() {
  if [ -f "$PKI_CA_DIR/ca.key" ] && [ "${FORCAR:-0}" != "1" ]; then
    log "CA já existe em pki/out — nada a fazer (use FORCAR=1 para recriar tudo)."
    return 0
  fi
  rm -rf "$OUT"
  mkdir -p "$PKI_CA_DIR/emitidos" "$PUB"
  : > "$PKI_CA_DIR/index.txt"
  : > "$REG"
  echo 1000 > "$PKI_CA_DIR/serial"
  echo 1000 > "$PKI_CA_DIR/crlnumber"

  log "criando a CA do projeto"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$PKI_CA_DIR/ca.key" 2>/dev/null
  chmod 600 "$PKI_CA_DIR/ca.key"
  openssl req -x509 -new -config "$CNF" -extensions ext_ca -key "$PKI_CA_DIR/ca.key" -sha256 -days 1825 \
    -subj "/O=$ORG/CN=CA Vila Aurora (laboratorio)" -out "$PKI_CA_DIR/ca.crt"
  cp "$PKI_CA_DIR/ca.crt" "$PUB/ca.crt"
  chmod 644 "$PUB/ca.crt"

  emitir "nuvem-ingest" servidor "nuvem/ingest" ingest "$UID_APP" "DNS:nuvem-ingest"
  for e in $ESPACOS; do
    emitir "borda-$e-broker" servidor "bordas/$e/broker" broker "$UID_BROKER" "DNS:borda-$e-broker"
    emitir "agente-$e" cliente "bordas/$e/agente" agente "$UID_APP"
  done
  grep -v '^#' "$RAIZ/inventario.csv" | tr -d '\r' | while IFS=';' read -r espaco cn; do
    [ -n "$cn" ] || continue
    emitir "$cn" cliente "dispositivos/$espaco" "$cn" "$UID_APP"
  done
  gerar_crl
  log "PKI pronta: $(grep -c . "$REG") identidades emitidas. A chave da CA fica só em pki/out/ca (nunca é montada em container de serviço)."
}

cmd_listar() {
  [ -f "$PKI_CA_DIR/index.txt" ] || erro "PKI não inicializada."
  printf '%-10s %-8s %s\n' "ESTADO" "SERIAL" "IDENTIDADE"
  awk -F'\t' '{ estado = ($1 == "V") ? "valido" : (($1 == "R") ? "REVOGADO" : $1);
               n = split($6, p, "CN="); printf "%-10s %-8s %s\n", estado, $4, p[n] }' "$PKI_CA_DIR/index.txt"
}

cmd_revogar() {
  local cn="${1:-}"; [ -n "$cn" ] || erro "uso: pki.sh revogar <cn>"
  local linha tipo rel base dono san
  linha="$(buscar "$cn")"
  IFS=';' read -r _ tipo rel base dono san <<< "$linha"
  ossl_ca -revoke "$OUT/$rel/$base.crt" -crl_reason keyCompromise
  gerar_crl
  log "revogado: $cn — CRL atualizada em pki/out/publico/ca.crl"
  log "aplique a CRL reiniciando quem valida certificados (brokers da borda e ingest da nuvem)."
}

cmd_rotacionar() {
  local cn="${1:-}"; [ -n "$cn" ] || erro "uso: pki.sh rotacionar <cn>"
  local linha tipo rel base dono san
  linha="$(buscar "$cn")"
  IFS=';' read -r _ tipo rel base dono san <<< "$linha"
  # revoga o certificado atual se ainda estiver válido
  if openssl verify -CAfile "$PUB/ca.crt" -CRLfile "$PUB/ca.crl" -crl_check "$OUT/$rel/$base.crt" >/dev/null 2>&1; then
    ossl_ca -revoke "$OUT/$rel/$base.crt" -crl_reason superseded
  fi
  emitir "$cn" "$tipo" "$rel" "$base" "$dono" "$san"
  gerar_crl
  log "rotacionado: $cn — reinicie o serviço que usa esta identidade e os validadores (brokers/ingest)."
}

case "${1:-}" in
  init)       cmd_init ;;
  listar)     cmd_listar ;;
  revogar)    shift; cmd_revogar "$@" ;;
  rotacionar) shift; cmd_rotacionar "$@" ;;
  *) erro "uso: pki.sh {init|listar|revogar <cn>|rotacionar <cn>}" ;;
esac
