"""Serviço de ingestão da nuvem — Rede Comunitária Vila Aurora.

Recebe os lotes dos agentes de borda por HTTPS com autenticação mútua (mTLS):
só entra quem apresenta certificado válido, não revogado, emitido pela CA do projeto
e com identidade de agente. A gravação é idempotente (o id do evento é a chave),
o que permite à borda reenviar lotes sem duplicar dados na reconciliação.
"""
import json
import os
import ssl
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from validacao import validar

MAX_CORPO = 1_000_000
MAX_EVENTOS = 500

SQL = {
    "leitura": """INSERT INTO leituras (id, espaco, dispositivo, metrica, valor, unidade, extra, ts, agente)
                  VALUES (%(id)s, %(espaco)s, %(dispositivo)s, %(metrica)s, %(valor)s, %(unidade)s,
                          %(extra)s, %(ts)s, %(agente)s)
                  ON CONFLICT (id) DO NOTHING""",
    "alarme": """INSERT INTO alarmes (id, espaco, dispositivo, regra, severidade, estado, mensagem, valor, ts, agente)
                 VALUES (%(id)s, %(espaco)s, %(dispositivo)s, %(regra)s, %(severidade)s, %(estado)s,
                         %(mensagem)s, %(valor)s, %(ts)s, %(agente)s)
                 ON CONFLICT (id) DO NOTHING""",
    "comando": """INSERT INTO comandos (id, espaco, dispositivo, acao, origem, ts, agente)
                  VALUES (%(id)s, %(espaco)s, %(dispositivo)s, %(acao)s, %(origem)s, %(ts)s, %(agente)s)
                  ON CONFLICT (id) DO NOTHING""",
}



import socket as _socket

_SIEM_ADDR = os.environ.get("SIEM_ADDR")


def _emitir_seguranca(registro: dict) -> None:
    if not _SIEM_ADDR:
        return
    try:
        host, porta = _SIEM_ADDR.split(":")
        with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as s:
            s.sendto(json.dumps(registro, ensure_ascii=False).encode("utf-8"), (host, int(porta)))
    except Exception:
        pass   # o SIEM é observabilidade; indisponível, não afeta a operação


# Eventos que interessam ao SIEM (tentativas de acesso sem credencial válida)
_EVENTOS_SEGURANCA = {"conexao_tls_recusada", "identidade_nao_autorizada"}


def log(evento: str, nivel: str = "info", **campos) -> None:
    registro = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "nivel": nivel, "componente": "nuvem-ingest", "evento": evento, **campos,
    }
    print(json.dumps(registro, ensure_ascii=False), flush=True)
    if evento in _EVENTOS_SEGURANCA:
        _emitir_seguranca({"ts": registro["ts"], "fonte": "nuvem-ingest", "nivel": nivel,
                           "evento": evento, "origem": campos.get("origem"),
                           "dados": {k: v for k, v in campos.items() if k != "origem"}})


class ArmazenamentoPostgres:
    """Grava com o papel `ingest_rw`, que só tem permissão de INSERT (menor privilégio)."""

    def __init__(self):
        import psycopg2  # importado aqui para os testes rodarem sem o driver
        self._psycopg2 = psycopg2
        self._dsn = dict(
            host=os.environ.get("DB_HOST", "nuvem-db"), port=int(os.environ.get("DB_PORTA", "5432")),
            dbname=os.environ.get("DB_NOME", "vilaaurora"), user="ingest_rw",
            password=os.environ["INGEST_DB_SENHA"], connect_timeout=5,
        )

    def gravar(self, registros: list[tuple[str, dict]]) -> tuple[int, int]:
        aceitos = duplicados = 0
        conexao = self._psycopg2.connect(**self._dsn)
        try:
            with conexao, conexao.cursor() as cur:   # uma transação por lote
                for tipo, registro in registros:
                    cur.execute(SQL[tipo], registro)   # consulta parametrizada
                    if cur.rowcount == 1:
                        aceitos += 1
                    else:
                        duplicados += 1
        finally:
            conexao.close()
        return aceitos, duplicados


def cn_do_certificado(certificado: dict | None) -> str | None:
    for rdn in (certificado or {}).get("subject", ()):
        for chave, valor in rdn:
            if chave == "commonName":
                return valor
    return None


class Manipulador(BaseHTTPRequestHandler):
    server_version = "VilaAuroraIngest"
    sys_version = ""
    timeout = 15
    armazenamento = None  # injetado em main()

    def setup(self):
        # Handshake TLS feito aqui, na thread desta conexão: um cliente lento ou sem
        # certificado não trava o atendimento dos demais agentes.
        self.request.settimeout(self.timeout)
        self.request.do_handshake()
        super().setup()

    def log_message(self, *_args):   # silencia o log padrão; usamos log estruturado
        pass

    def _responder(self, status: int, corpo: dict) -> None:
        dados = json.dumps(corpo).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(dados)))
        self.end_headers()
        self.wfile.write(dados)

    def _agente(self) -> str | None:
        cn = cn_do_certificado(self.connection.getpeercert())
        return cn if cn and cn.startswith("agente-") else None

    def do_GET(self):
        if self.path == "/saude":
            self._responder(200, {"ok": True})
        else:
            self._responder(404, {"erro": "não encontrado"})

    def do_POST(self):
        if self.path != "/ingest":
            return self._responder(404, {"erro": "não encontrado"})
        agente = self._agente()
        if agente is None:
            log("identidade_nao_autorizada", "aviso", origem=self.client_address[0],
                cn=cn_do_certificado(self.connection.getpeercert()))
            return self._responder(403, {"erro": "identidade não autorizada"})
        espaco = agente.removeprefix("agente-")

        try:
            tamanho = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._responder(411, {"erro": "Content-Length obrigatório"})
        if tamanho <= 0 or tamanho > MAX_CORPO:
            return self._responder(413, {"erro": "corpo fora do limite"})
        try:
            corpo = json.loads(self.rfile.read(tamanho).decode("utf-8"))
            eventos = corpo["eventos"]
            if not isinstance(eventos, list) or not 0 < len(eventos) <= MAX_EVENTOS:
                raise ValueError
        except (ValueError, KeyError, TypeError, UnicodeDecodeError):
            return self._responder(400, {"erro": "requisição inválida"})

        validos, rejeitados = [], []
        for evento in eventos:
            try:
                tipo, registro = validar(evento, espaco)
                registro["agente"] = agente
                validos.append((tipo, registro))
            except (ValueError, TypeError, AttributeError):
                ident = evento.get("id") if isinstance(evento, dict) else None
                if isinstance(ident, str):
                    rejeitados.append(ident[:36])
        try:
            aceitos, duplicados = self.armazenamento.gravar(validos) if validos else (0, 0)
        except Exception as exc:   # falha de banco: a borda tenta de novo depois
            log("falha_gravacao", "erro", agente=agente, motivo=type(exc).__name__)
            return self._responder(503, {"erro": "indisponível"})   # sem detalhes internos na resposta

        if rejeitados:
            log("eventos_rejeitados", "aviso", agente=agente, quantidade=len(rejeitados))
        log("lote_recebido", agente=agente, aceitos=aceitos, duplicados=duplicados, rejeitados=len(rejeitados))
        self._responder(200, {"aceitos": aceitos, "duplicados": duplicados, "rejeitados": rejeitados})


def criar_contexto_tls(pki_pub: Path, pki_ingest: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(pki_ingest / "ingest.crt"), str(pki_ingest / "ingest.key"))
    ctx.load_verify_locations(cafile=str(pki_pub / "ca.crt"))
    ctx.load_verify_locations(cafile=str(pki_pub / "ca.crl"))       # lista de revogação (RT-05)
    ctx.verify_mode = ssl.CERT_REQUIRED                              # mTLS: cliente sem certificado não entra
    ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    return ctx


class Servidor(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        """Conexões que falham no handshake (sem certificado, revogado, CA errada) viram log, não traceback."""
        exc = sys.exc_info()[1]
        if isinstance(exc, (ssl.SSLError, ConnectionError, TimeoutError)):
            log("conexao_tls_recusada", "aviso", origem=client_address[0],
                motivo=getattr(exc, "reason", None) or type(exc).__name__)
        else:
            log("erro_interno", "erro", origem=client_address[0], motivo=type(exc).__name__)


def criar_servidor(endereco, armazenamento, ctx: ssl.SSLContext) -> Servidor:
    Manipulador.armazenamento = armazenamento
    servidor = Servidor(endereco, Manipulador)
    # handshake feito na thread da conexão, para um cliente lento não travar os demais
    servidor.socket = ctx.wrap_socket(servidor.socket, server_side=True, do_handshake_on_connect=False)
    return servidor


def main() -> None:
    pki_pub = Path(os.environ.get("PKI_PUBLICO", "/pki/publico"))
    pki_ingest = Path(os.environ.get("PKI_INGEST", "/pki/ingest"))
    try:
        armazenamento = ArmazenamentoPostgres()
    except KeyError as exc:
        sys.exit(f"variável de ambiente obrigatória ausente: {exc}")
    # Em produção o serviço escuta SOMENTE no endereço do túnel WireGuard (ESCUTA=10.8.0.1):
    # fora da VPN não existe porta aberta para a ingestão.
    escuta = os.environ.get("ESCUTA", "0.0.0.0")
    servidor = criar_servidor((escuta, int(os.environ.get("PORTA", "8443"))),
                              armazenamento, criar_contexto_tls(pki_pub, pki_ingest))
    log("ingest_iniciado", escuta=escuta, porta=servidor.server_address[1], mtls=True, crl=True)
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
