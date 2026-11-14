"""SIEM da Rede Comunitária Vila Aurora (RT-12, 13, 15).

- Coleta: recebe eventos de segurança (JSON por UDP) dos serviços da nuvem que o alcançam
  pela rede interna (ingestão e painel), e LÊ do banco os comandos de atuador já centralizados
  pelo túnel (campo/borda). Respeita a segmentação: não abre caminho novo entre segmentos.
- Correlação e detecção: motor de 4 regras (regras.py).
- Resposta (RT-15): respostas de BAIXO RISCO são automáticas (quarentena da origem);
  ações de ALTO IMPACTO (mexer num atuador, revogar certificado) NUNCA são automáticas —
  entram numa fila que só a coordenação aprova no painel.
- Retenção: eventos antigos são removidos após RETER_DIAS.

Relógios: todos os containers compartilham o relógio do host, então os registros já saem
sincronizados — a causa raiz da investigação falha do incidente (relógios dessincronizados)
não se repete. O host deve manter a hora por NTP.
"""
import json
import os
import socket
import threading
import time
from datetime import datetime, timezone


def agora_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def log(evento: str, nivel: str = "info", **campos) -> None:
    print(json.dumps({"ts": agora_iso(), "componente": "siem", "nivel": nivel, "evento": evento, **campos},
                     ensure_ascii=False), flush=True)


class SIEM:
    def __init__(self, motor, armazenamento):
        self.motor = motor
        self.bd = armazenamento
        self._trava = threading.Lock()
        self._parar = threading.Event()
        self.porta = int(os.environ.get("PORTA", "5514"))
        self.reter_dias = int(os.environ.get("RETER_DIAS", "30"))

    # --------------------------------------------------------------- um evento
    def processar(self, ev: dict) -> None:
        ev.setdefault("recebido_em", agora_iso())
        if not ev.get("ts"):
            ev["ts"] = ev["recebido_em"]          # evento sem horário: usa o de recebimento
        if not ev.get("fonte"):
            ev["fonte"] = "desconhecida"
        try:
            self.bd.gravar_evento(ev)
        except Exception as exc:
            log("falha_gravar_evento", "erro", motivo=type(exc).__name__)
        with self._trava:                       # o motor tem estado; serializa o acesso
            saidas = self.motor.avaliar(ev)
        for s in saidas:
            self._aplicar(s)

    def _aplicar(self, s: dict) -> None:
        try:
            if s["tipo"] == "alerta":
                self.bd.gravar_alerta({k: s.get(k) for k in
                                       ("regra", "severidade", "titulo", "detalhe", "fonte", "origem", "tecnica", "resposta")})
                log("alerta", s["severidade"], regra=s["regra"], titulo=s["titulo"],
                    origem=s.get("origem"), tecnica=s.get("tecnica"), resposta=s.get("resposta"))
            elif s["tipo"] == "quarentena":
                self.bd.quarentenar(s["origem"], s["regra"], s["motivo"])
                log("resposta_automatica", "aviso", acao="quarentena", origem=s["origem"],
                    regra=s["regra"], nota="contenção de baixo risco aplicada automaticamente")
            elif s["tipo"] == "acao":
                if self.bd.enfileirar_acao(s["acao"], s["alvo"], s["motivo"], s["severidade"]):
                    log("acao_requer_aprovacao", "aviso", acao=s["acao"], alvo=s["alvo"],
                        nota="alto impacto: aguardando aprovação humana da coordenação")
                else:
                    log("acao_ja_pendente", "info", acao=s["acao"], alvo=s["alvo"],
                        nota="já existe uma ação igual aguardando a coordenação; não duplicada")
        except Exception as exc:
            log("falha_aplicar_saida", "erro", tipo=s.get("tipo"), motivo=type(exc).__name__)

    # --------------------------------------------------------------- coletor UDP
    def _coletor_udp(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", self.porta))
        sock.settimeout(1.0)
        log("coletor_iniciado", porta=self.porta)
        while not self._parar.is_set():
            try:
                dados, end = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                ev = json.loads(dados.decode("utf-8"))
                if not isinstance(ev, dict) or "evento" not in ev:
                    raise ValueError
            except (ValueError, UnicodeDecodeError):
                log("evento_descartado", "aviso", origem=end[0])
                continue
            ev.setdefault("origem", end[0])
            self.processar(ev)
        sock.close()

    # ------------------------------------------- leitura dos comandos no banco
    def _poller_comandos(self) -> None:
        """Lê os comandos de atuador já centralizados no banco (regra D), sem reprocessar o histórico."""
        cursor = None
        while not self._parar.wait(5):
            try:
                if cursor is None:
                    cursor = self.bd.cursor_inicial()   # começa do presente
                    continue
                linhas = self.bd.novos_comandos(cursor)
            except Exception as exc:
                log("falha_ler_comandos", "erro", motivo=type(exc).__name__)
                continue
            for recebido_em, cid, ts, espaco, dispositivo, acao, origem, agente in linhas:
                cursor = (recebido_em, cid)
                self.processar({
                    "ts": ts.isoformat() if hasattr(ts, "isoformat") else str(ts),
                    "fonte": f"agente-{espaco}", "nivel": "info", "evento": "comando",
                    "origem": agente,
                    "dados": {"dispositivo": dispositivo, "acao": acao, "origem": origem, "espaco": espaco},
                })

    def _retencao(self) -> None:
        while not self._parar.wait(3600):
            try:
                n = self.bd.limpar(self.reter_dias)
                if n:
                    log("retencao", removidos=n, reter_dias=self.reter_dias)
            except Exception as exc:
                log("falha_retencao", "erro", motivo=type(exc).__name__)

    def executar(self) -> None:
        log("siem_iniciado", reter_dias=self.reter_dias)
        alvos = (self._coletor_udp, self._poller_comandos, self._retencao)
        threads = [threading.Thread(target=f, daemon=True) for f in alvos]
        for t in threads:
            t.start()
        try:
            while not self._parar.wait(1):
                pass
        except KeyboardInterrupt:
            self._parar.set()


def main() -> None:
    from armazenamento import Postgres
    from deteccao import Motor
    try:
        bd = Postgres()
    except KeyError as exc:
        raise SystemExit(f"variável de ambiente obrigatória ausente: {exc}")
    SIEM(Motor(), bd).executar()


if __name__ == "__main__":
    main()
