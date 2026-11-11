"""Agente do nó de borda — Rede Comunitária Vila Aurora.

Um agente por espaço comunitário (RT-01). Ele:
  1. recebe a telemetria dos dispositivos pelo broker local (MQTT + mTLS);
  2. aplica as regras de controle locais, sem depender da nuvem (RT-02);
  3. grava tudo no buffer em disco e encaminha em lotes para a nuvem
     por HTTPS com mTLS, reconciliando quando o link volta (RT-02).
"""
import json
import os
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import paho.mqtt.client as mqtt

from buffer import Buffer
from regras import Motor

CAMPOS_LEITURA = ("id", "espaco", "dispositivo", "metrica", "valor", "unidade", "ts")


def log(evento: str, nivel: str = "info", **campos) -> None:
    registro = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "nivel": nivel,
        "componente": "agente-borda",
        "espaco": os.environ.get("ESPACO", "?"),
        "evento": evento,
        **campos,
    }
    print(json.dumps(registro, ensure_ascii=False), flush=True)


class Agente:
    def __init__(self):
        self.espaco = os.environ["ESPACO"]
        self.broker = os.environ["BROKER_HOST"]
        self.porta = int(os.environ.get("BROKER_PORTA", "8883"))
        self.ingest_url = os.environ["INGEST_URL"]
        self.lote = int(os.environ.get("LOTE", "200"))
        self.intervalo = float(os.environ.get("INTERVALO_ENVIO_S", "5"))
        self.reter_s = float(os.environ.get("RETER_ENVIADOS_S", "86400"))

        pki_pub = Path(os.environ.get("PKI_PUBLICO", "/pki/publico"))
        pki_ag = Path(os.environ.get("PKI_AGENTE", "/pki/agente"))
        self.ca = str(pki_pub / "ca.crt")
        self.crt = str(pki_ag / "agente.crt")
        self.key = str(pki_ag / "agente.key")

        regras_arq = Path(os.environ.get("REGRAS_DIR", "/app/regras")) / f"{self.espaco}.json"
        regras = json.loads(regras_arq.read_text(encoding="utf-8"))
        self.motor = Motor(regras, self.espaco)
        self.buffer = Buffer(os.environ.get("BUFFER_DB", "/dados/buffer.db"))
        self._trava_regras = threading.Lock()
        self._parar = threading.Event()

        self.cliente = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2, client_id=f"agente-{self.espaco}", clean_session=False
        )
        self.cliente.tls_set(ca_certs=self.ca, certfile=self.crt, keyfile=self.key, cert_reqs=ssl.CERT_REQUIRED)
        self.cliente.on_connect = self._ao_conectar
        self.cliente.on_disconnect = self._ao_desconectar
        self.cliente.on_message = self._ao_receber
        self.cliente.reconnect_delay_set(min_delay=1, max_delay=30)

        self._ctx_nuvem = ssl.create_default_context(cafile=self.ca)
        self._ctx_nuvem.minimum_version = ssl.TLSVersion.TLSv1_2
        self._ctx_nuvem.load_cert_chain(self.crt, self.key)
        # conexão direta com a nuvem (pelo túnel), sem proxy intermediário
        self._http = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=self._ctx_nuvem)
        )

    # ------------------------------------------------------------------ MQTT
    def _ao_conectar(self, cliente, _ud, _flags, codigo, _props=None):
        if getattr(codigo, "is_failure", False):
            log("broker_conexao_recusada", "erro", motivo=str(codigo))
            return
        cliente.subscribe("dispositivos/+/telemetria", qos=1)
        log("broker_conectado", broker=self.broker, regras=len(self.motor.regras))

    def _ao_desconectar(self, _cliente, _ud, _flags, codigo, _props=None):
        log("broker_desconectado", "aviso", motivo=str(codigo))

    def _ao_receber(self, _cliente, _ud, msg):
        try:
            leitura = json.loads(msg.payload.decode("utf-8"))
            if not isinstance(leitura, dict) or any(c not in leitura for c in CAMPOS_LEITURA):
                raise ValueError("campos obrigatórios ausentes")
            if not isinstance(leitura["valor"], (int, float)) or isinstance(leitura["valor"], bool):
                raise ValueError("valor não numérico")
            # O tópico carrega a identidade autenticada (CN do certificado, garantido pela ACL):
            # uma leitura que diga ser de outro dispositivo ou espaço é descartada.
            cn_topico = msg.topic.split("/")[1]
            if leitura["dispositivo"] != cn_topico or leitura["espaco"] != self.espaco:
                raise ValueError("identidade da leitura difere da identidade autenticada")
        except (ValueError, UnicodeDecodeError, IndexError) as exc:
            log("leitura_descartada", "aviso", topico=msg.topic, motivo=str(exc))
            return

        self.buffer.guardar("leitura", leitura)
        with self._trava_regras:
            acoes = self.motor.avaliar(leitura)
        for acao in acoes:
            self._executar(acao)

    def _executar(self, acao: dict) -> None:
        dados = acao["dados"]
        self.buffer.guardar(acao["tipo"], dados)
        if acao["tipo"] == "alarme":
            self.cliente.publish(f"borda/{self.espaco}/alarme", json.dumps(dados, ensure_ascii=False), qos=1)
            log("alarme_local", "aviso", regra=dados["regra"], dispositivo=dados["dispositivo"],
                severidade=dados["severidade"], estado=dados["estado"], valor=dados["valor"],
                mensagem=dados["mensagem"])
        elif acao["tipo"] == "comando":
            self.cliente.publish(f"dispositivos/{dados['dispositivo']}/comando",
                                 json.dumps(dados, ensure_ascii=False), qos=1)
            log("comando_local", dispositivo=dados["dispositivo"], acao=dados["acao"], origem=dados["origem"])

    # ----------------------------------------------------------------- nuvem
    def _postar(self, eventos: list[dict]) -> dict:
        corpo = json.dumps({"eventos": eventos}, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            self.ingest_url, data=corpo, method="POST", headers={"Content-Type": "application/json"}
        )
        with self._http.open(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _enviador(self) -> None:
        link_ok = True
        espera = self.intervalo
        ultima_limpeza = time.monotonic()
        while not self._parar.is_set():
            lote = self.buffer.proximos(self.lote)
            if not lote:
                self._parar.wait(self.intervalo)
                continue
            try:
                resposta = self._postar(lote)
            except (urllib.error.URLError, OSError, ValueError) as exc:
                if link_ok:
                    log("link_nuvem_indisponivel", "aviso", motivo=str(exc)[:200],
                        pendentes=self.buffer.contagem()["pendente"],
                        nota="operação local continua; eventos ficam no buffer")
                link_ok = False
                espera = min(espera * 2, 60)
                self._parar.wait(espera)
                continue

            rejeitados = set(resposta.get("rejeitados", []))
            entregues = [e["id"] for e in lote if e["id"] not in rejeitados]
            self.buffer.marcar(entregues, "enviado")
            self.buffer.marcar(list(rejeitados), "rejeitado")
            if not link_ok:
                log("link_nuvem_restabelecido", pendentes=self.buffer.contagem()["pendente"],
                    nota="reconciliando eventos acumulados")
            link_ok = True
            espera = self.intervalo
            if rejeitados:
                log("eventos_rejeitados_pela_nuvem", "aviso", quantidade=len(rejeitados))
            log("lote_entregue", "debug", enviados=len(entregues), aceitos=resposta.get("aceitos"),
                duplicados=resposta.get("duplicados"), pendentes=self.buffer.contagem()["pendente"])

            if time.monotonic() - ultima_limpeza > 600:
                self.buffer.limpar(self.reter_s)
                ultima_limpeza = time.monotonic()
            if len(lote) < self.lote:
                self._parar.wait(self.intervalo)

    def _relator(self) -> None:
        while not self._parar.wait(60):
            log("estado_buffer", **self.buffer.contagem())

    # ------------------------------------------------------------------ ciclo
    def executar(self) -> None:
        log("agente_iniciado", broker=self.broker, ingest=self.ingest_url)
        self.cliente.connect_async(self.broker, self.porta, keepalive=30)
        self.cliente.loop_start()
        threading.Thread(target=self._enviador, name="enviador", daemon=True).start()
        threading.Thread(target=self._relator, name="relator", daemon=True).start()
        try:
            while not self._parar.wait(1):
                pass
        except KeyboardInterrupt:
            pass
        finally:
            self.parar()

    def parar(self) -> None:
        self._parar.set()
        self.cliente.loop_stop()
        self.cliente.disconnect()


if __name__ == "__main__":
    try:
        Agente().executar()
    except KeyError as exc:
        sys.exit(f"variável de ambiente obrigatória ausente: {exc}")
