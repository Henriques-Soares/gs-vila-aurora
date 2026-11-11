"""Simulador dos dispositivos de campo — Rede Comunitária Vila Aurora.

Cada dispositivo do espaço abre a PRÓPRIA conexão MQTT com o PRÓPRIO certificado
X.509 (mTLS), exatamente como um ESP32 real faria. Todos os dados são sintéticos.
"""
import json
import os
import random
import ssl
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import paho.mqtt.client as mqtt

CENARIOS = Path(os.environ.get("CENARIOS_DIR", "/tmp/cenarios"))


def agora_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def log(evento: str, **campos) -> None:
    print(json.dumps({"ts": agora_iso(), "componente": "campo", "espaco": os.environ.get("ESPACO", "?"),
                      "evento": evento, **campos}, ensure_ascii=False), flush=True)


def cenario_ativo(nome: str | None) -> bool:
    return bool(nome) and (CENARIOS / nome).exists()


class Dispositivo:
    """Base: identidade (CN), conexão mTLS própria e publicação de telemetria."""

    def __init__(self, cfg: dict, espaco: str, broker: str, porta: int, pki_pub: Path, pki_dev: Path):
        self.cfg = cfg
        self.cn = cfg["cn"]
        self.espaco = espaco
        self.conectado = False
        self.cliente = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=self.cn)
        self.cliente.tls_set(
            ca_certs=str(pki_pub / "ca.crt"),
            certfile=str(pki_dev / f"{self.cn}.crt"),
            keyfile=str(pki_dev / f"{self.cn}.key"),
            cert_reqs=ssl.CERT_REQUIRED,
        )
        self.cliente.on_connect = self._ao_conectar
        self.cliente.on_disconnect = self._ao_desconectar
        self.cliente.on_message = self._ao_receber
        self.cliente.reconnect_delay_set(min_delay=1, max_delay=30)
        self.cliente.connect_async(broker, porta, keepalive=30)
        self.cliente.loop_start()

    def _ao_conectar(self, cliente, _ud, _flags, codigo, _props=None):
        if getattr(codigo, "is_failure", False):
            log("conexao_recusada", dispositivo=self.cn, motivo=str(codigo))
            return
        self.conectado = True
        cliente.subscribe(f"dispositivos/{self.cn}/comando", qos=1)
        log("conectado_mtls", dispositivo=self.cn)

    def _ao_desconectar(self, _cliente, _ud, _flags, codigo, _props=None):
        self.conectado = False
        log("desconectado", dispositivo=self.cn, motivo=str(codigo))

    def _ao_receber(self, _cliente, _ud, msg):
        try:
            comando = json.loads(msg.payload.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return
        if isinstance(comando, dict):
            self.ao_comando(comando)

    def publicar(self, metrica: str, valor: float, unidade: str, extra: dict | None = None) -> None:
        leitura = {
            "id": str(uuid.uuid4()),
            "espaco": self.espaco,
            "dispositivo": self.cn,
            "metrica": metrica,
            "valor": round(float(valor), 3),
            "unidade": unidade,
            "ts": agora_iso(),
        }
        if extra:
            leitura["extra"] = extra
        self.cliente.publish(f"dispositivos/{self.cn}/telemetria", json.dumps(leitura, ensure_ascii=False), qos=1)

    def ao_comando(self, comando: dict) -> None:
        pass

    def tick(self, mundo: dict) -> None:
        raise NotImplementedError


class Faixa(Dispositivo):
    """Sensor cuja leitura oscila dentro de uma faixa normal (passeio aleatório com retorno ao centro)."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.valores = {m["nome"]: float(m["inicial"]) for m in self.cfg["metricas"]}

    def tick(self, mundo):
        for m in self.cfg["metricas"]:
            v = self.valores[m["nome"]]
            falha = m.get("cenario")
            if falha and cenario_ativo(falha["nome"]):
                v += falha["deriva"]
                v = min(v, falha["limite"]) if falha["deriva"] > 0 else max(v, falha["limite"])
            elif v > m["max"] or v < m["min"]:
                v += -2 * m["passo"] if v > m["max"] else 2 * m["passo"]   # recuperação gradual
            else:
                centro = (m["min"] + m["max"]) / 2
                v += random.uniform(-m["passo"], m["passo"]) + (centro - v) * 0.05
                v = max(m["min"], min(m["max"], v))
            self.valores[m["nome"]] = v
            self.publicar(m["nome"], v, m["unidade"])


class Bomba(Dispositivo):
    """Atuador: bomba de recalque. Só muda de estado por comando recebido do agente de borda."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.ligada = False

    def ao_comando(self, comando):
        acao = comando.get("acao")
        if acao in ("ligar", "desligar"):
            self.ligada = acao == "ligar"
            log("atuador_comando", dispositivo=self.cn, acao=acao, origem=comando.get("origem"))
            self.publicar("estado", 1 if self.ligada else 0, "ligada", {"origem": str(comando.get("origem"))[:80]})

    def tick(self, mundo):
        self.publicar("estado", 1 if self.ligada else 0, "ligada")


class Reservatorio(Dispositivo):
    """Nível do reservatório: sobe com a bomba ligada e desce com o consumo."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.nivel = float(self.cfg["inicial"])

    def tick(self, mundo):
        bomba = mundo.get(self.cfg["bomba"])
        consumo = self.cfg["consumo"]
        if cenario_ativo(self.cfg.get("cenario_vazamento")):
            consumo += self.cfg["vazamento"]
        self.nivel -= consumo * random.uniform(0.7, 1.3)
        if bomba is not None and bomba.ligada:
            self.nivel += self.cfg["enchimento"]
        self.nivel = max(0.0, min(100.0, self.nivel))
        self.publicar("nivel", self.nivel, "%")


class Fechadura(Dispositivo):
    """Fechadura eletrônica RFID/QR. O crachá é sempre um pseudônimo sintético (LGPD)."""

    CRACHAS = [f"vol-{i:03d}" for i in range(1, 13)]

    def tick(self, mundo):
        if random.random() < self.cfg.get("probabilidade", 0.15):
            permitido = random.random() > 0.08
            self.publicar("acesso", 1 if permitido else 0, "evento", {
                "cracha": random.choice(self.CRACHAS),
                "metodo": random.choice(["rfid", "qr"]),
                "resultado": "permitido" if permitido else "negado",
            })


MODELOS = {"faixa": Faixa, "bomba": Bomba, "reservatorio": Reservatorio, "fechadura": Fechadura}


def main() -> None:
    try:
        espaco = os.environ["ESPACO"]
        broker = os.environ["BROKER_HOST"]
    except KeyError as exc:
        sys.exit(f"variável de ambiente obrigatória ausente: {exc}")
    porta = int(os.environ.get("BROKER_PORTA", "8883"))
    intervalo = float(os.environ.get("INTERVALO_S", "5"))
    pki_pub = Path(os.environ.get("PKI_PUBLICO", "/pki/publico"))
    pki_dev = Path(os.environ.get("PKI_DISPOSITIVOS", "/pki/dispositivos"))
    cfg_dir = Path(os.environ.get("DISPOSITIVOS_DIR", "/app/dispositivos"))

    cfg = json.loads((cfg_dir / f"{espaco}.json").read_text(encoding="utf-8"))
    mundo = {
        d["cn"]: MODELOS[d["modelo"]](d, espaco, broker, porta, pki_pub, pki_dev)
        for d in cfg["dispositivos"]
    }
    log("simulador_iniciado", dispositivos=sorted(mundo), broker=broker)
    try:
        while True:
            for dispositivo in mundo.values():
                if dispositivo.conectado:
                    dispositivo.tick(mundo)
            time.sleep(intervalo)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
