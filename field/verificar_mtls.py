"""Evidência de mTLS (RT-04): o broker da borda só aceita cliente com certificado válido.

Uso (dentro do container do espaço):
    python verificar_mtls.py
"""
import os
import ssl
import sys
import time
from pathlib import Path

import paho.mqtt.client as mqtt

BROKER = os.environ["BROKER_HOST"]
PORTA = int(os.environ.get("BROKER_PORTA", "8883"))
PUB = Path(os.environ.get("PKI_PUBLICO", "/pki/publico"))
DEV = Path(os.environ.get("PKI_DISPOSITIVOS", "/pki/dispositivos"))


def tentar(descricao: str, certificado: Path | None) -> bool:
    resultado = {"ok": False}

    def ao_conectar(_c, _u, _f, codigo, _p=None):
        resultado["ok"] = not getattr(codigo, "is_failure", False)

    cliente = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"verificacao-{int(time.time())}")
    if certificado is None:
        cliente.tls_set(ca_certs=str(PUB / "ca.crt"), cert_reqs=ssl.CERT_REQUIRED)
    else:
        cliente.tls_set(ca_certs=str(PUB / "ca.crt"), certfile=str(certificado),
                        keyfile=str(certificado.with_suffix(".key")), cert_reqs=ssl.CERT_REQUIRED)
    cliente.on_connect = ao_conectar
    try:
        cliente.connect(BROKER, PORTA, keepalive=10)
        fim = time.time() + 5
        while time.time() < fim and not resultado["ok"]:
            if cliente.loop(timeout=0.5) != mqtt.MQTT_ERR_SUCCESS:
                break
    except (ssl.SSLError, OSError) as exc:
        print(f"    detalhe: {type(exc).__name__}: {exc}")
    finally:
        try:
            cliente.disconnect()
        except Exception:
            pass
    print(f"[{'ACEITO   ' if resultado['ok'] else 'REJEITADO'}] {descricao}")
    return resultado["ok"]


def main() -> None:
    certificados = sorted(DEV.glob("*.crt"))
    if not certificados:
        sys.exit("nenhum certificado de dispositivo encontrado")
    print(f"Broker: {BROKER}:{PORTA}  (TLS com autenticação mútua)\n")
    sem = tentar("cliente SEM certificado", None)
    com = tentar(f"cliente COM certificado válido ({certificados[0].stem})", certificados[0])
    print()
    if not sem and com:
        print("RESULTADO: mTLS efetivo — só entra quem apresenta certificado emitido pela CA do projeto.")
    else:
        print("RESULTADO: comportamento inesperado — revise a configuração do broker.")
        sys.exit(1)


if __name__ == "__main__":
    main()
