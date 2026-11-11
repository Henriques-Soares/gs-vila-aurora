"""Evidência de segmentação de rede e VPN (RT-06 / RT-07).

Tenta abrir conexões TCP a partir deste container e compara com o esperado:
o que é necessário para a função deve ALCANÇAR; todo o resto deve ficar BLOQUEADO.

Uso:
    docker compose exec borda-ubs-agente python verificar_rede.py
"""
import os
import socket
import sys

ESPACO = os.environ["ESPACO"]
OUTRO = "escola" if ESPACO != "escola" else "ubs"
IP_TUNEL = {"centro": 11, "escola": 12, "ubs": 13, "horta": 14, "abrigo": 15}

# (descrição, host, porta, deve alcançar?)
TESTES = [
    ("broker da borda do próprio espaço (MQTT/mTLS)", f"borda-{ESPACO}-broker", 8883, True),
    ("ingestão da nuvem PELO TÚNEL WireGuard", "nuvem-ingest", 8443, True),
    ("ingestão da nuvem FORA do túnel (rede wan)", "nuvem-vpn", 8443, False),
    ("nó de borda de OUTRO espaço pelo túnel", f"10.8.0.{IP_TUNEL[OUTRO]}", 8443, False),
    ("broker da borda de OUTRO espaço", f"borda-{OUTRO}-broker", 8883, False),
    ("banco de dados da nuvem", "nuvem-db", 5432, False),
    ("painel de supervisão", "painel", 8080, False),
]


def alcanca(host: str, porta: int) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, porta), timeout=3):
            return True, "conexão aberta"
    except socket.gaierror:
        return False, "nome não existe neste segmento"
    except (TimeoutError, socket.timeout):
        return False, "sem resposta (tempo esgotado)"
    except OSError as exc:
        return False, exc.strerror or type(exc).__name__


def main() -> None:
    print(f"Origem: agente de borda do espaço '{ESPACO}'\n")
    falhas = 0
    for descricao, host, porta, esperado in TESTES:
        ok, detalhe = alcanca(host, porta)
        conforme = ok == esperado
        falhas += not conforme
        estado = "ALCANÇA  " if ok else "BLOQUEADO"
        print(f"[{estado}] {descricao:<58} {host}:{porta}  ({detalhe}){'' if conforme else '   <-- INESPERADO'}")
    print()
    if falhas:
        print(f"RESULTADO: {falhas} verificação(ões) fora do esperado — revise a segmentação.")
        sys.exit(1)
    print("RESULTADO: segmentação efetiva — só o caminho necessário está aberto (menor privilégio).")


if __name__ == "__main__":
    main()
