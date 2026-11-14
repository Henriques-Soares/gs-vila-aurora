"""Harness de teste controlado do SIEM — injeta eventos de segurança REPRESENTATIVOS
na coleta, para demonstrar as regras de detecção sem executar nenhum ataque real.

Uso (de dentro de um container que alcança o SIEM, ex.: painel):
    python simular.py acesso-invalido     # regras C e A (tentativas recusadas na nuvem)
    python simular.py sqli                 # regra B (assinatura de SQL Injection no painel)
    python simular.py comando-suspeito     # regra D (comando de atuador fora do perfil)
    python simular.py tudo
"""
import json
import os
import socket
import sys
import time

ALVO = os.environ.get("SIEM_ADDR", "siem:5514")
HOST, PORTA = ALVO.split(":")
PORTA = int(PORTA)


def enviar(ev: dict) -> None:
    ev.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(json.dumps(ev).encode("utf-8"), (HOST, PORTA))
    s.close()


def acesso_invalido() -> None:
    print("Injetando 6 tentativas recusadas da mesma origem (regra C em cada uma, regra A ao repetir)...")
    for i in range(6):
        enviar({"fonte": "nuvem-ingest", "nivel": "aviso", "evento": "conexao_tls_recusada",
                "origem": "10.8.0.77", "dados": {"motivo": "certificado revogado ou ausente"}})
        time.sleep(0.3)


def sqli() -> None:
    print("Injetando um evento de entrada suspeita vindo do painel (regra B)...")
    enviar({"fonte": "painel", "nivel": "aviso", "evento": "entrada_suspeita", "origem": "203.0.113.9",
            "dados": {"campo": "busca", "assinatura": "padrão de injeção"}})


def comando_suspeito() -> None:
    print("Injetando um comando de atuador cuja origem NÃO é uma regra local (regra D)...")
    enviar({"fonte": "agente-escola", "nivel": "aviso", "evento": "comando", "origem": "agente-escola",
            "dados": {"dispositivo": "escola-bomba", "acao": "desligar", "origem": "sessao-manual-externa",
                      "espaco": "escola"}})


if __name__ == "__main__":
    acao = sys.argv[1] if len(sys.argv) > 1 else ""
    if acao == "acesso-invalido":
        acesso_invalido()
    elif acao == "sqli":
        sqli()
    elif acao == "comando-suspeito":
        comando_suspeito()
    elif acao == "tudo":
        acesso_invalido(); time.sleep(1); sqli(); time.sleep(1); comando_suspeito()
    else:
        sys.exit(__doc__)
    print("Pronto. Veja os alertas com:  docker compose logs --since 2m siem")
