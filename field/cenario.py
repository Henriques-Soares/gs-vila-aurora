"""Liga/desliga cenários de falha do simulador (para demonstrações e testes).

Uso (dentro do container do espaço):
    python cenario.py listar
    python cenario.py ligar camara_fria_falha
    python cenario.py desligar camara_fria_falha
"""
import os
import sys
from pathlib import Path

CENARIOS = Path(os.environ.get("CENARIOS_DIR", "/tmp/cenarios"))
CONHECIDOS = {
    "camara_fria_falha": "UBS: a câmara fria de vacinas começa a esquentar",
    "alagamento": "Abrigo: a lâmina d'água sobe",
    "vazamento": "Escola: o reservatório esvazia mais rápido do que a bomba enche",
}


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in ("listar", "ligar", "desligar"):
        sys.exit(__doc__)
    CENARIOS.mkdir(parents=True, exist_ok=True)
    if sys.argv[1] == "listar":
        for nome, descricao in CONHECIDOS.items():
            estado = "LIGADO   " if (CENARIOS / nome).exists() else "desligado"
            print(f"{estado}  {nome:<20} {descricao}")
        return
    if len(sys.argv) < 3 or sys.argv[2] not in CONHECIDOS:
        sys.exit("cenários disponíveis: " + ", ".join(CONHECIDOS))
    alvo = CENARIOS / sys.argv[2]
    if sys.argv[1] == "ligar":
        alvo.touch()
        print(f"cenário ligado: {sys.argv[2]}")
    else:
        alvo.unlink(missing_ok=True)
        print(f"cenário desligado: {sys.argv[2]}")


if __name__ == "__main__":
    main()
