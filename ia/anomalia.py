"""IA defensiva: detecção de anomalias na telemetria com Isolation Forest (RT-16).

Aprende o comportamento NORMAL dos sensores da Vila Aurora e sinaliza leituras atípicas
(câmara fria esquentando, reservatório esvaziando rápido, alagamento, bateria despencando).
O desempenho é medido contra um conjunto rotulado: precisão, revocação e taxa de falsos positivos.

Uso:
    python anomalia.py              # treina com dados sintéticos rotulados e imprime as métricas
    python anomalia.py --banco      # além disso, pontua a telemetria real já gravada na nuvem
"""
import json
import sys

import numpy as np
from sklearn.ensemble import IsolationForest

# Sensores usados como atributos (faixa normal de operação de cada um)
SENSORES = [
    ("ubs-camara-fria.temperatura", 2.0, 8.0),
    ("escola-reservatorio.nivel", 20.0, 90.0),
    ("escola-qualidade-agua.cloro", 0.2, 2.0),
    ("abrigo-alagamento.nivel_agua", 0.0, 10.0),
    ("abrigo-ar.co2", 400.0, 1200.0),
    ("centro-energia.bateria", 30.0, 100.0),
]
NOMES = [s[0] for s in SENSORES]


def _normal(n: int, rng: np.random.Generator) -> np.ndarray:
    """n amostras com todos os sensores dentro da faixa (ruído suave em torno do centro)."""
    linhas = []
    for _ in range(n):
        linha = []
        for _, lo, hi in SENSORES:
            centro = (lo + hi) / 2
            amp = (hi - lo) / 2
            linha.append(np.clip(rng.normal(centro, amp * 0.33), lo, hi))
        linhas.append(linha)
    return np.array(linhas)


def _anomalo(n: int, rng: np.random.Generator) -> np.ndarray:
    """n amostras em que 1 a 2 sensores saem da faixa (como nas falhas do cenário)."""
    base = _normal(n, rng)
    for linha in base:
        for idx in rng.choice(len(SENSORES), size=rng.integers(1, 3), replace=False):
            _, lo, hi = SENSORES[idx]
            margem = (hi - lo)
            linha[idx] = hi + rng.uniform(0.2, 1.2) * margem if rng.random() < 0.5 \
                else lo - rng.uniform(0.2, 1.2) * margem
    return base


def gerar(seed: int = 42):
    rng = np.random.default_rng(seed)
    treino = _normal(1500, rng)                       # treino: só comportamento normal
    teste_normal = _normal(400, rng)
    teste_anomalo = _anomalo(120, rng)
    X_teste = np.vstack([teste_normal, teste_anomalo])
    y_teste = np.r_[np.zeros(len(teste_normal)), np.ones(len(teste_anomalo))]   # 1 = anomalia
    return treino, X_teste, y_teste


class Detector:
    def __init__(self, contaminacao: float = 0.08, seed: int = 42):
        self.modelo = IsolationForest(n_estimators=200, contamination=contaminacao,
                                      random_state=seed, n_jobs=1)

    def treinar(self, X):
        self.modelo.fit(X)
        return self

    def prever(self, X) -> np.ndarray:
        return (self.modelo.predict(X) == -1).astype(int)   # -1 = outlier -> 1 = anomalia


def metricas(y, yhat) -> dict:
    vp = int(np.sum((yhat == 1) & (y == 1)))
    fp = int(np.sum((yhat == 1) & (y == 0)))
    fn = int(np.sum((yhat == 0) & (y == 1)))
    vn = int(np.sum((yhat == 0) & (y == 0)))
    precisao = vp / (vp + fp) if vp + fp else 0.0
    revocacao = vp / (vp + fn) if vp + fn else 0.0
    taxa_fp = fp / (fp + vn) if fp + vn else 0.0
    f1 = 2 * precisao * revocacao / (precisao + revocacao) if precisao + revocacao else 0.0
    return {"vp": vp, "fp": fp, "fn": fn, "vn": vn, "precisao": precisao,
            "revocacao": revocacao, "taxa_fp": taxa_fp, "f1": f1}


def avaliar(seed: int = 42) -> dict:
    treino, X_teste, y_teste = gerar(seed)
    det = Detector(seed=seed).treinar(treino)
    return metricas(y_teste, det.prever(X_teste))


def _pct(x):
    return f"{x * 100:.1f}%".replace(".", ",")


def principal():
    m = avaliar()
    print("=== IA defensiva — detecção de anomalias (Isolation Forest) ===")
    print(f"Atributos (sensores): {len(SENSORES)}")
    print(f"Treino: 1500 leituras normais   |   Teste: 400 normais + 120 anômalas\n")
    print(f"  Verdadeiros positivos (anomalia detectada) : {m['vp']}")
    print(f"  Falsos negativos (anomalia não vista)      : {m['fn']}")
    print(f"  Falsos positivos (alarme à toa)            : {m['fp']}")
    print(f"  Verdadeiros negativos (normal, sem alarme) : {m['vn']}\n")
    print(f"  Precisão           : {_pct(m['precisao'])}")
    print(f"  Revocação (recall) : {_pct(m['revocacao'])}")
    print(f"  Taxa de falsos pos.: {_pct(m['taxa_fp'])}")
    print(f"  F1                 : {_pct(m['f1'])}")

    if "--banco" in sys.argv:
        pontuar_banco()


def pontuar_banco():
    import os
    try:
        import psycopg2
    except ModuleNotFoundError:
        print("\n(psycopg2 ausente: pulei a telemetria real.)")
        return
    dsn = dict(host=os.environ.get("DB_HOST", "nuvem-db"), port=int(os.environ.get("DB_PORTA", "5432")),
               dbname=os.environ.get("DB_NOME", "vilaaurora"), user="painel_app",
               password=os.environ["PAINEL_DB_SENHA"], connect_timeout=5)
    consulta = """
        SELECT dispositivo || '.' || metrica AS chave, valor
          FROM leituras WHERE ts > now() - interval '2 hours'"""
    conexao = psycopg2.connect(**dsn)
    try:
        with conexao.cursor() as cur:
            cur.execute(consulta)
            linhas = cur.fetchall()
    finally:
        conexao.close()
    ultimos = {}
    for chave, valor in linhas:
        if chave in NOMES:
            ultimos.setdefault(chave, []).append(float(valor))
    print(f"\n=== Telemetria real das últimas 2 h: {len(linhas)} leituras ===")
    for nome, _, _ in SENSORES:
        vals = ultimos.get(nome, [])
        if vals:
            print(f"  {nome:<34} {len(vals):>4} leituras   média {np.mean(vals):.1f}")


if __name__ == "__main__":
    principal()
