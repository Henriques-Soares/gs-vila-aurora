"""Buffer store-and-forward do nó de borda (RT-02).

Tudo o que a borda observa ou decide é gravado primeiro em disco (SQLite).
O envio para a nuvem acontece depois, em lotes; se o link cair, os eventos
ficam pendentes e são reconciliados quando a conexão volta.
"""
import json
import sqlite3
import threading
import time


class Buffer:
    def __init__(self, caminho: str):
        self._db = sqlite3.connect(caminho, check_same_thread=False, isolation_level=None)
        self._trava = threading.Lock()
        with self._trava:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=NORMAL")
            self._db.execute(
                """CREATE TABLE IF NOT EXISTS fila (
                       id         TEXT PRIMARY KEY,
                       tipo       TEXT NOT NULL,
                       dados      TEXT NOT NULL,
                       criado_em  REAL NOT NULL,
                       estado     TEXT NOT NULL DEFAULT 'pendente',
                       fechado_em REAL
                   )"""
            )
            self._db.execute("CREATE INDEX IF NOT EXISTS fila_estado ON fila (estado, criado_em)")

    def guardar(self, tipo: str, dados: dict) -> None:
        with self._trava:
            self._db.execute(
                "INSERT OR IGNORE INTO fila (id, tipo, dados, criado_em) VALUES (?, ?, ?, ?)",
                (dados["id"], tipo, json.dumps(dados, ensure_ascii=False), time.time()),
            )

    def proximos(self, limite: int) -> list[dict]:
        with self._trava:
            linhas = self._db.execute(
                "SELECT id, tipo, dados FROM fila WHERE estado = 'pendente' ORDER BY criado_em LIMIT ?",
                (limite,),
            ).fetchall()
        return [{"id": i, "tipo": t, "dados": json.loads(d)} for i, t, d in linhas]

    def marcar(self, ids: list[str], estado: str) -> None:
        if not ids:
            return
        agora = time.time()
        with self._trava:
            self._db.execute("BEGIN")
            self._db.executemany(
                "UPDATE fila SET estado = ?, fechado_em = ? WHERE id = ?",
                [(estado, agora, i) for i in ids],
            )
            self._db.execute("COMMIT")

    def contagem(self) -> dict:
        with self._trava:
            linhas = self._db.execute("SELECT estado, COUNT(*) FROM fila GROUP BY estado").fetchall()
        totais = {"pendente": 0, "enviado": 0, "rejeitado": 0}
        totais.update(dict(linhas))
        return totais

    def limpar(self, reter_s: float) -> int:
        """Remove eventos já entregues há mais de `reter_s` segundos. Pendentes nunca são removidos."""
        with self._trava:
            cur = self._db.execute(
                "DELETE FROM fila WHERE estado != 'pendente' AND fechado_em < ?",
                (time.time() - reter_s,),
            )
            return cur.rowcount
