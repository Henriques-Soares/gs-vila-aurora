"""Persistência do SIEM no PostgreSQL (papel siem_rw, privilégio mínimo).

Todo o SQL fica nas constantes abaixo (sempre parametrizado), o que permite validá-lo
contra um PostgreSQL real nos testes.
"""
import json
import os

# Comandos de atuador já centralizados pelo túnel. O id da tabela `comandos` é UUID,
# então a leitura incremental usa um cursor (recebido_em, id). A folga de 3 s evita
# perder uma transação da ingestão que começou antes, mas ainda não terminou.
SQL_CURSOR_INICIAL = "SELECT now() - interval '3 seconds'"
SQL_NOVOS_COMANDOS = """
    SELECT recebido_em, id, ts, espaco, dispositivo, acao, origem, agente
      FROM comandos
     WHERE (recebido_em, id) > (%(cur_ts)s, %(cur_id)s::uuid)
       AND recebido_em < now() - interval '3 seconds'
     ORDER BY recebido_em, id
     LIMIT %(limite)s"""
CURSOR_ID_INICIAL = "ffffffff-ffff-ffff-ffff-ffffffffffff"   # pula tudo o que já existia no instante inicial

SQL_EVENTO = """
    INSERT INTO eventos_seg (ts, fonte, nivel, evento, origem, dados)
    VALUES (%(ts)s, %(fonte)s, %(nivel)s, %(evento)s, %(origem)s, %(dados)s)"""
SQL_ALERTA = """
    INSERT INTO alertas_seg (regra, severidade, titulo, detalhe, fonte, origem, tecnica, resposta)
    VALUES (%(regra)s, %(severidade)s, %(titulo)s, %(detalhe)s, %(fonte)s, %(origem)s, %(tecnica)s, %(resposta)s)"""
SQL_QUARENTENA = """
    INSERT INTO quarentena (origem, regra, motivo) VALUES (%(origem)s, %(regra)s, %(motivo)s)
    ON CONFLICT (origem) DO NOTHING"""
SQL_ACAO = """
    INSERT INTO acoes_seg (acao, alvo, motivo, severidade)
    SELECT %(acao)s, %(alvo)s, %(motivo)s, %(sev)s
     WHERE NOT EXISTS (SELECT 1 FROM acoes_seg
                        WHERE acao = %(acao)s AND alvo = %(alvo)s AND status = 'pendente')"""
SQL_RETENCAO = "DELETE FROM eventos_seg WHERE recebido_em < now() - make_interval(days => %(dias)s)"


class Postgres:
    def __init__(self):
        import psycopg2
        self._psycopg2 = psycopg2
        self._dsn = dict(
            host=os.environ.get("DB_HOST", "nuvem-db"), port=int(os.environ.get("DB_PORTA", "5432")),
            dbname=os.environ.get("DB_NOME", "vilaaurora"), user="siem_rw",
            password=os.environ["SIEM_DB_SENHA"], connect_timeout=5, options="-c statement_timeout=5000",
        )

    def _executar(self, sql: str, params=None, buscar: str | None = None):
        conexao = self._psycopg2.connect(**self._dsn)
        try:
            with conexao, conexao.cursor() as cur:
                cur.execute(sql, params)
                if buscar == "um":
                    return cur.fetchone()
                if buscar == "todos":
                    return cur.fetchall()
                return cur.rowcount
        finally:
            conexao.close()

    def gravar_evento(self, ev: dict) -> None:
        self._executar(SQL_EVENTO, {
            "ts": ev["ts"], "fonte": ev["fonte"], "nivel": ev.get("nivel"), "evento": ev["evento"],
            "origem": ev.get("origem"), "dados": json.dumps(ev.get("dados"), ensure_ascii=False)})

    def gravar_alerta(self, a: dict) -> None:
        self._executar(SQL_ALERTA, a)

    def quarentenar(self, origem: str, regra: str, motivo: str) -> None:
        self._executar(SQL_QUARENTENA, {"origem": origem, "regra": regra, "motivo": motivo})

    def enfileirar_acao(self, acao: str, alvo: str, motivo: str, severidade: str) -> bool:
        """Cria uma ação pendente, sem duplicar enquanto houver uma igual não decidida."""
        return self._executar(SQL_ACAO, {"acao": acao, "alvo": alvo, "motivo": motivo, "sev": severidade}) == 1

    def cursor_inicial(self) -> tuple:
        return (self._executar(SQL_CURSOR_INICIAL, buscar="um")[0], CURSOR_ID_INICIAL)

    def novos_comandos(self, cursor: tuple, limite: int = 200) -> list[tuple]:
        return self._executar(SQL_NOVOS_COMANDOS,
                              {"cur_ts": cursor[0], "cur_id": str(cursor[1]), "limite": limite}, buscar="todos")

    def limpar(self, reter_dias: int) -> int:
        return self._executar(SQL_RETENCAO, {"dias": reter_dias})
