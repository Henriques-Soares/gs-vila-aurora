"""Acesso ao banco do painel.

Conecta com o papel `painel_app` (privilégio mínimo) e usa SOMENTE consultas
parametrizadas: nenhum valor vindo do navegador é concatenado em SQL.
"""
import os
from contextlib import contextmanager

SQL_ULTIMAS = """
    SELECT DISTINCT ON (espaco, dispositivo, metrica)
           espaco, dispositivo, metrica, valor, unidade, ts
      FROM leituras
     WHERE ts > now() - make_interval(days => %(dias)s)
     ORDER BY espaco, dispositivo, metrica, ts DESC"""
SQL_SINCRONIA = "SELECT espaco, max(recebido_em) FROM leituras GROUP BY espaco"
SQL_ALARMES = """
    SELECT espaco, dispositivo, severidade, estado, mensagem, valor, ts
      FROM alarmes ORDER BY ts DESC LIMIT %(limite)s"""
SQL_ATIVOS = """
    SELECT count(*) FROM (
        SELECT DISTINCT ON (espaco, regra) estado
          FROM alarmes ORDER BY espaco, regra, ts DESC) ultimo
     WHERE estado = 'ativo'"""
SQL_COMANDOS = """
    SELECT ts, espaco, dispositivo, acao, origem
      FROM comandos ORDER BY ts DESC LIMIT %(limite)s"""
SQL_AUDITORIA = """
    SELECT ts, usuario, perfil, acao, resultado, detalhe, origem
      FROM auditoria ORDER BY ts DESC LIMIT %(limite)s"""
SQL_ALERTAS_SEG = """
    SELECT ts, regra, severidade, titulo, detalhe, origem, tecnica, resposta
      FROM alertas_seg ORDER BY ts DESC, id DESC LIMIT %(limite)s"""
SQL_ACOES_SEG = """
    SELECT id, criada_em, acao, alvo, motivo, severidade, status, decidida_em, decidida_por
      FROM acoes_seg ORDER BY (status = 'pendente') DESC, criada_em DESC LIMIT %(limite)s"""
SQL_QUARENTENA = "SELECT origem, desde, regra, motivo FROM quarentena ORDER BY desde DESC"
# Só decide o que ainda está pendente: uma ação já aprovada ou recusada não muda mais.
SQL_DECIDIR_ACAO = """
    UPDATE acoes_seg
       SET status = %(status)s, decidida_em = now(), decidida_por = %(usuario)s
     WHERE id = %(id)s AND status = 'pendente'
 RETURNING acao, alvo"""
SQL_USUARIO = """
    SELECT usuario, nome, perfil, senha_hash, totp_segredo, totp_ativo, totp_ultimo_passo,
           falhas, bloqueado_ate, ativo
      FROM usuarios WHERE usuario = %(usuario)s"""
CAMPOS_USUARIO = ("usuario", "nome", "perfil", "senha_hash", "totp_segredo", "totp_ativo",
                  "totp_ultimo_passo", "falhas", "bloqueado_ate", "ativo")


class Banco:
    def __init__(self):
        import psycopg2  # importado aqui para os testes rodarem sem o driver
        self._psycopg2 = psycopg2
        self._dsn = dict(
            host=os.environ.get("DB_HOST", "nuvem-db"), port=int(os.environ.get("DB_PORTA", "5432")),
            dbname=os.environ.get("DB_NOME", "vilaaurora"), user="painel_app",
            password=os.environ["PAINEL_DB_SENHA"], connect_timeout=5,
            options="-c statement_timeout=5000",
        )

    @contextmanager
    def _cursor(self):
        conexao = self._psycopg2.connect(**self._dsn)
        try:
            with conexao, conexao.cursor() as cur:
                yield cur
        finally:
            conexao.close()

    # ------------------------------------------------------------- supervisão
    def painel(self):
        with self._cursor() as cur:
            cur.execute(SQL_ULTIMAS, {"dias": 7})
            ultimas = cur.fetchall()
            cur.execute(SQL_SINCRONIA)
            sincronia = cur.fetchall()
            cur.execute(SQL_ALARMES, {"limite": 15})
            alarmes = cur.fetchall()
            cur.execute(SQL_ATIVOS)
            ativos = cur.fetchone()[0]
        return ultimas, sincronia, alarmes, ativos

    def comandos(self, limite: int = 50):
        with self._cursor() as cur:
            cur.execute(SQL_COMANDOS, {"limite": limite})
            return cur.fetchall()

    def auditoria(self, limite: int = 100):
        with self._cursor() as cur:
            cur.execute(SQL_AUDITORIA, {"limite": limite})
            return cur.fetchall()

    # ---------------------------------------------------------------- SIEM
    def seguranca(self, limite: int = 40):
        with self._cursor() as cur:
            cur.execute(SQL_ALERTAS_SEG, {"limite": limite})
            alertas = cur.fetchall()
            cur.execute(SQL_ACOES_SEG, {"limite": limite})
            acoes = cur.fetchall()
            cur.execute(SQL_QUARENTENA)
            quarentena = cur.fetchall()
        return alertas, acoes, quarentena

    def decidir_acao(self, acao_id: int, status: str, usuario: str):
        """Devolve (acao, alvo) se decidiu agora, ou None se não estava mais pendente."""
        with self._cursor() as cur:
            cur.execute(SQL_DECIDIR_ACAO, {"id": acao_id, "status": status, "usuario": usuario})
            return cur.fetchone()

    # ------------------------------------------------------- contas e sessão
    def usuario(self, usuario: str) -> dict | None:
        with self._cursor() as cur:
            cur.execute(SQL_USUARIO, {"usuario": usuario})
            linha = cur.fetchone()
        return dict(zip(CAMPOS_USUARIO, linha)) if linha else None

    def registrar_falha(self, usuario: str, limite: int, bloqueio_min: int) -> None:
        with self._cursor() as cur:
            cur.execute(
                """UPDATE usuarios
                      SET falhas = falhas + 1,
                          bloqueado_ate = CASE WHEN falhas + 1 >= %(limite)s
                                               THEN now() + make_interval(mins => %(minutos)s)
                                               ELSE bloqueado_ate END
                    WHERE usuario = %(usuario)s""",
                {"usuario": usuario, "limite": limite, "minutos": bloqueio_min})

    def salvar_segredo(self, usuario: str, segredo: str) -> None:
        with self._cursor() as cur:
            cur.execute("UPDATE usuarios SET totp_segredo = %(s)s, totp_ativo = false WHERE usuario = %(u)s",
                        {"u": usuario, "s": segredo})

    def concluir_login(self, usuario: str, passo: int) -> None:
        """Segundo fator aceito: ativa o MFA, grava o passo usado (anti-replay) e zera as falhas."""
        with self._cursor() as cur:
            cur.execute(
                """UPDATE usuarios
                      SET totp_ativo = true, totp_ultimo_passo = %(passo)s, falhas = 0,
                          bloqueado_ate = NULL, ultimo_login = now()
                    WHERE usuario = %(usuario)s""",
                {"usuario": usuario, "passo": passo})

    def auditar(self, usuario, perfil, acao: str, resultado: str, detalhe=None, origem=None) -> None:
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO auditoria (usuario, perfil, acao, resultado, detalhe, origem)
                   VALUES (%(usuario)s, %(perfil)s, %(acao)s, %(resultado)s, %(detalhe)s, %(origem)s)""",
                {"usuario": usuario, "perfil": perfil, "acao": acao, "resultado": resultado,
                 "detalhe": detalhe, "origem": origem})
