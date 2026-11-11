"""Painel de supervisão — Rede Comunitária Vila Aurora (versão corrigida).

Nesta fase o painel é somente leitura. Ele acessa o banco com o papel `painel_ro`
(apenas SELECT) e usa exclusivamente consultas parametrizadas.
Login com MFA e perfis de acesso (RBAC) entram na Fase 3.
"""
import os
from datetime import datetime, timezone

from flask import Flask, render_template, request

app = Flask(__name__)

ESPACOS = {
    "centro": "Centro Comunitário",
    "escola": "Escola Municipal",
    "ubs": "Unidade Básica de Saúde (UBS)",
    "horta": "Horta e Cozinha Solidária",
    "abrigo": "Abrigo de Emergência",
}
DISPOSITIVOS = {
    "camara-fria": "Câmara fria de vacinas", "fechadura": "Fechadura eletrônica", "energia": "Energia",
    "reservatorio": "Reservatório de água", "bomba": "Bomba de água", "qualidade-agua": "Qualidade da água",
    "ambiente": "Ambiente", "alagamento": "Sensor de alagamento", "ar": "Qualidade do ar",
}
METRICAS = {
    "temperatura": "Temperatura", "nivel": "Nível", "estado": "Estado", "acesso": "Último acesso",
    "turbidez": "Turbidez", "cloro": "Cloro residual", "umidade": "Umidade", "co2": "CO₂",
    "bateria": "Bateria", "consumo": "Consumo", "geracao_solar": "Geração solar", "nivel_agua": "Lâmina d'água",
}
SEVERIDADES = {"critico": "Crítico", "alto": "Atenção", "info": "Informativo"}
ATRASO_ALERTA_S = 60   # sem dados novos há mais que isso = borda sem conexão com a nuvem

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


def consultar() -> tuple[list, list, list, int]:
    """Lê o banco com o papel somente-leitura. Todas as consultas são parametrizadas."""
    import psycopg2
    conexao = psycopg2.connect(
        host=os.environ.get("DB_HOST", "nuvem-db"), port=int(os.environ.get("DB_PORTA", "5432")),
        dbname=os.environ.get("DB_NOME", "vilaaurora"), user="painel_ro",
        password=os.environ["PAINEL_DB_SENHA"], connect_timeout=5,
        options="-c default_transaction_read_only=on -c statement_timeout=5000",
    )
    try:
        with conexao, conexao.cursor() as cur:
            cur.execute(SQL_ULTIMAS, {"dias": 7})
            ultimas = cur.fetchall()
            cur.execute(SQL_SINCRONIA)
            sincronia = cur.fetchall()
            cur.execute(SQL_ALARMES, {"limite": 15})
            alarmes = cur.fetchall()
            cur.execute(SQL_ATIVOS)
            ativos = cur.fetchone()[0]
    finally:
        conexao.close()
    return ultimas, sincronia, alarmes, ativos


def nome_dispositivo(cn: str) -> str:
    sufixo = cn.split("-", 1)[1] if "-" in cn else cn
    return DISPOSITIVOS.get(sufixo, cn)


def formatar(dispositivo: str, metrica: str, valor: float, unidade: str) -> str:
    if metrica == "estado":
        return "Ligada" if valor >= 1 else "Desligada"
    if metrica == "acesso":
        return "Permitido" if valor >= 1 else "Negado"
    casas = 0 if unidade == "ppm" else 1
    return f"{valor:.{casas}f}".replace(".", ",") + f" {unidade}"


def ha_quanto(instante: datetime, agora: datetime) -> str:
    s = max(0, int((agora - instante).total_seconds()))
    if s < 60:
        return f"há {s} s"
    if s < 3600:
        return f"há {s // 60} min"
    return f"há {s // 3600} h"


def montar(ultimas, sincronia, alarmes, ativos: int, agora: datetime) -> dict:
    recebido = dict(sincronia)
    espacos = []
    for chave, nome in ESPACOS.items():
        # agrupa as medições por equipamento, na ordem em que vieram do banco
        equipamentos: dict[str, dict] = {}
        for e, d, m, v, u, ts in ultimas:
            if e != chave:
                continue
            eq = equipamentos.setdefault(d, {"nome": nome_dispositivo(d), "medicoes": [], "ts": ts})
            eq["medicoes"].append({"metrica": METRICAS.get(m, m), "valor": formatar(d, m, v, u)})
            eq["ts"] = max(eq["ts"], ts)
        for eq in equipamentos.values():
            eq["quando"] = ha_quanto(eq.pop("ts"), agora)

        ultimo = recebido.get(chave)
        if ultimo is None:
            situacao, rotulo = "sem-dados", "Sem dados"
            detalhe = "Ainda não recebemos dados deste espaço."
        elif (agora - ultimo).total_seconds() > ATRASO_ALERTA_S:
            situacao, rotulo = "sem-conexao", "Sem internet"
            detalhe = (f"Sem conexão com a nuvem {ha_quanto(ultimo, agora)}. O espaço continua "
                       "funcionando sozinho e enviará os dados quando a internet voltar.")
        else:
            situacao, rotulo = "ok", "Conectado"
            detalhe = f"Última atualização {ha_quanto(ultimo, agora)}."
        espacos.append({"nome": nome, "situacao": situacao, "rotulo": rotulo, "detalhe": detalhe,
                        "equipamentos": list(equipamentos.values())})
    lista_alarmes = [
        {"espaco": ESPACOS.get(e, e), "dispositivo": nome_dispositivo(d), "severidade": sev,
         "rotulo": SEVERIDADES.get(sev, sev), "estado": est, "mensagem": msg,
         "quando": ts.astimezone().strftime("%d/%m às %H:%M:%S")}
        for e, d, sev, est, msg, _valor, ts in alarmes
    ]
    resumo = {"conectados": sum(1 for e in espacos if e["situacao"] == "ok"), "total": len(espacos),
              "ativos": ativos}
    return {"espacos": espacos, "alarmes": lista_alarmes, "resumo": resumo}


@app.after_request
def cabecalhos_de_seguranca(resposta):
    resposta.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'"
    resposta.headers["X-Content-Type-Options"] = "nosniff"
    resposta.headers["X-Frame-Options"] = "DENY"
    resposta.headers["Referrer-Policy"] = "no-referrer"
    resposta.headers["Cache-Control"] = "no-store"
    return resposta


@app.get("/")
def inicio():
    auto = request.args.get("auto") == "1"
    try:
        dados = montar(*consultar(), datetime.now(timezone.utc))
        erro = None
    except Exception:
        app.logger.exception("falha ao consultar o banco")
        dados = {"espacos": [], "alarmes": [], "resumo": None}
        erro = "Não foi possível carregar os dados agora. Tente novamente em instantes."
    return render_template("index.html", auto=auto, erro=erro,
                           agora=datetime.now().astimezone().strftime("%d/%m/%Y %H:%M:%S"), **dados)


@app.get("/saude")
def saude():
    return {"ok": True}
