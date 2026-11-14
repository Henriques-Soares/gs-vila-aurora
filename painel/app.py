"""Painel de supervisão — Rede Comunitária Vila Aurora (versão corrigida).

Segurança de acesso (RT-09):
  - senha (hash scrypt) + segundo fator TOTP obrigatório para todos os perfis;
  - perfis de acesso (RBAC): operador, técnico, coordenação e auditor;
  - bloqueio temporário após tentativas erradas, proteção CSRF, sessão com expiração,
    trilha de auditoria de logins e acessos negados.
"""
import hmac
import json
import os
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (Flask, abort, g, redirect, render_template, request, session, url_for)
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

import totp
from dados import Banco

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("PAINEL_CHAVE_SESSAO") or secrets.token_hex(32),
    SESSION_COOKIE_NAME="va_sessao",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    # O laboratório publica o painel só em http://127.0.0.1. Atrás de HTTPS, defina PAINEL_COOKIE_SEGURO=1.
    SESSION_COOKIE_SECURE=os.environ.get("PAINEL_COOKIE_SEGURO") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),   # sessão expira após 30 min sem uso
    MAX_CONTENT_LENGTH=16 * 1024,
)

banco = None   # criado sob demanda (os testes injetam um substituto)

MAX_FALHAS = 5
BLOQUEIO_MIN = 5
VALIDADE_ETAPA_S = 300      # tempo para concluir o segundo fator depois da senha
RE_USUARIO = re.compile(r"^[a-z0-9._-]{3,40}$")
HASH_FALSO = generate_password_hash(secrets.token_hex(16))   # iguala o tempo de resposta de usuário inexistente

PERFIS = {"operador": "Operador(a)", "tecnico": "Técnico(a)", "coordenacao": "Coordenação", "auditor": "Auditor(a)"}
# Matriz de permissões (RBAC): cada perfil recebe só o que precisa para a sua função.
PERMISSOES = {
    "ver_painel":     {"rotulo": "Ver o painel e os avisos",                  "perfis": {"operador", "tecnico", "coordenacao", "auditor"}},
    "ver_comandos":   {"rotulo": "Ver os comandos enviados aos equipamentos", "perfis": {"tecnico", "coordenacao", "auditor"}},
    "ver_auditoria":  {"rotulo": "Ver o registro de acessos (auditoria)",     "perfis": {"coordenacao", "auditor"}},
    "ver_seguranca":  {"rotulo": "Ver os alertas de segurança (SIEM)",        "perfis": {"tecnico", "coordenacao", "auditor"}},
    "aprovar_acoes":  {"rotulo": "Aprovar ações de alto impacto",             "perfis": {"coordenacao"}},
}

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
ACOES = {"ligar": "Ligar", "desligar": "Desligar"}
ATRASO_ALERTA_S = 60   # sem dados novos há mais que isso = borda sem conexão com a nuvem


def bd() -> Banco:
    global banco
    if banco is None:
        banco = Banco()
    return banco


# --------------------------------------------------------------------- utilidades
def origem() -> str:
    return (request.remote_addr or "?")[:45]

import socket as _socket

_SIEM_ADDR = os.environ.get("SIEM_ADDR")


def _emitir_seguranca(registro: dict) -> None:
    if not _SIEM_ADDR:
        return
    try:
        host, porta = _SIEM_ADDR.split(":")
        with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as s:
            s.sendto(json.dumps(registro, ensure_ascii=False).encode("utf-8"), (host, int(porta)))
    except Exception:
        pass   # o SIEM é observabilidade; indisponível, não afeta a operação


# Detector de entrada maliciosa (WAF-like) — assinaturas defensivas de SQL Injection e XSS.
# Apenas DETECTA e RECUSA; as consultas do painel já são parametrizadas. Alimenta a regra B do SIEM.
import re as _re

_ASSINATURAS = [
    ("sql-union", _re.compile(r"union\s+select", _re.I)),
    ("sql-tautologia", _re.compile(r"""(\bor\b|\band\b)\s+['"]?\w+['"]?\s*=\s*['"]?\w+['"]?""", _re.I)),
    ("sql-comentario", _re.compile(r"(--|#|/\*)\s*$")),
    ("sql-empilhado", _re.compile(r";\s*(drop|delete|update|insert|alter)\b", _re.I)),
    ("xss-script", _re.compile(r"<\s*script", _re.I)),
]


# A senha nunca vai para SQL (é comparada com o hash) e pode ter qualquer caractere;
# o token CSRF é aleatório. Inspecioná-los só geraria falso positivo.
_CAMPOS_FORA_DO_DETECTOR = {"csrf", "senha"}


def _assinatura_suspeita(valor: str):
    if not isinstance(valor, str) or len(valor) > 2000:
        return None
    for nome, padrao in _ASSINATURAS:
        if padrao.search(valor):
            return nome
    return None


@app.before_request
def detector_entrada():
    """Inspeciona os valores recebidos; se baterem numa assinatura, registra, avisa o SIEM e recusa."""
    for campo, valor in list(request.args.items()) + list(request.form.items()):
        if campo in _CAMPOS_FORA_DO_DETECTOR:
            continue
        assinatura = _assinatura_suspeita(valor)
        if assinatura:
            conta = session.get("conta") or {}
            registro = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                        "fonte": "painel", "nivel": "aviso", "evento": "entrada_suspeita", "origem": origem(),
                        "dados": {"campo": campo, "assinatura": assinatura, "rota": request.path,
                                  "usuario": conta.get("usuario")}}
            app.logger.warning("entrada_suspeita: %s em %s", assinatura, campo)
            _emitir_seguranca(registro)
            try:
                auditar("entrada_suspeita", "recusado", f"{assinatura} em {campo}")
            except Exception:
                pass
            abort(400)


def auditar(acao: str, resultado: str, detalhe: str | None = None, usuario=None, perfil=None) -> None:
    conta = session.get("conta") or {}
    try:
        bd().auditar(usuario or conta.get("usuario"), perfil or conta.get("perfil"), acao, resultado, detalhe, origem())
    except Exception:
        app.logger.exception("falha ao gravar auditoria")


def token_csrf() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


@app.before_request
def proteger_formularios():
    """Todo POST precisa trazer o token CSRF da sessão."""
    if request.method == "POST":
        enviado = request.form.get("csrf", "")
        if not hmac.compare_digest(enviado, session.get("csrf", "")) or not enviado:
            abort(400)


@app.context_processor
def contexto_comum():
    conta = session.get("conta")
    pode = {p for p, d in PERMISSOES.items() if conta and conta["perfil"] in d["perfis"]}
    return {"conta": conta, "pode": pode, "csrf": token_csrf, "PERFIS": PERFIS,
            "agora": datetime.now().astimezone().strftime("%d/%m/%Y %H:%M:%S")}


def exige(permissao: str):
    """Controle de acesso por perfil (RBAC), verificado no servidor a cada requisição."""
    def decorador(funcao):
        @wraps(funcao)
        def protegida(*args, **kwargs):
            conta = session.get("conta")
            if not conta:
                return redirect(url_for("entrar"))
            if conta["perfil"] not in PERMISSOES[permissao]["perfis"]:
                auditar("acesso_negado", "negado", f"{request.path} exige {permissao}")
                abort(403)
            return funcao(*args, **kwargs)
        return protegida
    return decorador


def etapa_pendente() -> dict | None:
    pendente = session.get("pendente")
    if not pendente or time.time() - pendente["em"] > VALIDADE_ETAPA_S:
        session.pop("pendente", None)
        return None
    return pendente


def abrir_sessao(usuario: dict) -> None:
    session.clear()                     # nova sessão a cada login (evita fixação de sessão)
    session.permanent = True
    session["conta"] = {"usuario": usuario["usuario"], "nome": usuario["nome"], "perfil": usuario["perfil"]}


# ------------------------------------------------------------------- autenticação
@app.route("/entrar", methods=["GET", "POST"])
def entrar():
    if session.get("conta"):
        return redirect(url_for("inicio"))
    erro = None
    if request.method == "POST":
        nome = request.form.get("usuario", "").strip().lower()
        senha = request.form.get("senha", "")
        usuario = bd().usuario(nome) if RE_USUARIO.match(nome) else None
        bloqueado = bool(usuario and bloqueada(usuario))
        senha_ok = check_password_hash(usuario["senha_hash"] if usuario else HASH_FALSO, senha)
        if usuario and usuario["ativo"] and not bloqueado and senha_ok:
            session.clear()
            session["pendente"] = {"usuario": usuario["usuario"], "em": time.time()}
            return redirect(url_for("verificar" if usuario["totp_ativo"] else "configurar_mfa"))
        if usuario and not bloqueado:
            bd().registrar_falha(usuario["usuario"], MAX_FALHAS, BLOQUEIO_MIN)
        auditar("login", "bloqueado" if bloqueado else "falha", "senha", usuario=nome[:40] or None)
        # Mesma mensagem para usuário inexistente, senha errada ou conta bloqueada:
        # não revela quais contas existem.
        erro = (f"Usuário ou senha incorretos. Depois de {MAX_FALHAS} tentativas erradas, "
                f"a conta fica bloqueada por {BLOQUEIO_MIN} minutos.")
    return render_template("entrar.html", erro=erro), (401 if erro else 200)


MSG_BLOQUEIO = ("Conta bloqueada por alguns minutos por excesso de tentativas erradas. "
                "Aguarde e tente de novo, ou peça à coordenação para redefinir o acesso.")


def bloqueada(usuario: dict) -> bool:
    return bool(usuario["bloqueado_ate"] and usuario["bloqueado_ate"] > datetime.now(timezone.utc))


def _segundo_fator(usuario: dict, acao_auditoria: str) -> tuple[int | None, str | None]:
    """Confere o código TOTP enviado. Devolve (passo aceito, mensagem de erro)."""
    if bloqueada(usuario):      # senha já conferida nesta etapa: pode-se dizer que está bloqueada
        return None, MSG_BLOQUEIO
    passo = totp.verificar(usuario["totp_segredo"], request.form.get("codigo", ""), usuario["totp_ultimo_passo"])
    if passo is None:
        bd().registrar_falha(usuario["usuario"], MAX_FALHAS, BLOQUEIO_MIN)
        auditar(acao_auditoria, "falha", "código TOTP", usuario=usuario["usuario"], perfil=usuario["perfil"])
        return None, ("Código incorreto ou já utilizado. Confira se o código é o da conta "
                      f"“{usuario['usuario']}” no aplicativo e digite o que aparece agora.")
    return passo, None


@app.route("/verificar", methods=["GET", "POST"])
def verificar():
    pendente = etapa_pendente()
    usuario = bd().usuario(pendente["usuario"]) if pendente else None
    if not usuario or not usuario["totp_ativo"]:
        return redirect(url_for("entrar"))
    erro = None
    if request.method == "POST":
        passo, erro = _segundo_fator(usuario, "login")
        if passo is not None:
            bd().concluir_login(usuario["usuario"], passo)
            abrir_sessao(usuario)
            auditar("login", "sucesso", "senha + TOTP")
            return redirect(url_for("inicio"))
    return render_template("verificar.html", erro=erro), (401 if erro else 200)


@app.route("/mfa/configurar", methods=["GET", "POST"])
def configurar_mfa():
    """Primeiro acesso: cadastro obrigatório do segundo fator antes de entrar no painel."""
    pendente = etapa_pendente()
    usuario = bd().usuario(pendente["usuario"]) if pendente else None
    if not usuario or usuario["totp_ativo"]:
        return redirect(url_for("entrar"))
    erro = None
    if request.method == "POST" and usuario["totp_segredo"]:
        passo, erro = _segundo_fator(usuario, "mfa_cadastro")
        if passo is not None:
            bd().concluir_login(usuario["usuario"], passo)
            abrir_sessao(usuario)
            auditar("mfa_cadastrado", "sucesso")
            auditar("login", "sucesso", "senha + TOTP")
            return redirect(url_for("inicio"))
    if not usuario["totp_segredo"]:
        usuario["totp_segredo"] = totp.gerar_segredo()
        bd().salvar_segredo(usuario["usuario"], usuario["totp_segredo"])
    segredo = usuario["totp_segredo"]
    endereco = totp.uri(segredo, usuario["usuario"])
    try:
        import segno
        qr = segno.make(endereco, error="m").svg_inline(scale=5, border=2, dark="#17202e")
    except Exception:           # sem a biblioteca de QR, o cadastro manual continua funcionando
        qr = None
    chave = " ".join(segredo[i:i + 4] for i in range(0, len(segredo), 4))
    return render_template("mfa_configurar.html", erro=erro, qr=qr, chave=chave,
                           usuario=usuario["usuario"]), (401 if erro else 200)


@app.post("/sair")
def sair():
    auditar("logout", "sucesso")
    session.clear()
    return redirect(url_for("entrar"))


# --------------------------------------------------------------------- supervisão
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


def hora_local(instante: datetime) -> str:
    return instante.astimezone().strftime("%d/%m às %H:%M:%S")


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
         "rotulo": SEVERIDADES.get(sev, sev), "estado": est, "mensagem": msg, "quando": hora_local(ts)}
        for e, d, sev, est, msg, _valor, ts in alarmes
    ]
    resumo = {"conectados": sum(1 for e in espacos if e["situacao"] == "ok"), "total": len(espacos),
              "ativos": ativos}
    return {"espacos": espacos, "alarmes": lista_alarmes, "resumo": resumo}


@app.get("/")
@exige("ver_painel")
def inicio():
    auto = request.args.get("auto") == "1"
    try:
        dados = montar(*bd().painel(), datetime.now(timezone.utc))
        erro = None
    except Exception:
        app.logger.exception("falha ao consultar o banco")
        dados = {"espacos": [], "alarmes": [], "resumo": None}
        erro = "Não foi possível carregar os dados agora. Tente novamente em instantes."
    return render_template("index.html", auto=auto, erro=erro, **dados)


@app.get("/comandos")
@exige("ver_comandos")
def comandos():
    linhas = [
        {"quando": hora_local(ts), "espaco": ESPACOS.get(e, e), "dispositivo": nome_dispositivo(d),
         "acao": ACOES.get(acao, acao), "origem": origem_cmd}
        for ts, e, d, acao, origem_cmd in bd().comandos()
    ]
    return render_template("comandos.html", linhas=linhas)


@app.get("/auditoria")
@exige("ver_auditoria")
def auditoria():
    linhas = [
        {"quando": hora_local(ts), "usuario": u or "—", "perfil": PERFIS.get(p, p or "—"), "acao": acao,
         "resultado": resultado, "detalhe": detalhe or "", "origem": origem_ip or ""}
        for ts, u, p, acao, resultado, detalhe, origem_ip in bd().auditoria()
    ]
    return render_template("auditoria.html", linhas=linhas)


SEVERIDADES_SEG = {"critica": ("Crítica", "critico"), "alta": ("Alta", "alto"),
                   "media": ("Média", "info"), "baixa": ("Baixa", "info")}
REGRAS_SEG = {
    "A-acesso-nao-autorizado": "A · Acesso não autorizado repetido",
    "B-sql-injection": "B · Tentativa de SQL Injection",
    "C-credencial-invalida": "C · Credencial sem certificado válido",
    "D-comando-suspeito": "D · Comando de atuador fora do perfil",
}
ACOES_SEG = {"colocar_atuador_em_modo_seguro": "Colocar o atuador em modo seguro"}
STATUS_SEG = {"pendente": "Aguardando decisão", "aprovada": "Aprovada", "recusada": "Recusada"}


@app.get("/seguranca")
@exige("ver_seguranca")
def seguranca():
    alertas, acoes, quarentena = bd().seguranca()
    lista_alertas = [
        {"quando": hora_local(ts), "regra": REGRAS_SEG.get(regra, regra),
         "rotulo": SEVERIDADES_SEG.get(sev, (sev, "info"))[0], "classe": SEVERIDADES_SEG.get(sev, (sev, "info"))[1],
         "titulo": titulo, "detalhe": detalhe or "", "origem": orig or "—", "tecnica": tecnica or "—",
         "resposta": resposta}
        for ts, regra, sev, titulo, detalhe, orig, tecnica, resposta in alertas
    ]
    lista_acoes = [
        {"id": aid, "quando": hora_local(criada), "acao": ACOES_SEG.get(acao, acao), "alvo": nome_dispositivo(alvo),
         "alvo_cn": alvo, "motivo": motivo, "rotulo": SEVERIDADES_SEG.get(sev, (sev, "info"))[0],
         "classe": SEVERIDADES_SEG.get(sev, (sev, "info"))[1], "status": status,
         "status_rotulo": STATUS_SEG.get(status, status),
         "decisao": f"{decidida_por} · {hora_local(decidida_em)}" if decidida_em else ""}
        for aid, criada, acao, alvo, motivo, sev, status, decidida_em, decidida_por in acoes
    ]
    lista_quarentena = [{"origem": o, "desde": hora_local(desde), "regra": REGRAS_SEG.get(r, r), "motivo": m}
                        for o, desde, r, m in quarentena]
    pendentes = sum(1 for a in lista_acoes if a["status"] == "pendente")
    return render_template("seguranca.html", alertas=lista_alertas, acoes=lista_acoes,
                           quarentena=lista_quarentena, pendentes=pendentes,
                           aviso=request.args.get("aviso"))


@app.post("/seguranca/acoes/<int:acao_id>")
@exige("aprovar_acoes")
def decidir_acao(acao_id: int):
    """Decisão humana sobre uma ação de alto impacto (RT-15). Só a coordenação chega aqui."""
    decisao = request.form.get("decisao")
    if decisao not in ("aprovar", "recusar"):
        abort(400)
    status = "aprovada" if decisao == "aprovar" else "recusada"
    usuario = session["conta"]["usuario"]
    resultado = bd().decidir_acao(acao_id, status, usuario)
    if resultado is None:
        auditar("acao_seg_decidida", "ignorada", f"ação #{acao_id} já não estava pendente")
        return redirect(url_for("seguranca", aviso="ja-decidida"))
    acao, alvo = resultado
    auditar("acao_seg_decidida", status, f"ação #{acao_id}: {acao} em {alvo}")
    return redirect(url_for("seguranca", aviso=status))


@app.get("/conta")
@exige("ver_painel")
def conta():
    matriz = [{"rotulo": d["rotulo"], "perfis": {p: p in d["perfis"] for p in PERFIS}} for d in PERMISSOES.values()]
    return render_template("conta.html", matriz=matriz)


@app.get("/saude")
def saude():
    return {"ok": True}


# ------------------------------------------------------------- respostas e erros
@app.after_request
def cabecalhos_de_seguranca(resposta):
    resposta.headers["Content-Security-Policy"] = (
        "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    resposta.headers["X-Content-Type-Options"] = "nosniff"
    resposta.headers["X-Frame-Options"] = "DENY"
    resposta.headers["Referrer-Policy"] = "no-referrer"
    resposta.headers["Cache-Control"] = "no-store"
    return resposta


MENSAGENS = {
    400: ("Pedido inválido", "A página ficou aberta por muito tempo ou o pedido veio incompleto. Volte e tente de novo."),
    403: ("Acesso não permitido", "O seu perfil não tem permissão para ver esta página. Se precisar desse acesso, fale com a coordenação."),
    404: ("Página não encontrada", "O endereço digitado não existe neste painel."),
    413: ("Pedido grande demais", "O pedido enviado é maior do que o permitido."),
}


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(413)
def erro_conhecido(exc):
    titulo, texto = MENSAGENS[exc.code]
    return render_template("erro.html", titulo=titulo, texto=texto), exc.code


@app.errorhandler(Exception)
def erro_inesperado(exc):
    if isinstance(exc, HTTPException):
        return render_template("erro.html", titulo="Pedido não atendido",
                               texto="Não foi possível atender este pedido."), exc.code
    app.logger.exception("erro inesperado")   # o detalhe fica só no log do servidor
    return render_template("erro.html", titulo="Algo deu errado",
                           texto="Não foi possível concluir o pedido. Tente novamente em instantes."), 500
