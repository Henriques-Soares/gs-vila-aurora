"""Administração das contas do painel (uso em linha de comando, fora do painel).

O painel em si NÃO consegue criar contas, trocar senhas ou mudar perfis: isso só é
possível aqui, com a credencial administrativa do banco, por quem opera o servidor.

    docker compose run --rm admin migrar
    docker compose run --rm admin semear
    docker compose run --rm admin listar
    docker compose run --rm admin criar <usuario> <perfil> "<nome>"
    docker compose run --rm admin redefinir <usuario>
    docker compose run --rm admin conferir <usuario> <codigo>     (diagnóstico do segundo fator)

Todas as contas são fictícias (dados sintéticos). A senha inicial é aleatória e aparece
uma única vez; o segundo fator (TOTP) é cadastrado pela própria pessoa no primeiro acesso.
"""
import os
import re
import secrets
import sys
from pathlib import Path

from werkzeug.security import generate_password_hash

PERFIS = ("operador", "tecnico", "coordenacao", "auditor")
DEMONSTRACAO = [
    ("operador.demo", "operador", "Olívia Operadora (conta fictícia)"),
    ("tecnico.demo", "tecnico", "Tiago Técnico (conta fictícia)"),
    ("coordenacao.demo", "coordenacao", "Carla Coordenadora (conta fictícia)"),
    ("auditor.demo", "auditor", "Augusto Auditor (conta fictícia)"),
]
RE_USUARIO = re.compile(r"^[a-z0-9._-]{3,40}$")


def conectar():
    import psycopg2
    return psycopg2.connect(
        host=os.environ.get("DB_HOST", "nuvem-db"), port=int(os.environ.get("DB_PORTA", "5432")),
        dbname=os.environ.get("DB_NOME", "vilaaurora"), user="postgres",
        password=os.environ["POSTGRES_PASSWORD"], connect_timeout=5,
    )


def nova_senha() -> str:
    return secrets.token_urlsafe(12)


def migrar(cur) -> None:
    cur.execute(Path(os.environ.get("MIGRACAO", "/db/03-painel.sql")).read_text(encoding="utf-8"))
    print("Banco atualizado: tabelas de contas e auditoria prontas; papel do painel = painel_app.")


def gravar(cur, usuario: str, perfil: str, nome: str) -> str:
    senha = nova_senha()
    cur.execute(
        """INSERT INTO usuarios (usuario, nome, perfil, senha_hash)
           VALUES (%(u)s, %(n)s, %(p)s, %(h)s)
           ON CONFLICT (usuario) DO NOTHING""",
        {"u": usuario, "n": nome, "p": perfil, "h": generate_password_hash(senha, method="scrypt")})
    return senha if cur.rowcount == 1 else ""


def semear(cur) -> None:
    print(f"{'USUÁRIO':<20} {'PERFIL':<13} SENHA INICIAL")
    for usuario, perfil, nome in DEMONSTRACAO:
        senha = gravar(cur, usuario, perfil, nome)
        print(f"{usuario:<20} {perfil:<13} {senha or '(conta já existe — use: admin redefinir ' + usuario + ')'}")
    print("\nAnote as senhas agora: elas não ficam guardadas em lugar nenhum (só o hash).")
    print("No primeiro acesso, cada conta cadastra o segundo fator no aplicativo autenticador.")


def criar(cur, usuario: str, perfil: str, nome: str) -> None:
    if not RE_USUARIO.match(usuario):
        sys.exit("usuário inválido: use de 3 a 40 letras minúsculas, números, ponto, hífen ou sublinhado")
    if perfil not in PERFIS:
        sys.exit("perfil inválido: " + ", ".join(PERFIS))
    senha = gravar(cur, usuario, perfil, nome)
    print(f"Conta criada: {usuario} ({perfil}) — senha inicial: {senha}" if senha else "Essa conta já existe.")


def redefinir(cur, usuario: str) -> None:
    senha = nova_senha()
    cur.execute(
        """UPDATE usuarios
              SET senha_hash = %(h)s, totp_segredo = NULL, totp_ativo = false, totp_ultimo_passo = 0,
                  falhas = 0, bloqueado_ate = NULL
            WHERE usuario = %(u)s""",
        {"u": usuario, "h": generate_password_hash(senha, method="scrypt")})
    if cur.rowcount != 1:
        sys.exit("conta não encontrada")
    cur.execute("INSERT INTO auditoria (usuario, acao, resultado, detalhe, origem) VALUES (%s, %s, %s, %s, %s)",
                (usuario, "conta_redefinida", "sucesso", "senha e MFA redefinidos pelo administrador", "linha de comando"))
    print(f"Conta redefinida: {usuario} — nova senha: {senha} (o segundo fator será cadastrado de novo)")


def conferir(cur, usuario: str, informado: str) -> None:
    """Diagnóstico: diz se um código do aplicativo confere com a conta e com o relógio do servidor."""
    import time
    from datetime import datetime, timezone

    import totp
    cur.execute("SELECT totp_segredo, totp_ativo, falhas, bloqueado_ate FROM usuarios WHERE usuario = %s", (usuario,))
    linha = cur.fetchone()
    if not linha:
        sys.exit("conta não encontrada")
    segredo, ativo, falhas, bloqueado_ate = linha
    agora = time.time()
    print(f"Relógio do servidor (UTC): {datetime.now(timezone.utc):%d/%m/%Y %H:%M:%S}")
    print(f"Conta: {usuario} | MFA: {'ativo' if ativo else 'pendente'} | falhas: {falhas} | "
          f"bloqueada até: {bloqueado_ate.strftime('%H:%M:%S UTC') if bloqueado_ate else '—'}")
    if not segredo:
        sys.exit("Esta conta ainda não tem segredo TOTP: entre no painel com a senha para gerar o QR.")
    informado = "".join(ch for ch in informado if ch.isdigit())
    for desvio in sorted(range(-40, 41), key=abs):     # procura até 20 minutos para cada lado
        if totp.codigo(segredo, agora + desvio * totp.PASSO_S) == informado:
            if abs(desvio) <= 1:
                print("RESULTADO: código VÁLIDO para esta conta e para o relógio do servidor.")
            else:
                print(f"RESULTADO: o código pertence a esta conta, mas o relógio do servidor e o do celular "
                      f"diferem em cerca de {abs(desvio) * totp.PASSO_S} s (celular "
                      f"{'adiantado' if desvio > 0 else 'atrasado'}). Sincronize os relógios.")
            return
    print("RESULTADO: o código NÃO pertence a esta conta. O aplicativo provavelmente está mostrando "
          "o código de outra conta, ou o QR lido foi de um cadastro anterior.")


def listar(cur) -> None:
    cur.execute("SELECT usuario, perfil, totp_ativo, ativo, falhas, ultimo_login FROM usuarios ORDER BY usuario")
    print(f"{'USUÁRIO':<20} {'PERFIL':<13} {'MFA':<10} {'ATIVA':<6} {'FALHAS':<7} ÚLTIMO LOGIN (UTC)")
    for usuario, perfil, mfa, ativo, falhas, ultimo in cur.fetchall():
        print(f"{usuario:<20} {perfil:<13} {'ativo' if mfa else 'pendente':<10} {'sim' if ativo else 'não':<6} "
              f"{falhas:<7} {ultimo.strftime('%d/%m/%Y %H:%M:%S') if ultimo else '—'}")


def main() -> None:
    args = sys.argv[1:]
    comandos = {"migrar": (migrar, 0), "semear": (semear, 0), "listar": (listar, 0),
                "criar": (criar, 3), "redefinir": (redefinir, 1), "conferir": (conferir, 2)}
    if not args or args[0] not in comandos or len(args) - 1 != comandos[args[0]][1]:
        sys.exit(__doc__)
    funcao, _ = comandos[args[0]]
    conexao = conectar()
    try:
        with conexao, conexao.cursor() as cur:
            funcao(cur, *args[1:])
    finally:
        conexao.close()


if __name__ == "__main__":
    main()
