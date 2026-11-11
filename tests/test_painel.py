"""Testes de acesso do painel (RT-09): senha + TOTP, perfis (RBAC), bloqueio, CSRF e auditoria."""
import re
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "painel"))

from werkzeug.security import generate_password_hash  # noqa: E402

import app as painel  # noqa: E402
import totp  # noqa: E402

SENHA = "senha-de-teste-123"


class BancoFalso:
    def __init__(self):
        self.usuarios = {}
        self.trilha = []
        for nome, perfil in (("operador.demo", "operador"), ("tecnico.demo", "tecnico"),
                             ("coordenacao.demo", "coordenacao"), ("auditor.demo", "auditor")):
            self.usuarios[nome] = {
                "usuario": nome, "nome": nome.title(), "perfil": perfil,
                "senha_hash": generate_password_hash(SENHA), "totp_segredo": None, "totp_ativo": False,
                "totp_ultimo_passo": 0, "falhas": 0, "bloqueado_ate": None, "ativo": True}

    def usuario(self, usuario):
        u = self.usuarios.get(usuario)
        return dict(u) if u else None

    def registrar_falha(self, usuario, limite, bloqueio_min):
        u = self.usuarios[usuario]
        u["falhas"] += 1
        if u["falhas"] >= limite:
            u["bloqueado_ate"] = datetime.now(timezone.utc) + timedelta(minutes=bloqueio_min)

    def salvar_segredo(self, usuario, segredo):
        self.usuarios[usuario].update(totp_segredo=segredo, totp_ativo=False)

    def concluir_login(self, usuario, passo):
        self.usuarios[usuario].update(totp_ativo=True, totp_ultimo_passo=passo, falhas=0, bloqueado_ate=None)

    def auditar(self, usuario, perfil, acao, resultado, detalhe=None, origem=None):
        self.trilha.append((usuario, perfil, acao, resultado))

    def painel(self):
        return [], [], [], 0

    def comandos(self, limite=50):
        return []

    def auditoria(self, limite=100):
        return []


class TestePainel(unittest.TestCase):
    def setUp(self):
        painel.banco = BancoFalso()
        painel.app.config.update(TESTING=True)
        self.c = painel.app.test_client()

    def csrf(self, caminho):
        html = self.c.get(caminho).get_data(as_text=True)
        return re.search(r'name="csrf" value="([^"]+)"', html).group(1)

    def senha(self, usuario, senha=SENHA):
        return self.c.post("/entrar", data={"usuario": usuario, "senha": senha, "csrf": self.csrf("/entrar")})

    def entrar(self, usuario):
        """Login completo: senha + cadastro (ou verificação) do segundo fator."""
        r = self.senha(usuario)
        destino = r.headers["Location"]
        token = self.csrf(destino)
        segredo = painel.banco.usuarios[usuario]["totp_segredo"]
        return self.c.post(destino, data={"codigo": totp.codigo(segredo), "csrf": token})

    def test_sem_login_vai_para_a_tela_de_entrada(self):
        for caminho in ("/", "/comandos", "/auditoria", "/conta"):
            r = self.c.get(caminho)
            self.assertEqual((r.status_code, r.headers["Location"]), (302, "/entrar"), caminho)

    def test_senha_sozinha_nao_da_acesso(self):
        r = self.senha("operador.demo")
        self.assertEqual(r.headers["Location"], "/mfa/configurar")
        self.assertEqual(self.c.get("/").headers["Location"], "/entrar")   # ainda sem sessão

    def test_primeiro_acesso_cadastra_mfa_e_depois_exige_codigo(self):
        r = self.entrar("operador.demo")
        self.assertEqual(r.headers["Location"], "/")
        self.assertEqual(self.c.get("/").status_code, 200)
        self.assertTrue(painel.banco.usuarios["operador.demo"]["totp_ativo"])
        self.c.post("/sair", data={"csrf": self.csrf("/conta")})
        self.assertEqual(self.c.get("/").headers["Location"], "/entrar")
        # segundo login: vai para a verificação; código errado não entra
        self.assertEqual(self.senha("operador.demo").headers["Location"], "/verificar")
        r = self.c.post("/verificar", data={"codigo": "000000", "csrf": self.csrf("/verificar")})
        self.assertEqual(r.status_code, 401)
        self.assertEqual(self.c.get("/").headers["Location"], "/entrar")

    def test_codigo_ja_usado_e_recusado(self):
        self.entrar("operador.demo")
        usado = totp.codigo(painel.banco.usuarios["operador.demo"]["totp_segredo"])
        self.c.post("/sair", data={"csrf": self.csrf("/conta")})
        self.senha("operador.demo")
        r = self.c.post("/verificar", data={"codigo": usado, "csrf": self.csrf("/verificar")})
        self.assertEqual(r.status_code, 401)

    def test_perfis_de_acesso(self):
        esperado = {  # perfil -> (comandos, auditoria)
            "operador.demo": (403, 403), "tecnico.demo": (200, 403),
            "coordenacao.demo": (200, 200), "auditor.demo": (200, 200)}
        for usuario, (comandos, auditoria) in esperado.items():
            self.setUp()
            self.entrar(usuario)
            self.assertEqual(self.c.get("/").status_code, 200, usuario)
            self.assertEqual(self.c.get("/comandos").status_code, comandos, usuario)
            self.assertEqual(self.c.get("/auditoria").status_code, auditoria, usuario)
        self.setUp()
        self.entrar("operador.demo")
        self.c.get("/auditoria")
        self.assertIn(("operador.demo", "operador", "acesso_negado", "negado"), painel.banco.trilha)

    def test_bloqueio_apos_tentativas_erradas(self):
        for _ in range(painel.MAX_FALHAS):
            self.assertEqual(self.senha("tecnico.demo", "errada").status_code, 401)
        self.assertIsNotNone(painel.banco.usuarios["tecnico.demo"]["bloqueado_ate"])
        self.assertEqual(self.senha("tecnico.demo").status_code, 401)   # senha certa, mas conta bloqueada

    def test_bloqueio_na_etapa_do_codigo_e_informado_e_nao_se_estende(self):
        self.senha("auditor.demo")
        for _ in range(painel.MAX_FALHAS):
            r = self.c.post("/mfa/configurar", data={"codigo": "000000", "csrf": self.csrf("/mfa/configurar")})
            self.assertIn("Código incorreto", r.get_data(as_text=True))
        ate = painel.banco.usuarios["auditor.demo"]["bloqueado_ate"]
        self.assertIsNotNone(ate)
        certo = totp.codigo(painel.banco.usuarios["auditor.demo"]["totp_segredo"])
        r = self.c.post("/mfa/configurar", data={"codigo": certo, "csrf": self.csrf("/mfa/configurar")})
        self.assertIn("Conta bloqueada", r.get_data(as_text=True))
        self.assertEqual(painel.banco.usuarios["auditor.demo"]["bloqueado_ate"], ate)   # não renova o bloqueio
        self.assertEqual(painel.banco.usuarios["auditor.demo"]["falhas"], painel.MAX_FALHAS)

    def test_mensagem_igual_para_usuario_inexistente(self):
        a = self.senha("nao.existe", "x").get_data(as_text=True)
        b = self.senha("operador.demo", "x").get_data(as_text=True)
        limpar = lambda h: re.sub(r'value="[^"]+"', "", h)
        self.assertEqual(limpar(a), limpar(b))

    def test_post_sem_csrf_e_recusado(self):
        self.c.get("/entrar")
        r = self.c.post("/entrar", data={"usuario": "operador.demo", "senha": SENHA})
        self.assertEqual(r.status_code, 400)

    def test_cabecalhos_e_cookie(self):
        r = self.c.get("/entrar")
        self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])
        cookie = r.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)


if __name__ == "__main__":
    unittest.main()
