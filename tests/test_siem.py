"""Testes do motor de detecção do SIEM (RT-13) e do fluxo de resposta (RT-15)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "siem"))
from deteccao import Motor  # noqa: E402


class Relogio:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def ev_ingest(evento="conexao_tls_recusada", origem="10.8.0.77", motivo="certificado revogado"):
    return {"ts": "2026-01-01T00:00:00Z", "fonte": "nuvem-ingest", "nivel": "aviso",
            "evento": evento, "origem": origem, "dados": {"motivo": motivo}}


def ev_comando(origem, acao="ligar", dispositivo="escola-bomba", espaco="escola"):
    return {"ts": "2026-01-01T00:00:00Z", "fonte": f"agente-{espaco}", "evento": "comando",
            "origem": "agente-" + espaco,
            "dados": {"dispositivo": dispositivo, "acao": acao, "origem": origem, "espaco": espaco}}


def regras(saidas):
    return [s["regra"] for s in saidas if s["tipo"] == "alerta"]


def tipos(saidas):
    return [s["tipo"] for s in saidas]


class TesteRegras(unittest.TestCase):
    def setUp(self):
        self.rel = Relogio()
        self.m = Motor(relogio=self.rel)

    # Regra C — toda tentativa sem certificado válido vira alerta na hora
    def test_C_credencial_invalida_alerta_imediato(self):
        saidas = self.m.avaliar(ev_ingest())
        self.assertIn("C-credencial-invalida", regras(saidas))
        self.assertEqual([s for s in saidas if s["tipo"] == "quarentena"], [])   # 1 evento só: sem resposta ainda

    def test_C_vale_para_identidade_nao_autorizada(self):
        self.assertIn("C-credencial-invalida", regras(self.m.avaliar(ev_ingest(evento="identidade_nao_autorizada"))))

    # Regra A — repetição da mesma origem escala e dispara resposta automática (quarentena)
    def test_A_repeticao_escala_e_quarentena(self):
        saidas = []
        for _ in range(5):
            saidas = self.m.avaliar(ev_ingest())
        self.assertIn("A-acesso-nao-autorizado", regras(saidas))
        quar = [s for s in saidas if s["tipo"] == "quarentena"]
        self.assertEqual(len(quar), 1)
        self.assertEqual(quar[0]["origem"], "10.8.0.77")
        self.assertEqual([s for s in saidas if s["tipo"] == "alerta" and s["regra"] == "A-acesso-nao-autorizado"][0]["severidade"], "critica")

    def test_A_nao_dispara_com_poucas_ou_origens_diferentes(self):
        for i in range(10):
            saidas = self.m.avaliar(ev_ingest(origem=f"10.0.0.{i}"))   # origens distintas
            self.assertNotIn("A-acesso-nao-autorizado", regras(saidas))

    def test_A_respeita_a_janela_de_tempo(self):
        for _ in range(4):
            self.m.avaliar(ev_ingest())
        self.rel.t = 120                                    # passou da janela de 60 s
        saidas = self.m.avaliar(ev_ingest())
        self.assertNotIn("A-acesso-nao-autorizado", regras(saidas))

    # Regra B — assinatura de SQL Injection no painel
    def test_B_sql_injection_alerta_e_quarentena(self):
        saidas = self.m.avaliar({"fonte": "painel", "evento": "entrada_suspeita", "origem": "203.0.113.9",
                                 "dados": {"campo": "busca", "assinatura": "sql-union"}})
        self.assertIn("B-sql-injection", regras(saidas))
        self.assertIn("quarentena", tipos(saidas))

    # Regra D — comando de atuador fora do perfil exige APROVAÇÃO HUMANA (não age sozinho)
    def test_D_comando_sem_regra_pede_aprovacao(self):
        saidas = self.m.avaliar(ev_comando(origem="sessao-manual-coord"))
        self.assertIn("D-comando-suspeito", regras(saidas))
        acoes = [s for s in saidas if s["tipo"] == "acao"]
        self.assertEqual(len(acoes), 1)
        self.assertEqual(acoes[0]["acao"], "colocar_atuador_em_modo_seguro")
        self.assertEqual(acoes[0]["alvo"], "escola-bomba")

    def test_D_comando_de_regra_local_e_legitimo(self):
        self.assertEqual(self.m.avaliar(ev_comando(origem="regra:R-ESC-01")), [])

    def test_D_tecnica_ics_registrada(self):
        saidas = self.m.avaliar(ev_comando(origem="desconhecida"))
        alerta = [s for s in saidas if s["tipo"] == "alerta"][0]
        self.assertIn("ICS", alerta["tecnica"])


class TesteFluxoSIEM(unittest.TestCase):
    """Fluxo completo processar() -> armazenamento, com um banco falso."""

    def setUp(self):
        import siem as mod
        self.mod = mod

        class BancoFalso:
            def __init__(self):
                self.eventos, self.alertas, self.quarentena, self.acoes = [], [], [], []

            def gravar_evento(self, ev): self.eventos.append(ev)
            def gravar_alerta(self, a): self.alertas.append(a)
            def quarentenar(self, o, r, m): self.quarentena.append(o)
            def enfileirar_acao(self, acao, alvo, motivo, sev):
                dup = any(a["acao"] == acao and a["alvo"] == alvo for a in self.acoes)
                if not dup:
                    self.acoes.append({"acao": acao, "alvo": alvo})
                return not dup

        self.banco = BancoFalso()
        self.siem = mod.SIEM(Motor(relogio=Relogio()), self.banco)

    def test_evento_gera_alerta_e_persiste(self):
        self.siem.processar(ev_ingest())
        self.assertEqual(len(self.banco.eventos), 1)
        self.assertTrue(any(a["regra"] == "C-credencial-invalida" for a in self.banco.alertas))

    def test_comando_suspeito_enfileira_sem_duplicar(self):
        self.siem.processar(ev_comando(origem="manual"))
        self.siem.processar(ev_comando(origem="manual"))   # mesma ação pendente
        self.assertEqual(len(self.banco.acoes), 1)         # não duplica a aprovação pendente
