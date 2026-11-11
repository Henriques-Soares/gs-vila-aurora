import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "edge" / "agente"))
from regras import Motor  # noqa: E402


def leitura(dispositivo, metrica, valor):
    return {"id": "x", "espaco": "t", "dispositivo": dispositivo, "metrica": metrica,
            "valor": valor, "unidade": "u", "ts": "2026-01-01T00:00:00Z"}


class Relogio:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


class TesteFaixa(unittest.TestCase):
    REGRA = {"id": "R1", "tipo": "faixa", "dispositivo": "ubs-camara-fria", "metrica": "temperatura",
             "min": 2.0, "max": 8.0, "consecutivas": 3, "severidade": "critico", "mensagem": "fora da faixa"}

    def test_alarma_apos_n_leituras_e_normaliza(self):
        m = Motor([self.REGRA], "ubs")
        self.assertEqual(m.avaliar(leitura("ubs-camara-fria", "temperatura", 5.0)), [])
        self.assertEqual(m.avaliar(leitura("ubs-camara-fria", "temperatura", 9.0)), [])
        self.assertEqual(m.avaliar(leitura("ubs-camara-fria", "temperatura", 9.5)), [])
        acoes = m.avaliar(leitura("ubs-camara-fria", "temperatura", 10.0))
        self.assertEqual(len(acoes), 1)
        self.assertEqual(acoes[0]["dados"]["estado"], "ativo")
        self.assertEqual(acoes[0]["dados"]["severidade"], "critico")
        # não repete o alarme enquanto continua fora
        self.assertEqual(m.avaliar(leitura("ubs-camara-fria", "temperatura", 11.0)), [])
        for v in (6.0, 5.5):
            self.assertEqual(m.avaliar(leitura("ubs-camara-fria", "temperatura", v)), [])
        acoes = m.avaliar(leitura("ubs-camara-fria", "temperatura", 5.0))
        self.assertEqual(acoes[0]["dados"]["estado"], "normalizado")

    def test_pico_isolado_nao_alarma(self):
        m = Motor([self.REGRA], "ubs")
        for v in (9.0, 5.0, 9.0, 5.0, 9.0, 5.0):
            self.assertEqual(m.avaliar(leitura("ubs-camara-fria", "temperatura", v)), [])

    def test_ignora_outros_dispositivos(self):
        m = Motor([self.REGRA], "ubs")
        for _ in range(5):
            self.assertEqual(m.avaliar(leitura("ubs-energia", "temperatura", 50.0)), [])


class TesteHisterese(unittest.TestCase):
    REGRA = {"id": "R2", "tipo": "histerese", "dispositivo": "escola-reservatorio", "metrica": "nivel",
             "atuador": "escola-bomba", "ligar_abaixo": 30.0, "desligar_acima": 85.0,
             "max_ligado_s": 300, "descanso_s": 120, "reenvio_s": 10}

    def setUp(self):
        self.relogio = Relogio()
        self.m = Motor([self.REGRA], "escola", relogio=self.relogio)

    def comandos(self, acoes):
        return [a["dados"]["acao"] for a in acoes if a["tipo"] == "comando"]

    def test_liga_e_desliga_com_histerese(self):
        self.m.avaliar(leitura("escola-bomba", "estado", 0))
        self.assertEqual(self.comandos(self.m.avaliar(leitura("escola-reservatorio", "nivel", 50))), [])
        self.assertEqual(self.comandos(self.m.avaliar(leitura("escola-reservatorio", "nivel", 29))), ["ligar"])
        # sem confirmação, não repete o comando antes de `reenvio_s`
        self.relogio.t = 5
        self.assertEqual(self.comandos(self.m.avaliar(leitura("escola-reservatorio", "nivel", 28))), [])
        self.relogio.t = 11
        self.assertEqual(self.comandos(self.m.avaliar(leitura("escola-reservatorio", "nivel", 28))), ["ligar"])
        self.m.avaliar(leitura("escola-bomba", "estado", 1))
        self.relogio.t = 60
        self.assertEqual(self.comandos(self.m.avaliar(leitura("escola-reservatorio", "nivel", 60))), [])
        self.assertEqual(self.comandos(self.m.avaliar(leitura("escola-reservatorio", "nivel", 86))), ["desligar"])

    def test_limite_de_tempo_ligada_desliga_alarma_e_bloqueia(self):
        self.m.avaliar(leitura("escola-bomba", "estado", 0))
        self.m.avaliar(leitura("escola-reservatorio", "nivel", 20))
        self.m.avaliar(leitura("escola-bomba", "estado", 1))        # ligou em t=0
        self.relogio.t = 301
        acoes = self.m.avaliar(leitura("escola-reservatorio", "nivel", 22))
        self.assertEqual(self.comandos(acoes), ["desligar"])
        self.assertEqual([a["dados"]["severidade"] for a in acoes if a["tipo"] == "alarme"], ["alto"])
        self.m.avaliar(leitura("escola-bomba", "estado", 0))
        # durante o descanso não religa, mesmo com nível baixo
        self.relogio.t = 350
        self.assertEqual(self.comandos(self.m.avaliar(leitura("escola-reservatorio", "nivel", 18))), [])
        # depois do descanso volta a controlar
        self.relogio.t = 301 + 121
        self.assertEqual(self.comandos(self.m.avaliar(leitura("escola-reservatorio", "nivel", 18))), ["ligar"])


if __name__ == "__main__":
    unittest.main()
