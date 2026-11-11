"""Teste de ponta a ponta (sem Docker): campo -> borda -> nuvem, com mTLS real no trecho borda -> nuvem.

Usa a PKI de verdade (pki.sh + OpenSSL) em diretório temporário, o serviço de ingestão real
com um armazenamento em memória e um broker MQTT em memória (tests/_stubs).
Cobre: regra local acionando o atuador, queda do link, buffer e reconciliação sem perda.
"""
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(RAIZ / "tests" / "_stubs"), str(RAIZ / "edge" / "agente"),
                str(RAIZ / "field"), str(RAIZ / "cloud" / "ingest")]

import agente as mod_agente      # noqa: E402
import ingest as mod_ingest      # noqa: E402
import simulador as mod_sim      # noqa: E402

_getaddrinfo = socket.getaddrinfo


def _resolver(host, *a, **k):   # "nuvem-ingest" existe só na rede do Docker; aqui aponta para o loopback
    return _getaddrinfo("127.0.0.1" if host == "nuvem-ingest" else host, *a, **k)


class Memoria:
    def __init__(self):
        self.registros = {}
        self.duplicados = 0
        self._trava = threading.Lock()

    def gravar(self, registros):
        aceitos = duplicados = 0
        with self._trava:
            for tipo, r in registros:
                if r["id"] in self.registros:
                    duplicados += 1
                else:
                    self.registros[r["id"]] = (tipo, r)
                    aceitos += 1
            self.duplicados += duplicados
        return aceitos, duplicados

    def do_tipo(self, tipo):
        with self._trava:
            return [r for t, r in self.registros.values() if t == tipo]


@unittest.skipUnless(shutil.which("openssl") and shutil.which("bash"), "requer bash e openssl")
class TesteIntegracao(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        socket.getaddrinfo = _resolver
        cls.tmp = Path(tempfile.mkdtemp(prefix="va-teste-"))
        cls.pki = cls.tmp / "pki"
        cls.pki.mkdir()
        for nome in ("pki.sh", "ca.cnf", "inventario.csv"):
            shutil.copy(RAIZ / "pki" / nome, cls.pki / nome)
        cls.pki_cmd("init")
        cls.pub = cls.pki / "out" / "publico"
        cls.memoria = Memoria()
        cls.servidor = None
        cls.porta = 0
        cls.subir_ingest()

    @classmethod
    def tearDownClass(cls):
        socket.getaddrinfo = _getaddrinfo
        cls.derrubar_ingest()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def pki_cmd(cls, *args):
        subprocess.run(["bash", str(cls.pki / "pki.sh"), *args], check=True, capture_output=True,
                       env={**os.environ, "PKI_RAIZ": str(cls.pki)})

    @classmethod
    def subir_ingest(cls):
        ctx = mod_ingest.criar_contexto_tls(cls.pub, cls.pki / "out" / "nuvem" / "ingest")
        cls.servidor = mod_ingest.criar_servidor(("127.0.0.1", cls.porta), cls.memoria, ctx)
        cls.porta = cls.servidor.server_address[1]
        threading.Thread(target=cls.servidor.serve_forever, daemon=True).start()

    @classmethod
    def derrubar_ingest(cls):
        if cls.servidor:
            cls.servidor.shutdown()
            cls.servidor.server_close()
            cls.servidor = None

    def contexto(self, certificado=None):
        ctx = ssl.create_default_context(cafile=str(self.pub / "ca.crt"))
        if certificado:
            ctx.load_cert_chain(str(certificado), str(Path(certificado).with_suffix(".key")))
        return ctx

    def postar(self, ctx, corpo):
        req = urllib.request.Request(f"https://nuvem-ingest:{self.porta}/ingest",
                                     data=json.dumps(corpo).encode(), method="POST")
        abridor = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                              urllib.request.HTTPSHandler(context=ctx))
        with abridor.open(req, timeout=5) as resp:
            return json.loads(resp.read())

    def esperar(self, condicao, limite=15.0):
        fim = time.time() + limite
        while time.time() < fim:
            if condicao():
                return True
            time.sleep(0.05)
        return False

    # ------------------------------------------------------------- mTLS na nuvem
    def test_1_sem_certificado_e_recusado(self):
        with self.assertRaises((ssl.SSLError, urllib.error.URLError, OSError)):
            self.postar(self.contexto(), {"eventos": []})

    def test_2_certificado_de_dispositivo_nao_pode_ingerir(self):
        ctx = self.contexto(self.pki / "out" / "dispositivos" / "ubs" / "ubs-camara-fria.crt")
        with self.assertRaises(urllib.error.HTTPError) as erro:
            self.postar(ctx, {"eventos": [{"id": "x", "tipo": "leitura", "dados": {}}]})
        self.assertEqual(erro.exception.code, 403)

    def test_3_agente_nao_entrega_evento_de_outro_espaco(self):
        ctx = self.contexto(self.pki / "out" / "bordas" / "horta" / "agente" / "agente.crt")
        ident = "11111111-1111-4111-8111-111111111111"
        resposta = self.postar(ctx, {"eventos": [{"id": ident, "tipo": "leitura", "dados": {
            "id": ident, "espaco": "ubs", "dispositivo": "ubs-camara-fria", "metrica": "temperatura",
            "valor": 5.0, "unidade": "°C", "ts": "2026-01-01T00:00:00Z"}}]})
        self.assertEqual(resposta["aceitos"], 0)
        self.assertEqual(resposta["rejeitados"], [ident])

    def test_4_certificado_revogado_e_recusado(self):
        cert = self.pki / "out" / "bordas" / "centro" / "agente" / "agente.crt"
        ctx = self.contexto(cert)
        self.assertEqual(self.postar(ctx, {"eventos": [{"id": "x"}]})["aceitos"], 0)   # antes: aceito pelo TLS
        self.pki_cmd("revogar", "agente-centro")
        self.derrubar_ingest()
        self.subir_ingest()                                                            # recarrega a CRL
        with self.assertRaises((ssl.SSLError, urllib.error.URLError, OSError)):
            self.postar(self.contexto(cert), {"eventos": [{"id": "x"}]})

    # ------------------------------------------- campo -> borda -> nuvem + queda de link
    def test_5_fluxo_completo_com_queda_de_link_e_reconciliacao(self):
        os.environ.update({
            "ESPACO": "escola", "BROKER_HOST": "borda-escola-broker",
            "INGEST_URL": f"https://nuvem-ingest:{self.porta}/ingest",
            "PKI_PUBLICO": str(self.pub), "PKI_AGENTE": str(self.pki / "out" / "bordas" / "escola" / "agente"),
            "REGRAS_DIR": str(RAIZ / "edge" / "agente" / "regras"),
            "BUFFER_DB": str(self.tmp / "buffer.db"), "INTERVALO_ENVIO_S": "0.1", "LOTE": "50",
        })
        ag = mod_agente.Agente()
        threading.Thread(target=ag.executar, daemon=True).start()

        cfg = json.loads((RAIZ / "field" / "dispositivos" / "escola.json").read_text(encoding="utf-8"))
        dev_dir = self.pki / "out" / "dispositivos" / "escola"
        mundo = {d["cn"]: mod_sim.MODELOS[d["modelo"]](d, "escola", "borda-escola-broker", 8883, self.pub, dev_dir)
                 for d in cfg["dispositivos"]}
        bomba, reservatorio = mundo["escola-bomba"], mundo["escola-reservatorio"]

        def tick(n=1):
            for _ in range(n):
                for d in mundo.values():
                    d.tick(mundo)

        try:
            # 1) operação normal: leituras chegam à nuvem
            tick(3)
            self.assertTrue(self.esperar(lambda: len(self.memoria.do_tipo("leitura")) >= 12))
            self.assertFalse(bomba.ligada)

            # 2) nível baixo -> a regra LOCAL liga a bomba (decisão tomada na borda)
            reservatorio.nivel = 28.0
            tick(2)
            self.assertTrue(bomba.ligada, "a borda deveria ter ligado a bomba")
            self.assertTrue(self.esperar(lambda: any(c["acao"] == "ligar" for c in self.memoria.do_tipo("comando"))))

            # 3) cai o link com a nuvem: a borda segue operando e acumulando no buffer
            self.assertTrue(self.esperar(lambda: ag.buffer.contagem()["pendente"] == 0))
            antes = len(self.memoria.registros)
            self.derrubar_ingest()
            reservatorio.nivel = 86.0
            tick(4)
            self.assertFalse(bomba.ligada, "sem nuvem, a borda ainda deve desligar a bomba no nível alto")
            pendentes = ag.buffer.contagem()["pendente"]
            self.assertGreater(pendentes, 0)
            self.assertEqual(len(self.memoria.registros), antes)

            # 4) o link volta: reconciliação completa, sem perda e sem duplicar
            self.subir_ingest()
            self.assertTrue(self.esperar(lambda: ag.buffer.contagem()["pendente"] == 0, limite=90))
            self.assertEqual(len(self.memoria.registros), antes + pendentes)
            self.assertEqual(ag.buffer.contagem()["rejeitado"], 0)
        finally:
            ag.parar()


if __name__ == "__main__":
    unittest.main()
