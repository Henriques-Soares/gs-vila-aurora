"""Motor de regras de detecção do SIEM — Rede Comunitária Vila Aurora (RT-13).

Puro e testável: recebe eventos normalizados e devolve alertas e ações, sem tocar
em banco nem em rede. O SIEM (siem.py) cuida da coleta, do armazenamento e das respostas.

Quatro regras, cada uma ligada a uma falha do incidente INC-VA-0712:
  A  acesso não autorizado repetido na nuvem   (tentativas de entrar sem credencial válida)
  B  padrão de SQL Injection                    (assinatura detectada na entrada do painel)
  C  dispositivo/credencial sem certificado     (conexão recusada no mTLS da nuvem)
  D  comando de atuador fora do perfil/horário  (acionamento que não veio de uma regra local)
"""
import time
from collections import defaultdict, deque

# evento de entrada: {"ts","recebido_em","fonte","nivel","evento","origem","dados"}
# saída: alertas e ações (dicionários), avaliados pelo siem.py


class Motor:
    def __init__(self, relogio=time.monotonic):
        self._relogio = relogio
        self._janela = defaultdict(deque)   # (regra, chave) -> deque de instantes
        self._ja_alertou = {}               # evita repetir o mesmo alerta em sequência

    # ------------------------------------------------------------- utilidades
    def _conta_na_janela(self, chave, segundos: int) -> int:
        agora = self._relogio()
        janela = self._janela[chave]
        janela.append(agora)
        while janela and agora - janela[0] > segundos:
            janela.popleft()
        return len(janela)

    @staticmethod
    def _alerta(regra, severidade, titulo, evento, tecnica, detalhe=None, resposta=None):
        return {"tipo": "alerta", "regra": regra, "severidade": severidade, "titulo": titulo,
                "detalhe": detalhe or titulo, "fonte": evento.get("fonte"), "origem": evento.get("origem"),
                "tecnica": tecnica, "resposta": resposta}

    @staticmethod
    def _quarentena(origem, regra, motivo):
        return {"tipo": "quarentena", "origem": origem, "regra": regra, "motivo": motivo}

    @staticmethod
    def _aprovacao(acao, alvo, motivo, severidade):
        return {"tipo": "acao", "acao": acao, "alvo": alvo, "motivo": motivo, "severidade": severidade}

    # --------------------------------------------------------------- avaliação
    def avaliar(self, ev: dict) -> list[dict]:
        evento = ev.get("evento")
        if ev.get("fonte", "").startswith("nuvem-ingest"):
            if evento in ("conexao_tls_recusada", "identidade_nao_autorizada"):
                return self._acesso_nuvem(ev)
        if evento == "entrada_suspeita":
            return self._sql_injection(ev)
        if evento == "comando":
            return self._comando_atuador(ev)
        return []

    # Regras C (imediata) + A (repetição) — mesma fonte, lógicas distintas
    def _acesso_nuvem(self, ev: dict) -> list[dict]:
        saidas = []
        origem = ev.get("origem") or "desconhecida"
        motivo = (ev.get("dados") or {}).get("motivo", "")
        # Regra C: toda tentativa sem certificado válido é registrada na hora
        saidas.append(self._alerta(
            "C-credencial-invalida", "alta",
            "Dispositivo sem certificado válido tentou acessar a nuvem",
            ev, "T1190 / T1078",
            detalhe=f"Conexão recusada no mTLS da ingestão (origem {origem}; motivo: {motivo or 'certificado ausente/revogado'})."))
        # Regra A: repetição da mesma origem = acesso não autorizado / força bruta
        n = self._conta_na_janela(("A", origem), 60)
        if n >= 5 and self._ja_alertou.get(("A", origem)) != n // 5:
            self._ja_alertou[("A", origem)] = n // 5
            saidas.append(self._alerta(
                "A-acesso-nao-autorizado", "critica",
                "Acesso não autorizado repetido na nuvem",
                ev, "T1110 / T1133",
                detalhe=f"{n} tentativas recusadas da origem {origem} em até 60 s.",
                resposta="origem colocada em quarentena"))
            saidas.append(self._quarentena(origem, "A-acesso-nao-autorizado",
                                           f"{n} tentativas recusadas em 60 s"))
        return saidas

    # Regra B: assinatura de SQL Injection detectada na entrada do painel
    def _sql_injection(self, ev: dict) -> list[dict]:
        origem = ev.get("origem") or "desconhecida"
        dados = ev.get("dados") or {}
        saidas = [self._alerta(
            "B-sql-injection", "alta",
            "Tentativa de SQL Injection detectada no painel",
            ev, "T1190",
            detalhe=f"Assinatura '{dados.get('assinatura', '?')}' no campo '{dados.get('campo', '?')}' "
                    f"(origem {origem}). A consulta é parametrizada; a entrada foi recusada.",
            resposta="origem colocada em quarentena")]
        saidas.append(self._quarentena(origem, "B-sql-injection", "assinatura de injeção detectada"))
        return saidas

    # Regra D: comando de atuador que não veio de uma regra local automática
    def _comando_atuador(self, ev: dict) -> list[dict]:
        dados = ev.get("dados") or {}
        origem_cmd = str(dados.get("origem", ""))
        alvo = dados.get("dispositivo", "?")
        # Comandos legítimos nascem das regras locais da borda: origem "regra:...".
        if origem_cmd.startswith("regra:"):
            return []
        return [
            self._alerta(
                "D-comando-suspeito", "critica",
                "Comando de atuador fora do perfil esperado",
                ev, "T0831 / T0836 (ICS)",
                detalhe=f"Comando '{dados.get('acao', '?')}' para {alvo} com origem '{origem_cmd or 'desconhecida'}', "
                        "que não corresponde a uma regra local automática."),
            # Alto impacto: o SIEM NÃO desliga/religa nada sozinho — encaminha para aprovação humana.
            self._aprovacao("colocar_atuador_em_modo_seguro", alvo,
                            f"Comando suspeito ({origem_cmd or 'origem desconhecida'}) exige verificação", "critica"),
        ]
