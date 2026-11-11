"""Motor de regras locais do nó de borda (RT-02).

As regras rodam na própria borda, sem depender da nuvem: se a internet cair,
o alarme da câmara fria e o controle da bomba continuam funcionando.

Tipos de regra:
  faixa      alarme quando a métrica sai de [min, max] por N leituras seguidas
             (e aviso de normalização quando volta).
  histerese  controle liga/desliga de um atuador com limite de tempo ligado.
"""
import time
import uuid
from datetime import datetime, timezone


def agora_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class Motor:
    def __init__(self, regras: list[dict], espaco: str, relogio=time.monotonic):
        self.regras = regras
        self.espaco = espaco
        self._relogio = relogio
        self._st: dict[str, dict] = {r["id"]: {} for r in regras}

    def avaliar(self, leitura: dict) -> list[dict]:
        """Recebe uma leitura e devolve as ações decididas (alarmes e comandos)."""
        acoes: list[dict] = []
        for regra in self.regras:
            if regra["tipo"] == "faixa":
                acoes += self._faixa(regra, leitura)
            elif regra["tipo"] == "histerese":
                acoes += self._histerese(regra, leitura)
        return acoes

    # ------------------------------------------------------------------ faixa
    def _faixa(self, r: dict, l: dict) -> list[dict]:
        if l["dispositivo"] != r["dispositivo"] or l["metrica"] != r["metrica"]:
            return []
        st = self._st[r["id"]]
        st.setdefault("fora", 0)
        st.setdefault("dentro", 0)
        st.setdefault("ativo", False)
        n = r.get("consecutivas", 3)
        valor = l["valor"]
        fora = ("min" in r and valor < r["min"]) or ("max" in r and valor > r["max"])
        if fora:
            st["fora"] += 1
            st["dentro"] = 0
            if not st["ativo"] and st["fora"] >= n:
                st["ativo"] = True
                return [self._alarme(r, l, "ativo", r["severidade"], r["mensagem"])]
        else:
            st["dentro"] += 1
            st["fora"] = 0
            if st["ativo"] and st["dentro"] >= n:
                st["ativo"] = False
                return [self._alarme(r, l, "normalizado", "info", "Normalizado: " + r["mensagem"])]
        return []

    # -------------------------------------------------------------- histerese
    def _histerese(self, r: dict, l: dict) -> list[dict]:
        st = self._st[r["id"]]
        st.setdefault("confirmado", None)   # estado real informado pelo atuador
        st.setdefault("desejado", None)     # estado decidido pela regra
        st.setdefault("cmd_em", float("-inf"))
        st.setdefault("cmd_estado", None)   # último estado comandado
        st.setdefault("ligada_desde", None)
        st.setdefault("bloqueio_ate", float("-inf"))
        agora = self._relogio()
        acoes: list[dict] = []

        if l["dispositivo"] == r["atuador"] and l["metrica"] == "estado":
            ligada = l["valor"] >= 1
            if ligada and not st["confirmado"]:
                st["ligada_desde"] = agora
            if not ligada:
                st["ligada_desde"] = None
            st["confirmado"] = ligada
        elif l["dispositivo"] == r["dispositivo"] and l["metrica"] == r["metrica"]:
            if agora >= st["bloqueio_ate"]:
                if l["valor"] < r["ligar_abaixo"]:
                    st["desejado"] = True
                elif l["valor"] > r["desligar_acima"]:
                    st["desejado"] = False
        else:
            return []

        # Limite de funcionamento contínuo: protege o atuador e evita esvaziar/transbordar
        if st["confirmado"] and st["ligada_desde"] is not None \
                and agora - st["ligada_desde"] > r["max_ligado_s"]:
            st["desejado"] = False
            st["ligada_desde"] = None
            st["bloqueio_ate"] = agora + r.get("descanso_s", 120)
            acoes.append(self._alarme(
                r, l, "ativo", "alto",
                f"Atuador {r['atuador']} atingiu o limite de {r['max_ligado_s']} s ligado e foi desligado pela borda",
            ))

        # Comanda quando o estado desejado difere do confirmado. O MESMO comando só é
        # repetido após `reenvio_s` (evita inundar o atuador enquanto ele não confirma).
        repetido = st["cmd_estado"] == st["desejado"] and agora - st["cmd_em"] < r.get("reenvio_s", 10)
        if st["desejado"] is not None and st["desejado"] != st["confirmado"] and not repetido:
            st["cmd_em"] = agora
            st["cmd_estado"] = st["desejado"]
            acoes.append({
                "tipo": "comando",
                "dados": {
                    "id": str(uuid.uuid4()),
                    "espaco": self.espaco,
                    "dispositivo": r["atuador"],
                    "acao": "ligar" if st["desejado"] else "desligar",
                    "origem": f"regra:{r['id']}",
                    "ts": agora_iso(),
                },
            })
        return acoes

    # ------------------------------------------------------------------ comum
    def _alarme(self, r: dict, l: dict, estado: str, severidade: str, mensagem: str) -> dict:
        return {
            "tipo": "alarme",
            "dados": {
                "id": str(uuid.uuid4()),
                "espaco": self.espaco,
                "dispositivo": l["dispositivo"],
                "regra": r["id"],
                "severidade": severidade,
                "estado": estado,
                "mensagem": mensagem,
                "valor": l["valor"],
                "ts": agora_iso(),
            },
        }
