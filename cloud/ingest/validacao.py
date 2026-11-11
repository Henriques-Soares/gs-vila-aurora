"""Validação de entrada do serviço de ingestão (tudo o que chega da borda é conferido no servidor)."""
import json
import math
import uuid
from datetime import datetime

MAX_TEXTO = 200
SEVERIDADES = {"info", "alto", "critico"}
ESTADOS = {"ativo", "normalizado"}


def _texto(dados: dict, campo: str, maximo: int = MAX_TEXTO) -> str:
    valor = dados.get(campo)
    if not isinstance(valor, str) or not valor or len(valor) > maximo:
        raise ValueError(f"campo inválido: {campo}")
    return valor


def _numero(dados: dict, campo: str, obrigatorio: bool = True):
    valor = dados.get(campo)
    if valor is None and not obrigatorio:
        return None
    if isinstance(valor, bool) or not isinstance(valor, (int, float)) or not math.isfinite(valor):
        raise ValueError(f"campo inválido: {campo}")
    return float(valor)


def _instante(dados: dict, campo: str = "ts") -> datetime:
    bruto = _texto(dados, campo, 40)
    try:
        instante = datetime.fromisoformat(bruto.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"campo inválido: {campo}") from exc
    if instante.tzinfo is None:
        raise ValueError(f"campo sem fuso horário: {campo}")
    return instante


def validar(evento: dict, espaco_do_agente: str) -> tuple[str, dict]:
    """Devolve (tipo, registro pronto para o banco) ou levanta ValueError."""
    if not isinstance(evento, dict) or not isinstance(evento.get("dados"), dict):
        raise ValueError("evento malformado")
    tipo, d = evento.get("tipo"), evento["dados"]
    registro = {
        "id": str(uuid.UUID(_texto(d, "id", 36))),
        "espaco": _texto(d, "espaco", 40),
        "dispositivo": _texto(d, "dispositivo", 80),
        "ts": _instante(d),
    }
    # Um agente só pode entregar eventos do próprio espaço (identidade vem do certificado)
    if registro["espaco"] != espaco_do_agente:
        raise ValueError("espaço do evento difere do espaço do agente autenticado")

    if tipo == "leitura":
        extra = d.get("extra")
        if extra is not None:
            if not isinstance(extra, dict) or len(json.dumps(extra)) > 2000:
                raise ValueError("campo inválido: extra")
        registro.update(metrica=_texto(d, "metrica", 60), valor=_numero(d, "valor"),
                        unidade=_texto(d, "unidade", 20),
                        extra=json.dumps(extra, ensure_ascii=False) if extra is not None else None)
    elif tipo == "alarme":
        severidade, estado = _texto(d, "severidade", 20), _texto(d, "estado", 20)
        if severidade not in SEVERIDADES or estado not in ESTADOS:
            raise ValueError("severidade/estado inválidos")
        registro.update(regra=_texto(d, "regra", 40), severidade=severidade, estado=estado,
                        mensagem=_texto(d, "mensagem", 400), valor=_numero(d, "valor", obrigatorio=False))
    elif tipo == "comando":
        registro.update(acao=_texto(d, "acao", 40), origem=_texto(d, "origem", 80))
    else:
        raise ValueError("tipo de evento desconhecido")
    return tipo, registro
