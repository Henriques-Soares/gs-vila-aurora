"""TOTP (RFC 6238) com a biblioteca padrão — segundo fator do painel (RT-09).

Compatível com Google Authenticator, Microsoft Authenticator, Aegis etc.
(SHA-1, 6 dígitos, janela de 30 segundos).
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

PASSO_S = 30
DIGITOS = 6


def gerar_segredo() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def _codigo_do_passo(segredo: str, passo: int) -> str:
    chave = base64.b32decode(segredo, casefold=True)
    resumo = hmac.new(chave, struct.pack(">Q", passo), hashlib.sha1).digest()
    deslocamento = resumo[-1] & 0x0F
    numero = struct.unpack(">I", resumo[deslocamento:deslocamento + 4])[0] & 0x7FFFFFFF
    return str(numero % (10 ** DIGITOS)).zfill(DIGITOS)


def codigo(segredo: str, agora: float | None = None) -> str:
    return _codigo_do_passo(segredo, int((time.time() if agora is None else agora) // PASSO_S))


def verificar(segredo: str, informado: str, ultimo_passo: int = 0, agora: float | None = None) -> int | None:
    """Devolve o passo de tempo aceito, ou None.

    Aceita o passo atual e os vizinhos (tolerância de relógio de ±30 s) e recusa
    qualquer passo já utilizado, para que um código capturado não sirva duas vezes.
    """
    informado = "".join(ch for ch in str(informado) if ch.isdigit())
    if len(informado) != DIGITOS:
        return None
    atual = int((time.time() if agora is None else agora) // PASSO_S)
    aceito = None
    for passo in (atual - 1, atual, atual + 1):
        if hmac.compare_digest(_codigo_do_passo(segredo, passo), informado) and passo > ultimo_passo:
            aceito = passo
    return aceito


def uri(segredo: str, usuario: str, emissor: str = "Vila Aurora") -> str:
    return (f"otpauth://totp/{quote(emissor)}:{quote(usuario)}"
            f"?secret={segredo}&issuer={quote(emissor)}&algorithm=SHA1&digits={DIGITOS}&period={PASSO_S}")
