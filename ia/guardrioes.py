"""Proteção do assistente de IA (LLM) que faz triagem de alertas (RT-17).

O assistente só RESUME e CLASSIFICA alertas em linguagem simples para os operadores.
Ele nunca aciona atuadores nem decide nada — essa é a defesa contra "agência excessiva".
Em volta dele, guardrioes validam a entrada e a saída:

  OWASP Top 10 para LLM / MITRE ATLAS cobertos:
    LLM01 Prompt Injection (direta e indireta) ... AML.T0051
    LLM02 Insecure Output Handling .............. saída tratada como texto, nunca como comando
    LLM06 Sensitive Information Disclosure ....... AML.T0057 (redige segredos)
    LLM08 Excessive Agency ....................... o LLM não tem ferramentas nem atuadores

Sem dependências externas: o "modelo" é uma triagem local determinística, o suficiente para
exercitar e TESTAR os guardrioes (como se faria com uma ferramenta tipo garak) sem subir um LLM.
"""
import re

# --- entrada: padrões de injeção de prompt (direta e indireta, por e-mail/documento) ---
_INJECOES = [
    ("instrucao-sobrescrita", re.compile(r"(ignore|desconsidere|esqueça).{0,30}(instru|regra|anterior|acima|system)", re.I)),
    ("troca-de-papel", re.compile(r"(você agora é|aja como|a partir de agora você|you are now|pretenda ser)", re.I)),
    ("vazamento-de-prompt", re.compile(r"(revele|mostre|imprima).{0,30}(system prompt|prompt do sistema|suas instru|senha|segredo)", re.I)),
    ("ordem-de-acao", re.compile(r"(desligue|ligue|abra|revogue|execute|delete|apague|rode)\s+\w", re.I)),
    ("delimitador-falso", re.compile(r"(###|```|<\|.*?\|>|\[/?(system|inst)\])", re.I)),
]
# --- saída: segredos que nunca podem sair ---
_SEGREDOS = [
    ("senha", re.compile(r"(senha|password|secret|token|api[_-]?key)\s*[:=]\s*\S+", re.I)),
    ("chave-privada", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("cpf", re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")),
]
MAX_ENTRADA = 4000


def inspecionar_entrada(texto: str) -> list[str]:
    """Devolve os rótulos das ameaças encontradas na entrada (vazio = limpa)."""
    achados = []
    if not isinstance(texto, str):
        return ["tipo-invalido"]
    if len(texto) > MAX_ENTRADA:
        achados.append("entrada-excessiva")
    for rotulo, padrao in _INJECOES:
        if padrao.search(texto):
            achados.append(rotulo)
    return achados


def redigir_saida(texto: str) -> tuple[str, list[str]]:
    """Remove segredos da saída. Devolve (texto_seguro, rótulos_redigidos)."""
    redigidos = []
    for rotulo, padrao in _SEGREDOS:
        if padrao.search(texto):
            redigidos.append(rotulo)
            texto = padrao.sub("[REDIGIDO]", texto)
    return texto, redigidos


class AssistenteTriagem:
    """Resumo e classificação de alertas. Sem ferramentas, sem atuadores (LLM08)."""

    def _modelo(self, alerta: dict) -> str:
        sev = {"critica": "crítico", "alta": "alto", "media": "médio", "baixa": "baixo"}.get(
            alerta.get("severidade", ""), "desconhecido")
        return (f"Alerta {sev}: {alerta.get('titulo', 'evento de segurança')}. "
                f"Origem {alerta.get('origem', 'desconhecida')}. "
                "Sugestão: revisar e, se necessário, encaminhar à coordenação.")

    def responder(self, alerta: dict, contexto_externo: str = "") -> dict:
        """Gera a triagem com os guardrioes aplicados na entrada e na saída."""
        ameacas = inspecionar_entrada(f"{alerta.get('titulo','')} {alerta.get('detalhe','')} {contexto_externo}")
        if ameacas:
            return {"bloqueado": True, "ameacas": ameacas,
                    "texto": "Conteúdo potencialmente malicioso ignorado pelo assistente. "
                             "Alerta encaminhado sem processar o texto suspeito.",
                    "acionou_atuador": False}
        texto, redigidos = redigir_saida(self._modelo(alerta))
        return {"bloqueado": False, "ameacas": [], "redigidos": redigidos,
                "texto": texto, "acionou_atuador": False}   # por construção, nunca aciona nada


MAPA_OWASP_ATLAS = {
    "LLM01 Prompt Injection": "inspecionar_entrada recusa injeção direta e indireta (AML.T0051)",
    "LLM02 Insecure Output Handling": "saída é texto exibido, nunca executada como comando",
    "LLM06 Sensitive Information Disclosure": "redigir_saida remove senhas, chaves e CPF (AML.T0057)",
    "LLM08 Excessive Agency": "o assistente não possui ferramentas nem acesso a atuadores",
}
