# Rede Comunitária Vila Aurora — Infraestrutura Segura e Resiliente

FIAP · Global Solution 2026.2 · Cybersecurity · Desafio *Resilient Community Infrastructure*
Protótipo funcional (entregável **E2**). Turma 4ECR.

| Integrante | RM |
|---|---|
| Henriques Paulo da Silva Soares | RM551033 |
| Raul Prado Reis | RM99270 |

> Laboratório acadêmico. Todos os dados são **sintéticos** e toda atividade ofensiva acontece
> apenas neste ambiente isolado.

## Arquitetura

Quatro camadas, com um nó de borda autônomo por espaço comunitário
(Centro Comunitário, Escola, UBS, Horta e Cozinha, Abrigo):

| Camada | Serviços (containers) | Função |
|---|---|---|
| Campo | `campo-<espaco>` | Dispositivos simulados; cada um com o próprio certificado X.509 |
| Borda | `borda-<espaco>-broker`, `borda-<espaco>-agente`, `borda-<espaco>-vpn` | Broker MQTT só com mTLS, regras locais, buffer store-and-forward, ponta do túnel WireGuard |
| Nuvem | `nuvem-vpn`, `nuvem-ingest`, `nuvem-db` | Concentrador WireGuard, ingestão HTTPS com mTLS + CRL (só dentro do túnel), PostgreSQL com privilégio mínimo |
| Supervisão | `painel` | Painel web acessível, com login em duas etapas (senha + TOTP) e perfis de acesso |
| Segurança | `siem` | Centraliza os logs de segurança, detecta (4 regras) e responde: contém sozinho o de baixo risco e encaminha o de alto impacto para aprovação humana |

Segmentos de rede: `campo-<espaco>` (isolado por espaço), `wan` (enlace não confiável, onde só trafega
WireGuard), túnel `10.8.0.0/24` (a ingestão só escuta em `10.8.0.1`), `nuvem` (interno) e `operadores`
(único com porta publicada, apenas em `127.0.0.1`).

## Como reproduzir

Pré-requisitos: Docker Desktop (ou Docker Engine + Compose v2.24+) e Git.

```bash
git clone https://github.com/Henriques-Soares/gs-vila-aurora.git
cd gs-vila-aurora

# 1) PKI do projeto, segredos e chaves da VPN (nada disso vai para o Git)
docker compose run --rm --build setup

# 2) Sobe o laboratório
docker compose up -d --build
docker compose ps

# 3) Contas fictícias do painel (as senhas iniciais aparecem uma única vez)
docker compose run --rm admin migrar      # tabelas de contas, auditoria e SIEM
docker compose run --rm admin semear
```

Painel: <http://127.0.0.1:8080>. No primeiro acesso, cada conta cadastra o segundo fator em um
aplicativo autenticador (Google Authenticator, Microsoft Authenticator, Aegis).

| Conta | Perfil | Pode |
|---|---|---|
| `operador.demo` | Operador(a) | Ver o painel e os avisos |
| `tecnico.demo` | Técnico(a) | + ver os comandos enviados aos equipamentos |
| `coordenacao.demo` | Coordenação | + ver a auditoria e aprovar ações de alto impacto |
| `auditor.demo` | Auditor(a) | Ver painel, comandos e auditoria (não aprova ações) |

Outros comandos de contas: `admin listar`, `admin criar <usuario> <perfil> "<nome>"`, `admin redefinir <usuario>`.
Quem já tinha o laboratório de uma versão anterior deve rodar antes `docker compose run --rm admin migrar`.

### Verificações

```bash
# mTLS: sem certificado não entra; com certificado da CA do projeto entra (RT-04)
docker compose exec campo-ubs python verificar_mtls.py

# VPN WireGuard: pares, último handshake e tráfego de cada nó de borda (RT-06)
docker compose exec nuvem-vpn wg show

# Segmentação: só o caminho necessário está aberto (RT-07)
docker compose exec borda-ubs-agente python verificar_rede.py
docker compose exec campo-ubs python verificar_rede.py

# SIEM: dispara as regras de detecção e mostra os alertas (RT-13)
docker compose exec siem python simular.py tudo
docker compose logs --since 2m siem        # alertas, respostas automáticas e ações pendentes

# Certificados emitidos e estado (válido/revogado)
docker compose run --rm pki listar

# Operação local: a câmara fria esquenta e a BORDA alarma, com ou sem internet (RT-02)
docker compose exec campo-ubs python cenario.py ligar camara_fria_falha
docker compose logs -f borda-ubs-agente
docker compose exec campo-ubs python cenario.py desligar camara_fria_falha
```

Cenários disponíveis: `camara_fria_falha` (UBS), `alagamento` (Abrigo), `vazamento` (Escola).

### Revogação e rotação de certificado (RT-05)

```bash
docker compose run --rm pki revogar ubs-fechadura
docker compose restart borda-ubs-broker        # o broker passa a aplicar a nova CRL
docker compose logs borda-ubs-broker           # conexão do dispositivo revogado é recusada

docker compose run --rm pki rotacionar ubs-fechadura
docker compose restart borda-ubs-broker campo-ubs
```

### Queda do link com a nuvem (RT-02)

```bash
docker network disconnect vila-aurora_wan vila-aurora-borda-ubs-vpn-1   # derruba a "internet" da UBS
docker compose logs -f borda-ubs-agente                                 # segue operando e acumulando
docker network connect vila-aurora_wan vila-aurora-borda-ubs-vpn-1      # link volta: reconciliação
```

## SIEM: detecção e resposta (RT-12, 13, 15)

O serviço `siem` centraliza os eventos de segurança (relógios já sincronizados, pois todos os
containers compartilham o relógio do host — mantido por NTP), guarda-os com retenção e aplica
quatro regras de detecção, cada uma ligada a uma falha do incidente INC-VA-0712:

| Regra | O que detecta | Origem | MITRE ATT&CK |
|---|---|---|---|
| A | Acesso não autorizado repetido na nuvem | ingestão (mTLS) | T1110 / T1133 |
| B | Assinatura de SQL Injection no painel | painel (WAF) | T1190 |
| C | Dispositivo/credencial sem certificado válido | ingestão (mTLS) | T1190 / T1078 |
| D | Comando de atuador fora do perfil esperado | comandos centralizados | T0831 / T0836 (ICS) |

**Resposta (RT-15).** O de baixo risco é automático: a origem ofensora entra em quarentena e o
alerta é registrado. O de alto impacto — mexer num atuador, revogar um certificado — o SIEM
**nunca** executa sozinho: cria uma ação pendente que só a **coordenação** aprova ou recusa na
página **Segurança** do painel. Cada ação é decidida uma única vez, com quem e quando, e a decisão
vai para a trilha de auditoria. Técnico e auditor acompanham, mas não decidem.

Por desenho, a nuvem não tem canal para comandar atuadores (a borda só envia dados para a nuvem):
mesmo quem comprometesse a nuvem não conseguiria ligar ou desligar uma bomba. A ação aprovada é
executada no local pelo técnico.

Para demonstrar as regras A, B e C sem nenhum ataque real, há um harness de teste controlado que
injeta eventos representativos na coleta:

```bash
docker compose exec siem python simular.py tudo
docker compose logs --since 2m siem
```

A regra D também dispara a partir de um comando de atuador real, lido do banco, cuja origem não
seja uma regra local da borda. Para validar todo o SQL do SIEM contra um PostgreSQL 16 real, o
projeto foi testado com o mesmo texto SQL do código (leitura incremental por cursor
`(recebido_em, id)`, já que o `id` dos comandos é UUID).

## IA defensiva e proteção do LLM (RT-16, 17)

**Detecção de anomalias (RT-16).** Um Isolation Forest (`ia/anomalia.py`) aprende o comportamento
normal dos sensores e sinaliza leituras atípicas (câmara fria esquentando, reservatório esvaziando,
alagamento). O desempenho é medido contra um conjunto rotulado — precisão, revocação e taxa de
falsos positivos.

**Proteção do assistente (RT-17).** Um assistente de triagem resume alertas em linguagem simples.
Ele não tem ferramentas nem acesso a atuadores (defesa contra agência excessiva), e `ia/guardrioes.py`
valida a entrada (injeção direta e indireta) e a saída (redação de segredos), com os riscos mapeados
no OWASP Top 10 para LLM e no MITRE ATLAS.

```bash
docker compose run --rm ia                                    # métricas do detector de anomalias
docker compose run --rm ia guardrioes_demo.py                 # guardrioes contra tentativas de abuso
docker compose run --rm -e PAINEL_DB_SENHA=... ia anomalia.py --banco   # pontua a telemetria real
```

## Testes automatizados

Rodam sem Docker (Python 3.11+, bash e OpenSSL): regras locais, mTLS e revogação na ingestão,
fluxo campo → borda → nuvem, queda de link e reconciliação sem perda.

```bash
python -m unittest discover -s tests -v
```

## Segurança

- **Sem segredo compartilhado:** cada dispositivo, broker e agente tem par de chaves e certificado próprios,
  emitidos pela CA do projeto (`pki/pki.sh`). A chave da CA nunca é montada em container de serviço.
- **Nada sensível no Git:** `pki/out/` e `segredos/` são gerados localmente e estão no `.gitignore`.
- **VPN moderna:** WireGuard (Curve25519, ChaCha20-Poly1305) com par de chaves por nó e chave
  pré-compartilhada por enlace; a ingestão não tem porta aberta fora do túnel.
- **Acesso ao painel:** senha (hash scrypt) + TOTP obrigatório, perfis de acesso (RBAC) verificados no
  servidor, bloqueio após 5 tentativas, proteção CSRF, sessão de 30 minutos e trilha de auditoria.
- **Menor privilégio:** ACL por dispositivo no broker; `ingest_rw` só insere; `painel_app` lê a telemetria,
  atualiza apenas campos de sessão/MFA e só acrescenta linhas na auditoria (contas são geridas fora do painel);
  serviços rodam sem root; apenas o painel publica porta, e só em `127.0.0.1`.
- **Entrada validada no servidor** e consultas sempre parametrizadas; um detector de assinaturas
  (WAF) recusa entradas maliciosas e avisa o SIEM.
- **SIEM com privilégio mínimo:** o papel `siem_rw` só grava eventos/alertas e lê os comandos;
  não altera a operação. A contenção automática fica restrita a ações de baixo risco.

## Estrutura

```
pki/      CA, emissão, revogação e rotação de certificados
field/    simulador dos dispositivos de campo e cenários de falha
edge/     broker Mosquitto (mTLS + ACL) e agente de borda (regras + buffer)
vpn/      túnel WireGuard (concentrador da nuvem e nós de borda)
cloud/    ingestão (mTLS) e esquema do banco
siem/     coleta de logs, regras de detecção e resposta
ia/       detecção de anomalias (Isolation Forest) e guardrioes do LLM
painel/   painel de supervisão
tests/    testes automatizados
```

## Uso de IA

IA generativa (Claude, da Anthropic) foi usada como apoio na estruturação do projeto, na escrita e
revisão de código e na documentação. A equipe revisou, executou e responde integralmente pelo conteúdo.
