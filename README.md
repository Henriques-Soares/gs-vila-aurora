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
- **Entrada validada no servidor** e consultas sempre parametrizadas.

## Estrutura

```
pki/      CA, emissão, revogação e rotação de certificados
field/    simulador dos dispositivos de campo e cenários de falha
edge/     broker Mosquitto (mTLS + ACL) e agente de borda (regras + buffer)
vpn/      túnel WireGuard (concentrador da nuvem e nós de borda)
cloud/    ingestão (mTLS) e esquema do banco
painel/   painel de supervisão
tests/    testes automatizados
```

## Uso de IA

IA generativa (Claude, da Anthropic) foi usada como apoio na estruturação do projeto, na escrita e
revisão de código e na documentação. A equipe revisou, executou e responde integralmente pelo conteúdo.
