-- SIEM: logs de segurança centralizados, alertas, respostas e fila de aprovação (RT-12, 13, 15).
-- Idempotente: aplicado na criação do banco e também por `admin migrar`.

CREATE TABLE IF NOT EXISTS eventos_seg (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts          timestamptz NOT NULL,                 -- quando o componente registrou (relógio comum dos containers)
    recebido_em timestamptz NOT NULL DEFAULT now(),   -- quando o SIEM recebeu
    fonte       text NOT NULL,                        -- componente de origem
    nivel       text,
    evento      text NOT NULL,
    origem      text,                                 -- IP/identidade associada, quando houver
    dados       jsonb
);
CREATE INDEX IF NOT EXISTS eventos_seg_recentes ON eventos_seg (recebido_em DESC);
CREATE INDEX IF NOT EXISTS eventos_seg_fonte ON eventos_seg (fonte, evento, recebido_em DESC);

CREATE TABLE IF NOT EXISTS alertas_seg (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts          timestamptz NOT NULL DEFAULT now(),
    regra       text NOT NULL,
    severidade  text NOT NULL CHECK (severidade IN ('baixa', 'media', 'alta', 'critica')),
    titulo      text NOT NULL,
    detalhe     text,
    fonte       text,
    origem      text,
    tecnica     text,                                 -- técnica MITRE ATT&CK associada
    resposta    text                                  -- resposta automática aplicada, se houve
);
CREATE INDEX IF NOT EXISTS alertas_seg_recentes ON alertas_seg (ts DESC);

-- Fila de ações de ALTO IMPACTO: o SIEM nunca as executa sozinho (RT-15).
-- Só a coordenação aprova no painel; auditor acompanha.
CREATE TABLE IF NOT EXISTS acoes_seg (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    criada_em    timestamptz NOT NULL DEFAULT now(),
    acao         text NOT NULL,
    alvo         text NOT NULL,
    motivo       text NOT NULL,
    severidade   text NOT NULL,
    status       text NOT NULL DEFAULT 'pendente' CHECK (status IN ('pendente', 'aprovada', 'recusada')),
    decidida_em  timestamptz,
    decidida_por text
);
CREATE INDEX IF NOT EXISTS acoes_seg_pendentes ON acoes_seg (status, criada_em DESC);

-- Leitura incremental dos comandos pelo SIEM (cursor recebido_em, id)
CREATE INDEX IF NOT EXISTS comandos_cursor_siem ON comandos (recebido_em, id);

-- Contenção automática de baixo risco (RT-15): origem sinalizada para os operadores.
CREATE TABLE IF NOT EXISTS quarentena (
    origem    text PRIMARY KEY,
    desde     timestamptz NOT NULL DEFAULT now(),
    motivo    text NOT NULL,
    regra     text NOT NULL
);

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'siem_rw') THEN
        -- a senha é definida por 05-siem-senha.sh (instalação nova) ou por `admin migrar`
        CREATE ROLE siem_rw LOGIN;
    END IF;
END $$;

GRANT USAGE ON SCHEMA public TO siem_rw;
GRANT INSERT, SELECT, DELETE ON eventos_seg TO siem_rw;
GRANT INSERT ON alertas_seg TO siem_rw;
GRANT INSERT, SELECT ON acoes_seg TO siem_rw;
GRANT INSERT, SELECT ON quarentena TO siem_rw;
GRANT SELECT ON comandos TO siem_rw;              -- o SIEM lê os comandos já centralizados (regra D)
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO siem_rw;

-- O painel (papel painel_app) lê os alertas e a fila, e a coordenação decide as ações pendentes.
GRANT SELECT ON eventos_seg, alertas_seg, acoes_seg, quarentena TO painel_app;
GRANT UPDATE (status, decidida_em, decidida_por) ON acoes_seg TO painel_app;
