-- Contas do painel, MFA e trilha de auditoria (RT-09).
-- Idempotente: roda na criação do banco e também pelo comando `admin migrar`.

DO $$
BEGIN
    -- versões anteriores do laboratório criavam o papel somente-leitura `painel_ro`
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'painel_ro')
       AND NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'painel_app') THEN
        ALTER ROLE painel_ro RENAME TO painel_app;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS usuarios (
    usuario           text PRIMARY KEY CHECK (usuario ~ '^[a-z0-9._-]{3,40}$'),
    nome              text NOT NULL,
    perfil            text NOT NULL CHECK (perfil IN ('operador', 'tecnico', 'coordenacao', 'auditor')),
    senha_hash        text NOT NULL,
    totp_segredo      text,
    totp_ativo        boolean NOT NULL DEFAULT false,
    totp_ultimo_passo bigint  NOT NULL DEFAULT 0,      -- impede reutilizar o mesmo código (replay)
    falhas            integer NOT NULL DEFAULT 0,
    bloqueado_ate     timestamptz,
    ativo             boolean NOT NULL DEFAULT true,
    criado_em         timestamptz NOT NULL DEFAULT now(),
    ultimo_login      timestamptz
);

CREATE TABLE IF NOT EXISTS auditoria (
    id        bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts        timestamptz NOT NULL DEFAULT now(),
    usuario   text,
    perfil    text,
    acao      text NOT NULL,
    resultado text NOT NULL,
    detalhe   text,
    origem    text
);
CREATE INDEX IF NOT EXISTS auditoria_recentes ON auditoria (ts DESC);

-- Privilégio mínimo do painel: lê a telemetria, lê as contas, atualiza apenas os campos de
-- sessão/MFA e só ACRESCENTA linhas na auditoria. Não cria conta, não troca senha nem perfil,
-- não apaga nada.
GRANT SELECT ON leituras, alarmes, comandos, usuarios, auditoria TO painel_app;
GRANT UPDATE (totp_segredo, totp_ativo, totp_ultimo_passo, falhas, bloqueado_ate, ultimo_login)
      ON usuarios TO painel_app;
GRANT INSERT ON auditoria TO painel_app;
