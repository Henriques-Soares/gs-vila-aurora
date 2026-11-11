-- Esquema da nuvem — Rede Comunitária Vila Aurora (somente dados sintéticos)

CREATE TABLE leituras (
    id          uuid PRIMARY KEY,
    espaco      text NOT NULL,
    dispositivo text NOT NULL,
    metrica     text NOT NULL,
    valor       double precision NOT NULL,
    unidade     text NOT NULL,
    extra       jsonb,
    ts          timestamptz NOT NULL,              -- quando o dispositivo mediu
    recebido_em timestamptz NOT NULL DEFAULT now(), -- quando a nuvem recebeu (mede o atraso da reconciliação)
    agente      text NOT NULL                       -- identidade mTLS do agente que entregou
);
CREATE INDEX leituras_ultimas ON leituras (espaco, dispositivo, metrica, ts DESC);
CREATE INDEX leituras_recebido ON leituras (espaco, recebido_em DESC);

CREATE TABLE alarmes (
    id          uuid PRIMARY KEY,
    espaco      text NOT NULL,
    dispositivo text NOT NULL,
    regra       text NOT NULL,
    severidade  text NOT NULL CHECK (severidade IN ('info', 'alto', 'critico')),
    estado      text NOT NULL CHECK (estado IN ('ativo', 'normalizado')),
    mensagem    text NOT NULL,
    valor       double precision,
    ts          timestamptz NOT NULL,
    recebido_em timestamptz NOT NULL DEFAULT now(),
    agente      text NOT NULL
);
CREATE INDEX alarmes_recentes ON alarmes (ts DESC);

CREATE TABLE comandos (
    id          uuid PRIMARY KEY,
    espaco      text NOT NULL,
    dispositivo text NOT NULL,
    acao        text NOT NULL,
    origem      text NOT NULL,                      -- quem decidiu: regra local, operador, etc.
    ts          timestamptz NOT NULL,
    recebido_em timestamptz NOT NULL DEFAULT now(),
    agente      text NOT NULL
);
CREATE INDEX comandos_recentes ON comandos (ts DESC);
