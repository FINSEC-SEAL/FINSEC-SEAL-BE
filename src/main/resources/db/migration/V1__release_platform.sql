CREATE DOMAIN sha256_digest AS varchar(71)
    CHECK (VALUE ~ '^sha256:[0-9a-f]{64}$');

CREATE TABLE workspaces (
    id uuid PRIMARY KEY,
    name varchar(120) NOT NULL,
    mode varchar(20) NOT NULL CHECK (mode IN ('DEMO')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE agents (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
    agent_key varchar(80) NOT NULL,
    name varchar(100) NOT NULL,
    purpose_summary varchar(500) NOT NULL,
    status varchar(20) NOT NULL CHECK (status IN ('ACTIVE', 'ARCHIVED')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_agent_workspace_key UNIQUE (workspace_id, agent_key)
);

CREATE TABLE agent_releases (
    id uuid PRIMARY KEY,
    agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,
    version varchar(50) NOT NULL,
    business_purpose varchar(100) NOT NULL,
    manifest_schema_version varchar(20) NOT NULL,
    manifest_json jsonb NOT NULL,
    agent_artifact_fingerprint sha256_digest NOT NULL,
    release_fingerprint sha256_digest NOT NULL,
    safety_contract_hash sha256_digest,
    lifecycle_state varchar(30) NOT NULL,
    effective_status varchar(30) NOT NULL,
    revalidation_reason_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    analyzed_at timestamptz,
    last_tested_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_release_lifecycle CHECK (lifecycle_state IN (
        'DRAFT', 'ANALYZED', 'TESTING', 'REMEDIATION', 'VERIFYING',
        'DECISION_PENDING', 'PASS', 'REVIEW', 'BLOCKED', 'NEEDS_REVALIDATION'
    )),
    CONSTRAINT ck_release_effective_status CHECK (effective_status IN (
        'DRAFT', 'ANALYZED', 'TESTING', 'REMEDIATION', 'VERIFYING',
        'DECISION_PENDING', 'PASS', 'REVIEW', 'BLOCKED', 'NEEDS_REVALIDATION'
    )),
    CONSTRAINT uq_release_agent_version UNIQUE (agent_id, version),
    CONSTRAINT uq_release_agent_fingerprint UNIQUE (agent_id, release_fingerprint)
);

CREATE TABLE release_artifacts (
    id uuid PRIMARY KEY,
    release_id uuid NOT NULL REFERENCES agent_releases(id) ON DELETE RESTRICT,
    artifact_type varchar(40) NOT NULL,
    name varchar(160) NOT NULL,
    content_json jsonb,
    content_text_encrypted text,
    sha256 sha256_digest NOT NULL,
    canonicalization_version varchar(40) NOT NULL,
    sensitivity varchar(30) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_release_artifact_type CHECK (artifact_type IN (
        'MODEL_CONFIG', 'SYSTEM_PROMPT', 'TOOL_SCHEMA', 'TOOL_DESCRIPTION', 'RAG_CONFIG',
        'BUSINESS_PURPOSE', 'BUSINESS_WORKFLOW', 'HUMAN_BOUNDARY', 'RUNTIME_CONTEXT', 'SAFETY_CONTRACT'
    )),
    CONSTRAINT ck_release_artifact_sensitivity CHECK (sensitivity IN (
        'NORMAL', 'PII', 'SENSITIVE_PII', 'FINANCIAL', 'CREDIT', 'SECRET'
    )),
    CONSTRAINT uq_release_artifact_name UNIQUE (release_id, artifact_type, name)
);

CREATE TABLE tool_definitions (
    id uuid PRIMARY KEY,
    tool_key varchar(100) NOT NULL,
    version varchar(50) NOT NULL,
    operation varchar(30) NOT NULL,
    input_schema_json jsonb NOT NULL,
    output_schema_json jsonb NOT NULL,
    description varchar(1000) NOT NULL,
    trust_level varchar(40) NOT NULL,
    risk_level varchar(20) NOT NULL,
    data_classifications_json jsonb NOT NULL,
    side_effect_type varchar(40) NOT NULL,
    adapter_key varchar(100) NOT NULL,
    schema_hash sha256_digest NOT NULL,
    description_hash sha256_digest NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_tool_definition_key_version UNIQUE (tool_key, version)
);

CREATE TABLE release_tools (
    release_id uuid NOT NULL REFERENCES agent_releases(id) ON DELETE RESTRICT,
    tool_definition_id uuid NOT NULL REFERENCES tool_definitions(id) ON DELETE RESTRICT,
    enabled boolean NOT NULL DEFAULT true,
    ordinal integer NOT NULL CHECK (ordinal >= 0),
    PRIMARY KEY (release_id, tool_definition_id)
);

CREATE TABLE rag_sources (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
    source_key varchar(100) NOT NULL,
    version varchar(50) NOT NULL,
    trust_level varchar(40) NOT NULL,
    content_digest sha256_digest NOT NULL,
    config_json jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_rag_source_key_version UNIQUE (workspace_id, source_key, version)
);

CREATE TABLE release_rag_sources (
    release_id uuid NOT NULL REFERENCES agent_releases(id) ON DELETE RESTRICT,
    rag_source_id uuid NOT NULL REFERENCES rag_sources(id) ON DELETE RESTRICT,
    retrieval_config_json jsonb NOT NULL,
    config_hash sha256_digest NOT NULL,
    PRIMARY KEY (release_id, rag_source_id)
);

CREATE INDEX ix_agent_release_agent_created ON agent_releases(agent_id, created_at DESC);
CREATE INDEX ix_agent_release_fingerprint ON agent_releases(release_fingerprint);

INSERT INTO workspaces (id, name, mode)
VALUES ('0198f1e2-0000-7000-8000-000000000001', 'FINSEC SEAL Demo', 'DEMO');
