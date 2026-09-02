CREATE TABLE api_idempotency_records (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
    actor_id varchar(120) NOT NULL,
    http_method varchar(10) NOT NULL,
    request_path varchar(1000) NOT NULL,
    idempotency_key varchar(128) NOT NULL,
    request_digest sha256_digest NOT NULL,
    state varchar(20) NOT NULL CHECK (state IN ('PROCESSING', 'COMPLETED')),
    response_status integer CHECK (response_status BETWEEN 100 AND 599),
    response_content_type varchar(200),
    response_location varchar(1000),
    response_trace_id uuid,
    response_body bytea,
    completed_at timestamptz,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_api_idempotency_completion CHECK (
        (state = 'PROCESSING' AND response_status IS NULL AND response_body IS NULL AND completed_at IS NULL)
        OR
        (state = 'COMPLETED' AND response_status IS NOT NULL AND response_trace_id IS NOT NULL
            AND response_body IS NOT NULL AND completed_at IS NOT NULL)
    ),
    CONSTRAINT uq_api_idempotency_scope
        UNIQUE (workspace_id, actor_id, http_method, request_path, idempotency_key)
);

CREATE INDEX ix_api_idempotency_expiry ON api_idempotency_records(expires_at);
