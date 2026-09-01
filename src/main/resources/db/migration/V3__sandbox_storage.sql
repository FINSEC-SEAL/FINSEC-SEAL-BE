CREATE TABLE sandbox_namespaces (
    id uuid PRIMARY KEY REFERENCES test_runs(id) ON DELETE RESTRICT,
    fixture_version varchar(50) NOT NULL,
    fixture_digest sha256_digest NOT NULL,
    state varchar(20) NOT NULL CHECK (state IN ('ACTIVE', 'SEALED', 'EXPIRED')),
    created_at timestamptz NOT NULL DEFAULT now(),
    sealed_at timestamptz,
    expires_at timestamptz NOT NULL
);

CREATE TABLE sandbox_customers (
    namespace_id uuid NOT NULL REFERENCES sandbox_namespaces(id) ON DELETE CASCADE,
    customer_key varchar(80) NOT NULL,
    display_name_token varchar(120) NOT NULL,
    profile_json jsonb NOT NULL,
    classification_json jsonb NOT NULL,
    row_version bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (namespace_id, customer_key)
);

CREATE TABLE sandbox_loan_cases (
    namespace_id uuid NOT NULL REFERENCES sandbox_namespaces(id) ON DELETE CASCADE,
    case_key varchar(80) NOT NULL,
    applicant_customer_key varchar(80) NOT NULL,
    status varchar(40) NOT NULL,
    allowed_document_ids_json jsonb NOT NULL,
    context_json jsonb NOT NULL,
    row_version bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (namespace_id, case_key),
    FOREIGN KEY (namespace_id, applicant_customer_key)
        REFERENCES sandbox_customers(namespace_id, customer_key) ON DELETE RESTRICT
);

CREATE TABLE sandbox_documents (
    namespace_id uuid NOT NULL REFERENCES sandbox_namespaces(id) ON DELETE CASCADE,
    document_key varchar(80) NOT NULL,
    case_key varchar(80) NOT NULL,
    owner_customer_key varchar(80) NOT NULL,
    document_type varchar(60) NOT NULL,
    content_encrypted text NOT NULL,
    content_digest sha256_digest NOT NULL,
    trust_level varchar(40) NOT NULL,
    classification_json jsonb NOT NULL,
    PRIMARY KEY (namespace_id, document_key),
    FOREIGN KEY (namespace_id, case_key)
        REFERENCES sandbox_loan_cases(namespace_id, case_key) ON DELETE RESTRICT,
    FOREIGN KEY (namespace_id, owner_customer_key)
        REFERENCES sandbox_customers(namespace_id, customer_key) ON DELETE RESTRICT
);

CREATE TABLE sandbox_loan_policies (
    namespace_id uuid NOT NULL REFERENCES sandbox_namespaces(id) ON DELETE CASCADE,
    policy_key varchar(80) NOT NULL,
    version varchar(50) NOT NULL,
    rule_code varchar(80) NOT NULL,
    requirement_json jsonb NOT NULL,
    content_digest sha256_digest NOT NULL,
    PRIMARY KEY (namespace_id, policy_key, version)
);

CREATE TABLE sandbox_review_notes (
    namespace_id uuid NOT NULL REFERENCES sandbox_namespaces(id) ON DELETE CASCADE,
    note_key varchar(80) NOT NULL,
    case_key varchar(80) NOT NULL,
    review_result_json jsonb NOT NULL,
    created_by_agent varchar(100) NOT NULL,
    row_version bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (namespace_id, note_key),
    FOREIGN KEY (namespace_id, case_key)
        REFERENCES sandbox_loan_cases(namespace_id, case_key) ON DELETE RESTRICT
);

CREATE TABLE sandbox_loan_decisions (
    namespace_id uuid NOT NULL REFERENCES sandbox_namespaces(id) ON DELETE CASCADE,
    case_key varchar(80) NOT NULL,
    decision varchar(30) NOT NULL,
    decided_by varchar(120) NOT NULL,
    row_version bigint NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (namespace_id, case_key),
    FOREIGN KEY (namespace_id, case_key)
        REFERENCES sandbox_loan_cases(namespace_id, case_key) ON DELETE RESTRICT
);

CREATE TABLE sandbox_exfil_events (
    namespace_id uuid NOT NULL REFERENCES sandbox_namespaces(id) ON DELETE CASCADE,
    event_key uuid NOT NULL,
    url_label varchar(120) NOT NULL,
    body_redacted jsonb NOT NULL,
    sensitive_token_hashes_json jsonb NOT NULL,
    received_at timestamptz NOT NULL,
    PRIMARY KEY (namespace_id, event_key)
);
