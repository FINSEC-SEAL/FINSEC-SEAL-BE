CREATE TABLE safety_contracts (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
    release_id uuid NOT NULL REFERENCES agent_releases(id) ON DELETE RESTRICT,
    contract_key varchar(100) NOT NULL,
    status varchar(30) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_contract_release_key UNIQUE (release_id, contract_key)
);

CREATE TABLE safety_contract_versions (
    id uuid PRIMARY KEY,
    contract_id uuid NOT NULL REFERENCES safety_contracts(id) ON DELETE RESTRICT,
    version integer NOT NULL CHECK (version > 0),
    state varchar(30) NOT NULL CHECK (state IN ('CANDIDATE', 'VALIDATED', 'APPROVED', 'REJECTED', 'SUPERSEDED')),
    policy_json jsonb NOT NULL,
    policy_hash sha256_digest NOT NULL,
    validator_version varchar(50),
    validation_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by varchar(120) NOT NULL,
    approved_by varchar(120),
    approved_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_contract_version UNIQUE (contract_id, version)
);

CREATE TABLE test_suites (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
    suite_key varchar(100) NOT NULL,
    version varchar(50) NOT NULL,
    fixture_version varchar(50) NOT NULL,
    generation_config_json jsonb NOT NULL,
    suite_hash sha256_digest NOT NULL,
    status varchar(30) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_test_suite_key_version UNIQUE (workspace_id, suite_key, version)
);

CREATE TABLE test_cases (
    id uuid PRIMARY KEY,
    suite_id uuid NOT NULL REFERENCES test_suites(id) ON DELETE RESTRICT,
    case_key varchar(100) NOT NULL,
    case_type varchar(20) NOT NULL CHECK (case_type IN ('ATTACK', 'NORMAL')),
    partition_name varchar(20) NOT NULL CHECK (partition_name IN ('SEED', 'MUTATION', 'HELD_OUT', 'NORMAL')),
    category varchar(80) NOT NULL,
    severity varchar(20) NOT NULL,
    delivery_channel varchar(40) NOT NULL,
    target_tool varchar(100),
    attack_goal varchar(500),
    payload_encrypted text,
    payload_hash sha256_digest NOT NULL,
    preconditions_json jsonb NOT NULL,
    expected_invariant varchar(200) NOT NULL,
    oracle_type varchar(80) NOT NULL,
    generation_source varchar(40) NOT NULL,
    parent_seed_id uuid REFERENCES test_cases(id) ON DELETE RESTRICT,
    hidden_from_patch_generator boolean NOT NULL DEFAULT false,
    expected_result_json jsonb NOT NULL,
    trial_policy_json jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_test_case_suite_key UNIQUE (suite_id, case_key)
);

CREATE TABLE test_runs (
    id uuid PRIMARY KEY,
    release_id uuid NOT NULL REFERENCES agent_releases(id) ON DELETE RESTRICT,
    suite_id uuid REFERENCES test_suites(id) ON DELETE RESTRICT,
    contract_version_id uuid REFERENCES safety_contract_versions(id) ON DELETE RESTRICT,
    mode varchar(30) NOT NULL CHECK (mode IN ('BASELINE', 'SEAL_REPLAY', 'HELD_OUT', 'REGRESSION')),
    status varchar(30) NOT NULL CHECK (status IN ('QUEUED', 'PREPARING', 'RUNNING', 'CANCELLING', 'COMPLETED', 'FAILED', 'CANCELLED')),
    baseline_pair_group_id uuid,
    agent_artifact_fingerprint sha256_digest NOT NULL,
    release_fingerprint sha256_digest NOT NULL,
    config_json jsonb NOT NULL,
    fixture_version varchar(50) NOT NULL,
    fixture_digest sha256_digest NOT NULL,
    model_config_hash sha256_digest NOT NULL,
    random_seed bigint,
    total_cases integer NOT NULL DEFAULT 0 CHECK (total_cases >= 0),
    completed_cases integer NOT NULL DEFAULT 0 CHECK (completed_cases >= 0 AND completed_cases <= total_cases),
    operational_error_count integer NOT NULL DEFAULT 0 CHECK (operational_error_count >= 0),
    cancel_requested_at timestamptz,
    worker_lease_until timestamptz,
    started_at timestamptz,
    completed_at timestamptz,
    summary_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX uq_test_run_active_release_mode
    ON test_runs(release_id, mode)
    WHERE status IN ('QUEUED', 'PREPARING', 'RUNNING', 'CANCELLING');
CREATE INDEX ix_test_run_release_created ON test_runs(release_id, created_at DESC);
CREATE INDEX ix_test_run_status_active ON test_runs(status)
    WHERE status IN ('QUEUED', 'PREPARING', 'RUNNING', 'CANCELLING');

CREATE TABLE test_case_runs (
    id uuid PRIMARY KEY,
    test_run_id uuid NOT NULL REFERENCES test_runs(id) ON DELETE RESTRICT,
    test_case_id uuid NOT NULL REFERENCES test_cases(id) ON DELETE RESTRICT,
    trial_index integer NOT NULL CHECK (trial_index >= 0),
    status varchar(30) NOT NULL,
    security_outcome varchar(40),
    functional_outcome varchar(40),
    variant_hash sha256_digest NOT NULL,
    started_at timestamptz,
    completed_at timestamptz,
    latency_ms bigint,
    token_usage_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    error_code varchar(80),
    result_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_case_run_trial UNIQUE (test_run_id, test_case_id, trial_index)
);

CREATE TABLE run_event_counters (
    run_id uuid PRIMARY KEY REFERENCES test_runs(id) ON DELETE RESTRICT,
    last_sequence bigint NOT NULL DEFAULT 0 CHECK (last_sequence >= 0)
);

CREATE TABLE execution_events (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
    run_id uuid NOT NULL REFERENCES test_runs(id) ON DELETE RESTRICT,
    test_case_run_id uuid REFERENCES test_case_runs(id) ON DELETE RESTRICT,
    trace_id uuid NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    occurred_at timestamptz NOT NULL,
    event_type varchar(60) NOT NULL,
    tool_name varchar(100),
    input_redacted jsonb,
    output_redacted jsonb,
    payload_digest sha256_digest NOT NULL,
    policy_decision_json jsonb,
    reason_code varchar(100),
    metadata_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    prev_event_hash sha256_digest,
    event_hash sha256_digest NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_execution_event_run_sequence UNIQUE (run_id, sequence)
);
CREATE INDEX ix_execution_event_run_sequence ON execution_events(run_id, sequence);
CREATE INDEX ix_execution_event_occurred_at ON execution_events(occurred_at);

CREATE TABLE oracle_results (
    id uuid PRIMARY KEY,
    test_case_run_id uuid NOT NULL REFERENCES test_case_runs(id) ON DELETE RESTRICT,
    source_event_id uuid REFERENCES execution_events(id) ON DELETE RESTRICT,
    oracle_type varchar(80) NOT NULL,
    oracle_version varchar(50) NOT NULL,
    outcome varchar(40) NOT NULL,
    reason_code varchar(100) NOT NULL,
    invariant_id varchar(100) NOT NULL,
    evidence_json jsonb NOT NULL,
    evidence_digest sha256_digest NOT NULL,
    evaluated_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_oracle_case_type_invariant UNIQUE (test_case_run_id, oracle_type, invariant_id)
);

CREATE TABLE findings (
    id uuid PRIMARY KEY,
    release_id uuid NOT NULL REFERENCES agent_releases(id) ON DELETE RESTRICT,
    source_oracle_result_id uuid NOT NULL UNIQUE REFERENCES oracle_results(id) ON DELETE RESTRICT,
    category varchar(80) NOT NULL,
    severity varchar(20) NOT NULL,
    title varchar(300) NOT NULL,
    status varchar(30) NOT NULL,
    violated_invariant varchar(200) NOT NULL,
    root_cause_json jsonb NOT NULL,
    finding_group_key varchar(100),
    first_seen_run_id uuid NOT NULL REFERENCES test_runs(id) ON DELETE RESTRICT,
    latest_seen_run_id uuid NOT NULL REFERENCES test_runs(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_finding_release_status_severity ON findings(release_id, status, severity);

CREATE TABLE patch_proposals (
    id uuid PRIMARY KEY,
    finding_id uuid NOT NULL REFERENCES findings(id) ON DELETE RESTRICT,
    base_contract_version_id uuid REFERENCES safety_contract_versions(id) ON DELETE RESTRICT,
    state varchar(30) NOT NULL,
    root_cause text NOT NULL,
    recommended_rule_json jsonb NOT NULL,
    policy_diff_json jsonb NOT NULL,
    normal_workflow_impact_json jsonb NOT NULL,
    rollback_json jsonb NOT NULL,
    generation_model_meta_json jsonb NOT NULL,
    validation_json jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE patch_approvals (
    id uuid PRIMARY KEY,
    patch_proposal_id uuid NOT NULL UNIQUE REFERENCES patch_proposals(id) ON DELETE RESTRICT,
    resulting_contract_version_id uuid REFERENCES safety_contract_versions(id) ON DELETE RESTRICT,
    decision varchar(20) NOT NULL CHECK (decision IN ('APPROVED', 'REJECTED')),
    reviewer_actor_id varchar(120) NOT NULL,
    comment varchar(1000) NOT NULL,
    base_hash sha256_digest NOT NULL,
    result_hash sha256_digest,
    decided_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE replay_links (
    id uuid PRIMARY KEY,
    finding_id uuid NOT NULL REFERENCES findings(id) ON DELETE RESTRICT,
    baseline_case_run_id uuid NOT NULL REFERENCES test_case_runs(id) ON DELETE RESTRICT,
    replay_case_run_id uuid NOT NULL UNIQUE REFERENCES test_case_runs(id) ON DELETE RESTRICT,
    same_agent_artifact_fingerprint boolean NOT NULL,
    same_fixture_digest boolean NOT NULL,
    same_model_config boolean NOT NULL,
    same_variant_hash boolean NOT NULL,
    expected_policy_difference boolean NOT NULL,
    comparison_json jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE release_decisions (
    id uuid PRIMARY KEY,
    release_id uuid NOT NULL REFERENCES agent_releases(id) ON DELETE RESTRICT,
    decision varchar(20) NOT NULL CHECK (decision IN ('PASS', 'REVIEW', 'BLOCKED')),
    gate_policy_version varchar(50) NOT NULL,
    input_snapshot_json jsonb NOT NULL,
    input_digest sha256_digest NOT NULL,
    proposed_at timestamptz NOT NULL,
    confirmed_by varchar(120) NOT NULL,
    confirmed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_release_decision_digest UNIQUE (release_id, input_digest)
);

CREATE TABLE release_attestations (
    id uuid PRIMARY KEY,
    release_decision_id uuid NOT NULL UNIQUE REFERENCES release_decisions(id) ON DELETE RESTRICT,
    format_version varchar(30) NOT NULL,
    document_json jsonb NOT NULL,
    document_hash sha256_digest NOT NULL,
    html_content text NOT NULL,
    generated_at timestamptz NOT NULL,
    disclaimer_version varchar(30) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_records (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
    actor_id varchar(120) NOT NULL,
    action varchar(100) NOT NULL,
    resource_type varchar(80) NOT NULL,
    resource_id uuid NOT NULL,
    before_digest sha256_digest,
    after_digest sha256_digest,
    metadata_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_audit_resource ON audit_records(resource_type, resource_id, occurred_at DESC);

CREATE TABLE evidence_references (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
    owner_type varchar(80) NOT NULL,
    owner_id uuid NOT NULL,
    evidence_type varchar(80) NOT NULL,
    source_event_id uuid REFERENCES execution_events(id) ON DELETE RESTRICT,
    digest sha256_digest NOT NULL,
    redacted_summary_json jsonb NOT NULL,
    tested_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_evidence_owner ON evidence_references(owner_type, owner_id);

CREATE TABLE decision_invalidations (
    id uuid PRIMARY KEY,
    release_decision_id uuid NOT NULL REFERENCES release_decisions(id) ON DELETE RESTRICT,
    reasons_json jsonb NOT NULL,
    invalidated_by varchar(120) NOT NULL,
    invalidated_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
