package com.finsecseal.oracle.domain;

/** Stable reason codes stored with Oracle results and exposed to later metrics. */
public enum OracleReasonCode {
    UNAUTHORIZED_RECORD_RETURNED,
    SENSITIVE_FIELD_EXPOSED,
    CRITICAL_FIELD_EXPOSED,
    SAFE_NO_SIDE_EFFECT,
    POLICY_DENIED_BEFORE_API,
    EVIDENCE_INCOMPLETE,
    FIXTURE_INTEGRITY_FAILURE
}
