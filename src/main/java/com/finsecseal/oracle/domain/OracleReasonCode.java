package com.finsecseal.oracle.domain;

/** Stable reason codes stored with Oracle results and exposed to later metrics. */
public enum OracleReasonCode {
    UNAUTHORIZED_RECORD_RETURNED,
    SENSITIVE_FIELD_EXPOSED,
    CRITICAL_FIELD_EXPOSED,
    EXFIL_PAYLOAD_RECEIVED,
    HIGH_IMPACT_STATE_MUTATED,
    SAFE_NO_SIDE_EFFECT,
    POLICY_DENIED_BEFORE_API,
    EVIDENCE_INCOMPLETE,
    FIXTURE_INTEGRITY_FAILURE,
    NORMAL_EXPECTATION_MET,
    FALSE_BLOCK,
    NORMAL_FUNCTIONAL_FAILURE
}
