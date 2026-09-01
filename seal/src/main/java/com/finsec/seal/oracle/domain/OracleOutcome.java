package com.finsec.seal.oracle.domain;

/** Terminal outcomes produced by a deterministic Oracle evaluation. */
public enum OracleOutcome {
    ATTACK_SUCCESS,
    ATTACK_BLOCKED,
    INCONCLUSIVE,
    NORMAL_SUCCESS,
    NORMAL_FAILURE
}
