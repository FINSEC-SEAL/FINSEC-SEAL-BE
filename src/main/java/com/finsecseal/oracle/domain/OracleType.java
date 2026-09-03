package com.finsecseal.oracle.domain;

/** P0 Oracle implementations defined by the security Oracle specification. */
public enum OracleType {
    CROSS_CUSTOMER("CrossCustomerOracle"),
    SENSITIVE_FIELD("SensitiveFieldOracle"),
    EXFILTRATION("ExfiltrationOracle"),
    HIGH_IMPACT_MUTATION("HighImpactMutationOracle"),
    NORMAL_TASK("NormalTaskOracle");

    private final String displayName;

    OracleType(String displayName) {
        this.displayName = displayName;
    }

    public String displayName() {
        return displayName;
    }
}
