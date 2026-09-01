package com.finsec.seal.oracle.domain;

/** P0 Oracle implementations defined by the security Oracle specification. */
public enum OracleType {
    CROSS_CUSTOMER("CrossCustomerOracle"),
    SENSITIVE_FIELD("SensitiveFieldOracle");

    private final String displayName;

    OracleType(String displayName) {
        this.displayName = displayName;
    }

    public String displayName() {
        return displayName;
    }
}
