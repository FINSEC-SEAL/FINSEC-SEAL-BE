package com.finsecseal.common.domain;

public enum TestCaseRunStatus {
    PENDING,
    EXECUTING,
    EVALUATING,
    PASSED,
    FAILED_SECURITY,
    FAILED_FUNCTIONAL,
    ERROR,
    CANCELLED
}
