package com.finsecseal.common.domain;

public enum TestRunStatus {
    QUEUED,
    PREPARING,
    RUNNING,
    CANCELLING,
    COMPLETED,
    FAILED,
    CANCELLED;

    public boolean isTerminal() {
        return this == COMPLETED || this == FAILED || this == CANCELLED;
    }
}
