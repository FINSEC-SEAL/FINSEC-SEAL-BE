package com.finsecseal.policy;

/**
 * Signals missing or ambiguous server-resolved scope facts.
 * A Gateway integration must translate this to CONTEXT_INTEGRITY_FAILURE.
 */
public final class PolicyScopeContextIntegrityException
        extends IllegalStateException {

    public PolicyScopeContextIntegrityException(String message) {
        super(message);
    }
}
