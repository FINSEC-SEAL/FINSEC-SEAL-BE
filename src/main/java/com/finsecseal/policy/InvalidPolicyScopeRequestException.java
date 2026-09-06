package com.finsecseal.policy;

/**
 * Signals malformed caller-supplied scope identities before policy judgment.
 * A Gateway integration must translate this to INVALID_REQUEST_SCHEMA.
 */
public final class InvalidPolicyScopeRequestException
        extends IllegalArgumentException {

    public InvalidPolicyScopeRequestException(String message) {
        super(message);
    }
}
