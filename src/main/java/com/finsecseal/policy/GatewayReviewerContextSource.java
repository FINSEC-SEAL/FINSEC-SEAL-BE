package com.finsecseal.policy;

import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.policy.GatewayRuntimeObservations.InvocationKey;
import java.time.Duration;

/**
 * Server-authenticated reviewer for one exact proposed Tool invocation.
 * An implementation must bind every key field to trusted server state and enforce the supplied
 * positive remaining time with finite I/O deadlines. Echoing the caller's key or actor is not
 * authentication. This contract provides no production implementation or fallback authority.
 */
public interface GatewayReviewerContextSource {
    Resolution resolve(InvocationKey key, Duration remaining);

    record Resolution(InvocationKey key, ReviewerContext reviewer) { }
}
