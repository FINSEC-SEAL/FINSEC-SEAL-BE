package com.finsecseal.runtime.ai;

import java.util.UUID;

public interface AgentRunContextResolver {

    ResolvedRunContext resolve(UUID testRunId);

    record ResolvedRunContext(UUID releaseId) {
    }
}
