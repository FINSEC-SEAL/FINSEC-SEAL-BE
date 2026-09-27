package com.finsecseal.sandbox.tool;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.policy.GatewayRuntimeObservations.InvocationKey;
import com.finsecseal.sandbox.SandboxExecutionContext;
import java.sql.Connection;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.function.LongSupplier;
import javax.sql.DataSource;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Partial B fact source for one fixed-operation adapter, not a Gateway observations provider.
 * The stored proposal identifies the call; the adapter implementation defines its operation.
 */
public final class StoredGatewayFixedOperationSource {

    private static final Duration MAX_BUDGET = Duration.ofSeconds(5);
    private static final int MAX_ADAPTERS = 50;
    private static final String READ = "READ";

    private final DataSource dataSource;
    private final StoredGatewayPreCallScopeSource scopes;
    private final List<ToolAdapter> adapters;
    private final LongSupplier nanoTime;

    public StoredGatewayFixedOperationSource(DataSource dataSource,
            StoredGatewayPreCallScopeSource scopes, List<ToolAdapter> adapters) {
        this(dataSource, scopes, adapters, System::nanoTime);
    }

    StoredGatewayFixedOperationSource(DataSource dataSource,
            StoredGatewayPreCallScopeSource scopes, List<ToolAdapter> adapters,
            LongSupplier nanoTime) {
        this.dataSource = Objects.requireNonNull(dataSource);
        this.scopes = Objects.requireNonNull(scopes);
        this.adapters = List.copyOf(adapters);
        this.nanoTime = Objects.requireNonNull(nanoTime);
    }

    public OperationFacts resolve(InvocationKey key, Duration remaining) {
        if (key == null || remaining == null || remaining.isNegative() || remaining.isZero()
                || remaining.compareTo(MAX_BUDGET) > 0
                || !TransactionSynchronizationManager.isActualTransactionActive()
                || !TransactionSynchronizationManager.hasResource(dataSource)
                || !Objects.equals(TransactionSynchronizationManager.getCurrentTransactionIsolationLevel(),
                        Connection.TRANSACTION_REPEATABLE_READ)) {
            throw incomplete();
        }
        long started = nanoTime.getAsLong();
        long budget = remaining.toNanos();
        try {
            if (adapters.isEmpty() || adapters.size() > MAX_ADAPTERS) throw incomplete();
            var scope = scopes.resolve(key, remainingDuration(started, budget));
            if (scope == null || !key.equals(scope.key()) || scope.namespace() == null
                    || !key.runId().equals(scope.namespace().namespaceId())
                    || !CustomerDataReadToolAdapter.TOOL_NAME.equals(scope.toolName())
                    || !sameContext(key, scope.serverContext())) {
                throw incomplete();
            }
            ToolAdapter adapter = uniqueAdapter(scope.toolName());
            if (!(adapter instanceof CustomerDataReadToolAdapter)
                    || !(adapter instanceof FixedOperationToolAdapter fixed)
                    || adapter.effect() != ToolEffect.READ_ONLY
                    || !READ.equals(fixed.fixedOperation())) {
                throw incomplete();
            }
            remainingDuration(started, budget);
            return new OperationFacts(key, scope.namespace().namespaceId(),
                    scope.toolName(), READ);
        } catch (RuntimeException failure) {
            // Stored values, SQL and driver causes must not cross this fact boundary.
            throw incomplete();
        }
    }

    private ToolAdapter uniqueAdapter(String requestedTool) {
        ToolAdapter match = null;
        for (ToolAdapter adapter : adapters) {
            String name = adapter.toolName();
            if (name == null || !name.matches("[A-Z][A-Z0-9_]{0,99}")) {
                throw incomplete();
            }
            if (requestedTool.equals(name)) {
                if (match != null) throw incomplete();
                match = adapter;
            }
        }
        if (match == null) throw incomplete();
        return match;
    }

    private Duration remainingDuration(long started, long budget) {
        long elapsed = nanoTime.getAsLong() - started;
        if (elapsed < 0 || elapsed >= budget) throw incomplete();
        return Duration.ofNanos(budget - elapsed);
    }

    private static boolean sameContext(InvocationKey key, SandboxExecutionContext context) {
        return context != null && key.runId().equals(context.runId())
                && key.caseRunId().equals(context.caseRunId())
                && key.traceId().equals(context.traceId())
                && context.mode() != null;
    }

    private static BusinessException incomplete() {
        return new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE,
                "Stored Gateway fixed operation is incomplete");
    }

    public record OperationFacts(InvocationKey key, UUID namespaceId,
            String toolName, String operation) {
        public OperationFacts {
            if (key == null || namespaceId == null || !key.runId().equals(namespaceId)
                    || !CustomerDataReadToolAdapter.TOOL_NAME.equals(toolName)
                    || !READ.equals(operation)) {
                throw incomplete();
            }
        }

        @Override
        public String toString() {
            return "StoredGatewayFixedOperation[READ]";
        }
    }
}
