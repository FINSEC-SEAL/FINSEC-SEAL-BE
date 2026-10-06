package com.finsecseal.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import com.finsecseal.evidence.StoredRunReviewerAuthoritySource;
import com.finsecseal.policy.GatewayRuntimeObservations.InvocationKey;
import com.finsecseal.sandbox.tool.StoredGatewayPreCallScopeSource;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionSynchronizationManager;

class StoredGatewayReviewerContextSourceTest {
    private final StoredRunReviewerAuthoritySource authorities = mock(StoredRunReviewerAuthoritySource.class);
    private final StoredGatewayPreCallScopeSource scopes = mock(StoredGatewayPreCallScopeSource.class);
    private final InvocationKey key = new InvocationKey(UUID.randomUUID(), UUID.randomUUID(),
            UUID.randomUUID(), UUID.randomUUID(), "sha256:" + "a".repeat(64));

    static Stream<Duration> invalidBudgets() {
        return Stream.of(null, Duration.ZERO, Duration.ofMillis(-1), Duration.ofSeconds(6),
                Duration.ofMillis(999), Duration.ofSeconds(1), Duration.ofSeconds(2));
    }

    @ParameterizedTest @MethodSource("invalidBudgets")
    void invalidOrInsufficientBudgetRejectsBeforeAnyBorrow(Duration budget) {
        try (CountingPool pool = new CountingPool()) {
            var source = new StoredGatewayReviewerContextSource(pool, authorities, scopes);
            assertThat(source.resolve(key, budget)).isNull();
            assertThat(pool.borrows).hasValue(0);
            verifyNoInteractions(authorities, scopes);
        }
    }

    @Test
    void absentKeyAndChangedPoolBoundRejectBeforeBorrow() {
        try (CountingPool pool = new CountingPool()) {
            var source = new StoredGatewayReviewerContextSource(pool, authorities, scopes);
            assertThat(source.resolve(null, Duration.ofSeconds(5))).isNull();
            pool.setConnectionTimeout(5_000);
            assertThat(source.resolve(key, Duration.ofSeconds(5))).isNull();
            assertThat(pool.borrows).hasValue(0);
            verifyNoInteractions(authorities, scopes);
        }
    }

    @Test
    void ambientTransactionResourceAndSynchronizationStayUntouched() {
        try (CountingPool pool = new CountingPool()) {
            var source = new StoredGatewayReviewerContextSource(pool, authorities, scopes);
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
            assertThat(TransactionSynchronizationManager.isSynchronizationActive()).isFalse();
            assertThat(TransactionSynchronizationManager.hasResource(pool)).isFalse();
            TransactionSynchronizationManager.setActualTransactionActive(true);
            try {
                assertThat(source.resolve(key, Duration.ofSeconds(5))).isNull();
                assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isTrue();
            } finally {
                TransactionSynchronizationManager.setActualTransactionActive(false);
            }
            Object resource = new Object();
            TransactionSynchronizationManager.bindResource(pool, resource);
            try {
                assertThat(source.resolve(key, Duration.ofSeconds(5))).isNull();
                assertThat(TransactionSynchronizationManager.getResource(pool)).isSameAs(resource);
            } finally {
                TransactionSynchronizationManager.unbindResource(pool);
            }
            TransactionSynchronizationManager.initSynchronization();
            try {
                assertThat(source.resolve(key, Duration.ofSeconds(5))).isNull();
                assertThat(TransactionSynchronizationManager.isSynchronizationActive()).isTrue();
            } finally {
                TransactionSynchronizationManager.clearSynchronization();
            }
            assertThat(pool.borrows).hasValue(0);
            verifyNoInteractions(authorities, scopes);
        }
    }

    @Test
    void constructorRejectsUnboundedOrUnsupportedPool() {
        try (HikariDataSource unbounded = new HikariDataSource()) {
            assertThatThrownBy(() -> new StoredGatewayReviewerContextSource(unbounded, authorities, scopes))
                    .isInstanceOf(IllegalStateException.class).hasNoCause();
            unbounded.setConnectionTimeout(5_000);
            assertThatThrownBy(() -> new StoredGatewayReviewerContextSource(unbounded, authorities, scopes))
                    .isInstanceOf(IllegalStateException.class).hasNoCause();
        }
        assertThatThrownBy(() -> new StoredGatewayReviewerContextSource(
                new DriverManagerDataSource(), authorities, scopes)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void qualifiedBeanRequiresBothExplicitTrueFlags() {
        var runner = new ApplicationContextRunner().withBean(HikariDataSource.class, CountingPool::new)
                .withBean(StoredRunReviewerAuthoritySource.class, () -> authorities)
                .withBean(StoredGatewayPreCallScopeSource.class, () -> scopes)
                .withUserConfiguration(StoredGatewayReviewerContextSource.class);
        runner.run(context -> assertThat(context.getBeansOfType(GatewayReviewerContextSource.class)).isEmpty());
        for (String[] flags : new String[][] {{"true", "false"}, {"false", "true"}, {"false", "false"}}) {
            runner.withPropertyValues("finsec.policy.gateway.enabled=" + flags[0],
                            "finsec.policy.gateway.reviewer.stored.enabled=" + flags[1])
                    .run(context -> assertThat(context.getBeansOfType(GatewayReviewerContextSource.class)).isEmpty());
        }
        runner.withPropertyValues("finsec.policy.gateway.enabled=true")
                .run(context -> assertThat(context.getBeansOfType(GatewayReviewerContextSource.class)).isEmpty());
        runner.withPropertyValues("finsec.policy.gateway.reviewer.stored.enabled=true")
                .run(context -> assertThat(context.getBeansOfType(GatewayReviewerContextSource.class)).isEmpty());
        runner.withPropertyValues("finsec.policy.gateway.enabled=true", "finsec.policy.gateway.reviewer.stored.enabled=true")
                .run(context -> assertThat(context.getBeanNamesForType(GatewayReviewerContextSource.class))
                        .containsExactly(LoanReviewPolicyGatewayConfiguration.REVIEWER_CONTEXT_BEAN));
    }

    private static final class CountingPool extends HikariDataSource {
        private final AtomicInteger borrows = new AtomicInteger();

        private CountingPool() { setConnectionTimeout(2_000); }

        @Override public Connection getConnection() throws SQLException {
            borrows.incrementAndGet();
            throw new SQLException("No connection should be borrowed by an admission guard");
        }
    }
}
