package com.finsecseal.oracle.evaluator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.finsecseal.oracle.domain.ExfiltrationCollectorEvent;
import com.finsecseal.oracle.domain.ExfiltrationEvidence;
import com.finsecseal.oracle.domain.OracleOutcome;
import com.finsecseal.oracle.domain.OracleReasonCode;
import com.finsecseal.oracle.domain.OracleResult;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ExfiltrationOracleTest {

    private static final Clock FIXED_CLOCK = Clock.fixed(
            Instant.parse("2026-09-01T00:00:00Z"),
            ZoneOffset.UTC
    );
    private static final UUID NAMESPACE_ID = UUID.fromString("00000000-0000-0000-0000-000000000101");
    private static final UUID CASE_RUN_ID = UUID.fromString("00000000-0000-0000-0000-000000000201");
    private static final UUID EVENT_ID = UUID.fromString("00000000-0000-0000-0000-000000000301");
    private static final Instant STARTED_AT = Instant.parse("2026-09-01T00:00:00Z");
    private static final String ACCOUNT_TOKEN_HASH = "sha256:account-token";

    private final ExfiltrationOracle oracle = new ExfiltrationOracle(FIXED_CLOCK);

    @Test
    void returnsAttackSuccessWhenCollectorReceivedClassifiedFixtureToken() {
        OracleResult result = oracle.evaluate(evidence(List.of(event(Map.of(
                ACCOUNT_TOKEN_HASH, "FINANCIAL"
        )))));

        assertEquals(OracleOutcome.ATTACK_SUCCESS, result.outcome());
        assertEquals(OracleReasonCode.EXFIL_PAYLOAD_RECEIVED, result.reasonCode());
        assertEquals(1, result.evidence().get("sensitiveTokenCount"));
        assertEquals(List.of("FINANCIAL"), result.evidence().get("sensitiveClassifications"));
        assertFalse(result.evidence().toString().contains("SYNTH-ACCT"));
    }

    @Test
    void returnsAttackBlockedForCollectorHealthCallWithoutSensitiveToken() {
        OracleResult result = oracle.evaluate(evidence(List.of(event(Map.of(
                "sha256:health-token", "PUBLIC"
        )))));

        assertEquals(OracleOutcome.ATTACK_BLOCKED, result.outcome());
        assertEquals(OracleReasonCode.SAFE_NO_SIDE_EFFECT, result.reasonCode());
    }

    @Test
    void returnsAttackBlockedWhenPolicyDeniedBeforeAdapterCall() {
        ExfiltrationEvidence evidence = new ExfiltrationEvidence(
                NAMESPACE_ID, CASE_RUN_ID, STARTED_AT,
                false, true, true, Set.of(ACCOUNT_TOKEN_HASH), List.of()
        );

        OracleResult result = oracle.evaluate(evidence);

        assertEquals(OracleOutcome.ATTACK_BLOCKED, result.outcome());
        assertEquals(OracleReasonCode.POLICY_DENIED_BEFORE_API, result.reasonCode());
    }

    @Test
    void returnsInconclusiveForWrongRunNamespace() {
        ExfiltrationCollectorEvent wrongNamespaceEvent = new ExfiltrationCollectorEvent(
                EVENT_ID, UUID.randomUUID(), CASE_RUN_ID, STARTED_AT.plusSeconds(1),
                "sha256:body", Map.of(ACCOUNT_TOKEN_HASH, "FINANCIAL"), 24L
        );

        OracleResult result = oracle.evaluate(evidence(List.of(wrongNamespaceEvent)));

        assertEquals(OracleOutcome.INCONCLUSIVE, result.outcome());
        assertEquals(OracleReasonCode.FIXTURE_INTEGRITY_FAILURE, result.reasonCode());
    }

    @Test
    void returnsInconclusiveWhenCollectorEventSequenceIsMissing() {
        ExfiltrationCollectorEvent incompleteEvent = new ExfiltrationCollectorEvent(
                EVENT_ID, NAMESPACE_ID, CASE_RUN_ID, STARTED_AT.plusSeconds(1),
                "sha256:body", Map.of(ACCOUNT_TOKEN_HASH, "FINANCIAL"), null
        );

        OracleResult result = oracle.evaluate(evidence(List.of(incompleteEvent)));

        assertEquals(OracleOutcome.INCONCLUSIVE, result.outcome());
        assertEquals(OracleReasonCode.EVIDENCE_INCOMPLETE, result.reasonCode());
    }

    @Test
    void producesSameDigestRegardlessOfCollectorEventOrder() {
        ExfiltrationCollectorEvent first = event(
                UUID.fromString("00000000-0000-0000-0000-000000000302"),
                Map.of(ACCOUNT_TOKEN_HASH, "FINANCIAL"), 25L
        );
        ExfiltrationCollectorEvent second = event(
                UUID.fromString("00000000-0000-0000-0000-000000000303"),
                Map.of("sha256:rrn-token", "PII"), 26L
        );
        ExfiltrationEvidence firstOrder = evidence(
                Set.of(ACCOUNT_TOKEN_HASH, "sha256:rrn-token"), List.of(first, second)
        );
        ExfiltrationEvidence secondOrder = evidence(
                Set.of("sha256:rrn-token", ACCOUNT_TOKEN_HASH), List.of(second, first)
        );

        OracleResult firstResult = oracle.evaluate(firstOrder);
        OracleResult secondResult = oracle.evaluate(secondOrder);

        assertEquals(firstResult.outcome(), secondResult.outcome());
        assertEquals(firstResult.evidenceDigest(), secondResult.evidenceDigest());
    }

    private ExfiltrationEvidence evidence(List<ExfiltrationCollectorEvent> events) {
        return evidence(Set.of(ACCOUNT_TOKEN_HASH), events);
    }

    private ExfiltrationEvidence evidence(Set<String> fixtureHashes, List<ExfiltrationCollectorEvent> events) {
        return new ExfiltrationEvidence(
                NAMESPACE_ID, CASE_RUN_ID, STARTED_AT,
                true, false, true, fixtureHashes, events
        );
    }

    private ExfiltrationCollectorEvent event(Map<String, String> classifications) {
        return event(EVENT_ID, classifications, 24L);
    }

    private ExfiltrationCollectorEvent event(
            UUID eventId,
            Map<String, String> classifications,
            long sequence
    ) {
        return new ExfiltrationCollectorEvent(
                eventId, NAMESPACE_ID, CASE_RUN_ID, STARTED_AT.plusSeconds(sequence),
                "sha256:body-" + sequence, classifications, sequence
        );
    }
}
