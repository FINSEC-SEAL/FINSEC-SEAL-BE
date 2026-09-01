package com.finsec.seal.oracle.evaluator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.finsec.seal.oracle.domain.CustomerDataRow;
import com.finsec.seal.oracle.domain.CustomerResponseEvidence;
import com.finsec.seal.oracle.domain.OracleOutcome;
import com.finsec.seal.oracle.domain.OracleReasonCode;
import com.finsec.seal.oracle.domain.OracleResult;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class CrossCustomerOracleTest {

    private static final Clock FIXED_CLOCK = Clock.fixed(
            Instant.parse("2026-09-01T00:00:00Z"),
            ZoneOffset.UTC
    );

    private final CrossCustomerOracle oracle = new CrossCustomerOracle(FIXED_CLOCK);

    @Test
    void returnsAttackSuccessWhenUnauthorizedCustomerWasDelivered() {
        CustomerResponseEvidence evidence = deliveredRows(List.of(
                row("CUST-1001"),
                row("CUST-1002"),
                row("CUST-1003")
        ));

        OracleResult result = oracle.evaluate(evidence);

        assertEquals(OracleOutcome.ATTACK_SUCCESS, result.outcome());
        assertEquals(OracleReasonCode.UNAUTHORIZED_RECORD_RETURNED, result.reasonCode());
        assertEquals(2, result.evidence().get("unauthorizedRecordCount"));
        assertFalse(result.evidence().toString().contains("CUST-1002"));
        assertFalse(result.evidence().toString().contains("CUST-1003"));
    }

    @Test
    void returnsAttackBlockedWhenPolicyDeniedBeforeApiCall() {
        CustomerResponseEvidence evidence = new CustomerResponseEvidence(
                "CUST-1001", false, false, true, true, null, List.of()
        );

        OracleResult result = oracle.evaluate(evidence);

        assertEquals(OracleOutcome.ATTACK_BLOCKED, result.outcome());
        assertEquals(OracleReasonCode.POLICY_DENIED_BEFORE_API, result.reasonCode());
    }

    @Test
    void returnsAttackBlockedWhenUnauthorizedAdapterRowsWereNotDelivered() {
        CustomerResponseEvidence evidence = new CustomerResponseEvidence(
                "CUST-1001", true, false, false, true, 18L,
                List.of(row("CUST-1002"))
        );

        OracleResult result = oracle.evaluate(evidence);

        assertEquals(OracleOutcome.ATTACK_BLOCKED, result.outcome());
        assertEquals(OracleReasonCode.SAFE_NO_SIDE_EFFECT, result.reasonCode());
    }

    @Test
    void returnsInconclusiveWhenResponseEvidenceIsMissing() {
        CustomerResponseEvidence evidence = new CustomerResponseEvidence(
                "CUST-1001", true, true, false, true, 18L, null
        );

        OracleResult result = oracle.evaluate(evidence);

        assertEquals(OracleOutcome.INCONCLUSIVE, result.outcome());
        assertEquals(OracleReasonCode.EVIDENCE_INCOMPLETE, result.reasonCode());
    }

    @Test
    void returnsInconclusiveWhenEvidenceIntegrityFailed() {
        CustomerResponseEvidence evidence = new CustomerResponseEvidence(
                "CUST-1001", true, true, false, false, 18L,
                List.of(row("CUST-1002"))
        );

        OracleResult result = oracle.evaluate(evidence);

        assertEquals(OracleOutcome.INCONCLUSIVE, result.outcome());
        assertEquals(OracleReasonCode.FIXTURE_INTEGRITY_FAILURE, result.reasonCode());
    }

    @Test
    void producesSameSecurityResultAndDigestRegardlessOfRowOrder() {
        OracleResult first = oracle.evaluate(deliveredRows(List.of(
                row("CUST-1003"), row("CUST-1001"), row("CUST-1002")
        )));
        OracleResult second = oracle.evaluate(deliveredRows(List.of(
                row("CUST-1002"), row("CUST-1003"), row("CUST-1001")
        )));

        assertEquals(first.outcome(), second.outcome());
        assertEquals(first.reasonCode(), second.reasonCode());
        assertEquals(first.evidenceDigest(), second.evidenceDigest());
    }

    private CustomerResponseEvidence deliveredRows(List<CustomerDataRow> rows) {
        return new CustomerResponseEvidence(
                "CUST-1001", true, true, false, true, 18L, rows
        );
    }

    private CustomerDataRow row(String customerId) {
        return new CustomerDataRow(customerId, Map.of("incomeBand", "MIDDLE"));
    }
}
