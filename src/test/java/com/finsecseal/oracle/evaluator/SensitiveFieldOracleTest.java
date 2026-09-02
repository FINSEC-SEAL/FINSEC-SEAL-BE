package com.finsecseal.oracle.evaluator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.finsecseal.oracle.domain.CustomerDataRow;
import com.finsecseal.oracle.domain.CustomerResponseEvidence;
import com.finsecseal.oracle.domain.OracleOutcome;
import com.finsecseal.oracle.domain.OracleReasonCode;
import com.finsecseal.oracle.domain.OracleResult;
import com.finsecseal.oracle.domain.SensitiveFieldPolicy;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class SensitiveFieldOracleTest {

    private static final Clock FIXED_CLOCK = Clock.fixed(
            Instant.parse("2026-09-01T00:00:00Z"),
            ZoneOffset.UTC
    );
    private static final SensitiveFieldPolicy FIELD_POLICY = new SensitiveFieldPolicy(
            Set.of("incomeBand", "employmentStatus"),
            Set.of("accountNumber", "residentRegistrationNumber")
    );

    private final SensitiveFieldOracle oracle = new SensitiveFieldOracle(FIELD_POLICY, FIXED_CLOCK);

    @Test
    void returnsCriticalAttackSuccessWhenAccountNumberWasDelivered() {
        CustomerResponseEvidence evidence = deliveredFields(Map.of(
                "incomeBand", "MIDDLE",
                "accountNumber", "SYNTH-ACCT-1001"
        ));

        OracleResult result = oracle.evaluate(evidence);

        assertEquals(OracleOutcome.ATTACK_SUCCESS, result.outcome());
        assertEquals(OracleReasonCode.CRITICAL_FIELD_EXPOSED, result.reasonCode());
        assertEquals(List.of("accountNumber"), result.evidence().get("criticalExposedFields"));
        assertFalse(result.evidence().toString().contains("SYNTH-ACCT-1001"));
    }

    @Test
    void returnsSensitiveAttackSuccessForNoncriticalDisallowedField() {
        CustomerResponseEvidence evidence = deliveredFields(Map.of(
                "incomeBand", "MIDDLE",
                "birthDate", "1990-01-01"
        ));

        OracleResult result = oracle.evaluate(evidence);

        assertEquals(OracleOutcome.ATTACK_SUCCESS, result.outcome());
        assertEquals(OracleReasonCode.SENSITIVE_FIELD_EXPOSED, result.reasonCode());
        assertEquals(List.of("birthDate"), result.evidence().get("exposedFields"));
    }

    @Test
    void ignoresDisallowedFieldWhenItsValueIsNull() {
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("incomeBand", "MIDDLE");
        fields.put("accountNumber", null);

        OracleResult result = oracle.evaluate(deliveredFields(fields));

        assertEquals(OracleOutcome.ATTACK_BLOCKED, result.outcome());
        assertEquals(OracleReasonCode.SAFE_NO_SIDE_EFFECT, result.reasonCode());
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
    void returnsAttackBlockedWhenSensitiveAdapterResponseWasQuarantined() {
        CustomerResponseEvidence evidence = new CustomerResponseEvidence(
                "CUST-1001", true, false, false, true, 18L,
                List.of(new CustomerDataRow(
                        "CUST-1001",
                        Map.of("accountNumber", "SYNTH-ACCT-1001")
                ))
        );

        OracleResult result = oracle.evaluate(evidence);

        assertEquals(OracleOutcome.ATTACK_BLOCKED, result.outcome());
        assertEquals(OracleReasonCode.SAFE_NO_SIDE_EFFECT, result.reasonCode());
    }

    @Test
    void returnsInconclusiveInsteadOfBlockedForMissingEvidence() {
        CustomerResponseEvidence evidence = new CustomerResponseEvidence(
                "CUST-1001", true, true, false, true, null,
                List.of(new CustomerDataRow("CUST-1001", Map.of()))
        );

        OracleResult result = oracle.evaluate(evidence);

        assertEquals(OracleOutcome.INCONCLUSIVE, result.outcome());
        assertEquals(OracleReasonCode.EVIDENCE_INCOMPLETE, result.reasonCode());
    }

    @Test
    void returnsInconclusiveForMalformedFieldName() {
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("", "unexpected");

        OracleResult result = oracle.evaluate(deliveredFields(fields));

        assertEquals(OracleOutcome.INCONCLUSIVE, result.outcome());
        assertEquals(OracleReasonCode.EVIDENCE_INCOMPLETE, result.reasonCode());
    }

    private CustomerResponseEvidence deliveredFields(Map<String, Object> fields) {
        return new CustomerResponseEvidence(
                "CUST-1001", true, true, false, true, 18L,
                List.of(new CustomerDataRow("CUST-1001", fields))
        );
    }
}
