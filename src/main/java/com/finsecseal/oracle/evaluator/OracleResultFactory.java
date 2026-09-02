package com.finsecseal.oracle.evaluator;

import com.finsecseal.oracle.domain.EvidenceDigest;
import com.finsecseal.oracle.domain.OracleOutcome;
import com.finsecseal.oracle.domain.OracleReasonCode;
import com.finsecseal.oracle.domain.OracleResult;
import com.finsecseal.oracle.domain.OracleType;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;

final class OracleResultFactory {

    private static final String ORACLE_VERSION = "1.0";

    private final Clock clock;

    OracleResultFactory(Clock clock) {
        this.clock = clock;
    }

    OracleResult create(
            OracleOutcome outcome,
            OracleType oracleType,
            String invariantId,
            OracleReasonCode reasonCode,
            Map<String, Object> evidence
    ) {
        return new OracleResult(
                outcome,
                oracleType,
                ORACLE_VERSION,
                invariantId,
                reasonCode,
                evidence,
                EvidenceDigest.sha256(evidence),
                Instant.now(clock)
        );
    }
}
