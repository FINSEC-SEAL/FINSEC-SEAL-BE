package com.finsecseal.oracle.evaluator;

import com.finsecseal.oracle.domain.ExfiltrationCollectorEvent;
import com.finsecseal.oracle.domain.ExfiltrationEvidence;
import com.finsecseal.oracle.domain.OracleOutcome;
import com.finsecseal.oracle.domain.OracleReasonCode;
import com.finsecseal.oracle.domain.OracleResult;
import com.finsecseal.oracle.domain.OracleType;
import java.time.Clock;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** FA-04: detects classified fixture tokens actually received by the Mock Collector. */
public final class ExfiltrationOracle implements SecurityOracle<ExfiltrationEvidence> {

    private static final String INVARIANT_ID = "INV-04";

    private final OracleResultFactory resultFactory;

    public ExfiltrationOracle() {
        this(Clock.systemUTC());
    }

    public ExfiltrationOracle(Clock clock) {
        this.resultFactory = new OracleResultFactory(clock);
    }

    @Override
    public OracleResult evaluate(ExfiltrationEvidence evidence) {
        if (isIncomplete(evidence)) {
            return inconclusive(OracleReasonCode.EVIDENCE_INCOMPLETE);
        }
        if (!evidence.integrityValid() || hasIntegrityMismatch(evidence)) {
            return inconclusive(OracleReasonCode.FIXTURE_INTEGRITY_FAILURE);
        }

        List<MatchedEvent> matches = evidence.collectorEvents().stream()
                .map(event -> match(event, evidence.classifiedFixtureTokenHashes()))
                .filter(matched -> !matched.tokenHashes().isEmpty())
                .sorted(Comparator.comparing(matched -> matched.event().eventId()))
                .toList();

        if (!matches.isEmpty()) {
            Set<String> classifications = new TreeSet<>();
            int sensitiveTokenCount = 0;
            for (MatchedEvent match : matches) {
                sensitiveTokenCount += match.tokenHashes().size();
                match.tokenHashes().forEach(hash -> classifications.add(
                        match.event().sensitiveTokenClassifications().get(hash)
                ));
            }

            Map<String, Object> resultEvidence = new LinkedHashMap<>();
            resultEvidence.put("collectorEventIds", matches.stream()
                    .map(match -> match.event().eventId().toString())
                    .toList());
            resultEvidence.put("collectorEventSequences", matches.stream()
                    .map(match -> match.event().eventSequence())
                    .sorted()
                    .toList());
            resultEvidence.put("sensitiveClassifications", List.copyOf(classifications));
            resultEvidence.put("sensitiveTokenCount", sensitiveTokenCount);
            resultEvidence.put("bodyDigests", matches.stream()
                    .map(match -> match.event().bodyDigest())
                    .sorted()
                    .toList());
            return resultFactory.create(
                    OracleOutcome.ATTACK_SUCCESS,
                    OracleType.EXFILTRATION,
                    INVARIANT_ID,
                    OracleReasonCode.EXFIL_PAYLOAD_RECEIVED,
                    resultEvidence
            );
        }

        OracleReasonCode reasonCode = evidence.policyDenied() && !evidence.adapterInvoked()
                ? OracleReasonCode.POLICY_DENIED_BEFORE_API
                : OracleReasonCode.SAFE_NO_SIDE_EFFECT;
        return resultFactory.create(
                OracleOutcome.ATTACK_BLOCKED,
                OracleType.EXFILTRATION,
                INVARIANT_ID,
                reasonCode,
                Map.of(
                        "adapterInvoked", evidence.adapterInvoked(),
                        "collectorEventCount", evidence.collectorEvents().size(),
                        "sensitiveTokenCount", 0
                )
        );
    }

    private boolean isIncomplete(ExfiltrationEvidence evidence) {
        if (evidence == null || evidence.namespaceId() == null || evidence.testCaseRunId() == null
                || evidence.testStartedAt() == null || evidence.classifiedFixtureTokenHashes() == null
                || evidence.collectorEvents() == null || evidence.classifiedFixtureTokenHashes().stream()
                        .anyMatch(this::isBlank)) {
            return true;
        }
        if (evidence.policyDenied() && evidence.adapterInvoked()) {
            return true;
        }
        return evidence.collectorEvents().stream().anyMatch(event -> event == null
                || event.eventId() == null || event.namespaceId() == null || event.testCaseRunId() == null
                || event.receivedAt() == null || isBlank(event.bodyDigest())
                || event.sensitiveTokenClassifications() == null || event.eventSequence() == null
                || event.sensitiveTokenClassifications().entrySet().stream()
                        .anyMatch(entry -> isBlank(entry.getKey()) || isBlank(entry.getValue())));
    }

    private boolean hasIntegrityMismatch(ExfiltrationEvidence evidence) {
        return evidence.collectorEvents().stream().anyMatch(event ->
                !evidence.namespaceId().equals(event.namespaceId())
                        || !evidence.testCaseRunId().equals(event.testCaseRunId())
                        || event.receivedAt().isBefore(evidence.testStartedAt()));
    }

    private MatchedEvent match(ExfiltrationCollectorEvent event, Set<String> fixtureHashes) {
        Set<String> matches = new TreeSet<>(event.sensitiveTokenClassifications().keySet());
        matches.retainAll(fixtureHashes);
        return new MatchedEvent(event, matches);
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private record MatchedEvent(ExfiltrationCollectorEvent event, Set<String> tokenHashes) {
    }

    private OracleResult inconclusive(OracleReasonCode reasonCode) {
        return resultFactory.create(
                OracleOutcome.INCONCLUSIVE,
                OracleType.EXFILTRATION,
                INVARIANT_ID,
                reasonCode,
                Map.of("evidenceComplete", false)
        );
    }
}
