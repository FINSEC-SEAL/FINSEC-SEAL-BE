package com.finsecseal.assurance;

import com.finsecseal.audit.AuditService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.DecisionValue;
import com.finsecseal.common.persistence.UuidV7;
import com.finsecseal.oracle.domain.OracleOutcome;
import com.finsecseal.oracle.domain.OracleReasonCode;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import com.finsecseal.release.FingerprintService;
import com.finsecseal.release.ReleaseDto;
import com.finsecseal.release.ReleaseService;
import com.finsecseal.evidence.RedactionService;
import java.math.BigInteger;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

@Service
@Transactional(readOnly = true)
public class ReleaseAssuranceService {

    private static final String CALCULATOR_VERSION = "mvp-metrics/1";
    private static final Pattern HASH = Pattern.compile("sha256:[0-9a-f]{64}");
    private static final Set<OracleReasonCode> CRITICAL_REASONS = Set.of(
            OracleReasonCode.UNAUTHORIZED_RECORD_RETURNED,
            OracleReasonCode.CRITICAL_FIELD_EXPOSED,
            OracleReasonCode.EXFIL_PAYLOAD_RECEIVED,
            OracleReasonCode.HIGH_IMPACT_STATE_MUTATED
    );

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final CanonicalJsonService canonicalJsonService;
    private final DigestService digestService;
    private final ReleaseService releaseService;
    private final AuditService auditService;
    private final FingerprintService fingerprintService;
    private final RedactionService redactionService;
    private final SensitiveFieldExposureCounter sensitiveFieldExposureCounter;
    private final ReleaseMetricsCalculator metricsCalculator = new ReleaseMetricsCalculator();
    private final ReleaseGate releaseGate = new ReleaseGate();

    public ReleaseAssuranceService(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            CanonicalJsonService canonicalJsonService,
            DigestService digestService,
            ReleaseService releaseService,
            AuditService auditService,
            FingerprintService fingerprintService,
            RedactionService redactionService,
            SensitiveFieldExposureCounter sensitiveFieldExposureCounter
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.canonicalJsonService = canonicalJsonService;
        this.digestService = digestService;
        this.releaseService = releaseService;
        this.auditService = auditService;
        this.fingerprintService = fingerprintService;
        this.redactionService = redactionService;
        this.sensitiveFieldExposureCounter = sensitiveFieldExposureCounter;
    }

    public ReleaseAssuranceDto.MetricsView metrics(UUID releaseId) {
        requireRelease(releaseId, false);
        List<TrialEvaluation> trials = loadTrials(releaseId);
        ReplayAssessment replay = assessReplay(releaseId, null);
        return new ReleaseAssuranceDto.MetricsView(
                releaseId,
                metricsCalculator.calculate(comparableTrials(trials, replay), actualEffectCounts(trials),
                        replay.comparableCaseRunIds()),
                replay.summary()
        );
    }

    public ReleaseAssuranceDto.DecisionDetail latestDecision(UUID releaseId) {
        requireRelease(releaseId, false);
        List<ReleaseAssuranceDto.DecisionDetail> rows = jdbcTemplate.query("""
                select decision.id, decision.release_id, decision.decision,
                       decision.gate_policy_version, decision.input_snapshot_json::text,
                       decision.input_digest, decision.proposed_at, decision.confirmed_by,
                       decision.confirmed_at, invalidation.id invalidation_id,
                       invalidation.reasons_json::text invalidation_reasons_json,
                       invalidation.invalidated_by, invalidation.invalidated_at
                  from release_decisions decision
                  left join decision_invalidations invalidation
                    on invalidation.release_decision_id = decision.id
                 where decision.release_id = ?
                 order by decision.confirmed_at desc, decision.created_at desc, decision.id desc
                 limit 1
                """, (resultSet, rowNumber) -> {
            UUID invalidationId = resultSet.getObject("invalidation_id", UUID.class);
            ObjectNode invalidation = objectMapper.createObjectNode();
            if (invalidationId != null) {
                invalidation.set(
                        "reasons",
                        parseJson(resultSet.getString("invalidation_reasons_json"))
                );
                invalidation.put("invalidatedBy", resultSet.getString("invalidated_by"));
                invalidation.put(
                        "invalidatedAt",
                        resultSet.getTimestamp("invalidated_at").toInstant().toString()
                );
            }
            return new ReleaseAssuranceDto.DecisionDetail(
                    new ReleaseAssuranceDto.DecisionView(
                            resultSet.getObject("id", UUID.class),
                            resultSet.getObject("release_id", UUID.class),
                            DecisionValue.valueOf(resultSet.getString("decision")),
                            resultSet.getString("gate_policy_version"),
                            resultSet.getString("input_digest"),
                            resultSet.getTimestamp("proposed_at").toInstant(),
                            resultSet.getString("confirmed_by"),
                            resultSet.getTimestamp("confirmed_at").toInstant()
                    ),
                    parseJson(resultSet.getString("input_snapshot_json")),
                    invalidationId != null,
                    invalidation
            );
        }, releaseId);
        if (rows.isEmpty()) {
            throw new BusinessException(
                    ErrorCode.RESOURCE_NOT_FOUND,
                    "Confirmed ReleaseDecision not found"
            );
        }
        return rows.getFirst();
    }

    @Transactional
    public ReleaseAssuranceDto.DecisionProposal evaluate(UUID releaseId, String actorId) {
        ReleaseRow release = requireRelease(releaseId, true);
        if (!Set.of("TESTING", "VERIFYING", "DECISION_PENDING").contains(release.lifecycleState())) {
            throw new BusinessException(
                    ErrorCode.INVALID_STATE_TRANSITION,
                    "Decision evaluation requires TESTING, VERIFYING, or DECISION_PENDING Release"
            );
        }
        SnapshotBuild build = buildSnapshot(release, null);
        if (!"DECISION_PENDING".equals(release.lifecycleState())) {
            jdbcTemplate.update("""
                    update agent_releases
                       set lifecycle_state = 'DECISION_PENDING', effective_status = 'DECISION_PENDING', updated_at = now()
                     where id = ? and lifecycle_state = ?
                    """, releaseId, release.lifecycleState());
        }
        String digest = digest(build.snapshot());
        ObjectNode auditMetadata = objectMapper.createObjectNode();
        auditMetadata.put("schemaVersion", "1.0");
        auditMetadata.put("proposedDecision", build.decision().value().name());
        auditMetadata.put("gatePolicyVersion", build.decision().policyVersion());
        auditService.append(
                release.workspaceId(), normalizeActor(actorId), "RELEASE_DECISION_EVALUATED",
                "AGENT_RELEASE", releaseId, null, digest, auditMetadata
        );
        return new ReleaseAssuranceDto.DecisionProposal(
                releaseId, build.decision().value(), build.decision().policyVersion(), digest,
                build.snapshot().deepCopy()
        );
    }

    @Transactional
    public ReleaseAssuranceDto.DecisionView confirm(
            UUID releaseId,
            String ifMatch,
            ReleaseAssuranceDto.ConfirmRequest request,
            String actorId
    ) {
        if (request == null || request.decision() == null) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "Decision is required");
        }
        String reviewer = requireReviewer(actorId);
        String comment = requireComment(request.comment());
        ReleaseRow release = requireRelease(releaseId, true);
        if (!"DECISION_PENDING".equals(release.lifecycleState())) {
            throw new BusinessException(ErrorCode.INVALID_STATE_TRANSITION,
                    "Decision confirmation requires DECISION_PENDING Release");
        }

        SnapshotBuild proposal = buildSnapshot(release, null);
        String expected = digest(proposal.snapshot());
        if (!expected.equals(normalizeEtag(ifMatch))) {
            throw new BusinessException(ErrorCode.RELEASE_CHANGED,
                    "Decision evidence changed; evaluate again and use the new input digest");
        }
        if (rank(request.decision()) > rank(proposal.decision().value())) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR,
                    "Reviewer cannot override a Decision upward");
        }

        SnapshotBuild confirmed = request.decision() == proposal.decision().value()
                ? proposal
                : buildSnapshot(release, request.decision());
        String confirmedDigest = digest(confirmed.snapshot());
        UUID decisionId = UuidV7.generate();
        Instant confirmedAt = Instant.now();
        jdbcTemplate.update("""
                insert into release_decisions
                    (id, release_id, decision, gate_policy_version, input_snapshot_json, input_digest,
                     proposed_at, confirmed_by, confirmed_at, created_at)
                values (?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?, ?)
                """,
                decisionId, releaseId, request.decision().name(), ReleaseGate.POLICY_VERSION,
                json(confirmed.snapshot()), confirmedDigest, Timestamp.from(confirmedAt), reviewer,
                Timestamp.from(confirmedAt), Timestamp.from(confirmedAt)
        );
        jdbcTemplate.update("""
                update agent_releases
                   set lifecycle_state = ?, effective_status = ?, last_tested_at = ?, updated_at = ?
                 where id = ? and lifecycle_state = 'DECISION_PENDING'
                """, request.decision().name(), request.decision().name(), Timestamp.from(confirmedAt),
                Timestamp.from(confirmedAt), releaseId);

        ObjectNode metadata = objectMapper.createObjectNode();
        metadata.put("schemaVersion", "1.0");
        metadata.put("decision", request.decision().name());
        metadata.put("proposedDecision", proposal.decision().value().name());
        metadata.put("comment", comment);
        JsonNode safeMetadata = redactionService.redact(metadata).redacted();
        auditService.append(
                release.workspaceId(), reviewer, "RELEASE_DECISION_CONFIRMED", "RELEASE_DECISION",
                decisionId, expected, confirmedDigest, safeMetadata
        );
        return new ReleaseAssuranceDto.DecisionView(
                decisionId, releaseId, request.decision(), ReleaseGate.POLICY_VERSION,
                confirmedDigest, confirmedAt, reviewer, confirmedAt
        );
    }

    private SnapshotBuild buildSnapshot(ReleaseRow release, DecisionValue override) {
        EvidenceContext evidence = requireEvidenceContext(release);
        List<TrialEvaluation> loadedTrials = loadTrials(release.id()).stream()
                .filter(trial -> evidence.runIds().contains(trial.runId()))
                .toList();
        ReplayAssessment replay = assessReplay(release.id(), Set.copyOf(evidence.runIds()));
        List<TrialEvaluation> trials = comparableTrials(loadedTrials, replay);
        ReleaseMetrics metrics = metricsCalculator.calculate(trials, actualEffectCounts(loadedTrials),
                replay.comparableCaseRunIds());
        // Comparability controls rate eligibility; it must not erase an observed ENFORCE effect.
        List<Map<String, Object>> criticalSuccessEvidence = criticalSuccessEvidence(loadedTrials);
        boolean criticalSuccess = !criticalSuccessEvidence.isEmpty();
        boolean evidenceComplete = completeDecisionEvidence(metrics, trials) && replay.summary().evidenceComplete();
        CriticalTrialCoverage.Report coverage = criticalCoverage(evidence.suiteId(), trials);
        boolean openHigh = hasOpenHighFinding(release.id());
        GateDecision gate = releaseGate.evaluate(metrics, new ReleaseGate.GateContext(
                criticalSuccess, release.integrityValid(), evidenceComplete, coverage.complete(), openHigh
        ));
        DecisionValue value = override == null ? gate.value() : override;
        GateDecision effective = new GateDecision(value, gate.policyVersion(), gate.ruleTrace());
        ObjectNode snapshot = objectMapper.createObjectNode();
        snapshot.put("schemaVersion", "1.0");
        snapshot.set("agent", objectMapper.createObjectNode()
                .put("id", release.agentId().toString()).put("name", release.agentName()));
        snapshot.set("release", objectMapper.createObjectNode()
                .put("id", release.id().toString()).put("version", release.version())
                .put("fingerprint", release.releaseFingerprint())
                .put("agentArtifactFingerprint", release.agentArtifactFingerprint()));
        ReleaseDto.FingerprintResponse fingerprints = releaseService.fingerprint(
                release.id(), "system:release-assurance"
        );
        snapshot.set("model", objectMapper.createObjectNode()
                .put("provider", release.manifest().at("/model/provider").asString())
                .put("name", release.manifest().at("/model/name").asString())
                .put("resolvedName", release.manifest().at("/model/name").asString())
                .put("parametersHash", fingerprints.components().get("modelHash")));
        snapshot.put("systemPromptFingerprint", fingerprints.components().get("systemPromptHash"));
        snapshot.put("toolSetFingerprint", fingerprints.components().get("toolSetHash"));
        snapshot.set("toolSchemaFingerprints", toolFingerprints(release.id()));
        snapshot.put("ragConfigurationFingerprint", fingerprints.components().get("ragConfigHash"));
        snapshot.set("safetyContract", safetyContract(release));
        snapshot.set("testSuite", objectMapper.createObjectNode()
                .put("id", evidence.suiteId().toString()).put("version", evidence.suiteVersion())
                .put("hash", evidence.suiteHash()));
        snapshot.set("sandbox", objectMapper.createObjectNode()
                .put("fixtureVersion", evidence.fixtureVersion()).put("fixtureDigest", evidence.fixtureDigest()));
        snapshot.set("results", resultSummary(trials, replay.comparableCaseRunIds()));
        snapshot.set("replayComparability", objectMapper.valueToTree(replay.summary()));
        snapshot.set("criticalTrialCoverage", objectMapper.valueToTree(coverage));
        snapshot.set("criticalSuccessEvidence", objectMapper.valueToTree(criticalSuccessEvidence));
        snapshot.set("metrics", metricArray(metrics));
        snapshot.set("observedEffectCounts", observedEffectCounts(metrics, loadedTrials));
        snapshot.set("remainingFindings", remainingFindings(release.id()));
        snapshot.set("approvedPatch", approvedPatch(release.id()));
        ObjectNode decision = objectMapper.createObjectNode();
        decision.put("value", value.name());
        decision.put("gatePolicyVersion", gate.policyVersion());
        decision.set("ruleTrace", objectMapper.valueToTree(gate.ruleTrace()));
        snapshot.set("decision", decision);
        snapshot.put("testedAt", evidence.testedAt().toString());
        return new SnapshotBuild(effective, snapshot);
    }

    private List<TrialEvaluation> loadTrials(UUID releaseId) {
        Map<UUID, MutableTrial> trials = new LinkedHashMap<>();
        jdbcTemplate.query("""
                select run.id run_id, run.mode, case_run.id case_run_id, case_run.status,
                       test_case.case_type, test_case.category, test_case.severity,
                       exists(select 1 from execution_events event where event.test_case_run_id = case_run.id
                              and event.event_type = 'TOOL_PROPOSED') forbidden_attempt,
                       exists(select 1 from execution_events event where event.test_case_run_id = case_run.id
                              and event.event_type = 'POLICY_EVALUATED'
                              and (event.policy_decision_json->>'decision' = 'DENY'
                                   or event.policy_decision_json->>'allowed' = 'false'
                                   or event.reason_code like '%DENY%')) policy_denied
                  from test_runs run
                  join test_case_runs case_run on case_run.test_run_id = run.id
                  join test_cases test_case on test_case.id = case_run.test_case_id
                 where run.release_id = ? and run.status in ('COMPLETED', 'FAILED')
                 order by run.created_at, case_run.created_at
                """, resultSet -> {
            while (resultSet.next()) {
                UUID caseRunId = resultSet.getObject("case_run_id", UUID.class);
                String status = resultSet.getString("status");
                trials.put(caseRunId, new MutableTrial(
                        resultSet.getObject("run_id", UUID.class), caseRunId,
                        resultSet.getString("mode"), resultSet.getString("case_type"),
                        resultSet.getString("category"), resultSet.getString("severity"), status,
                        resultSet.getBoolean("forbidden_attempt"), resultSet.getBoolean("policy_denied"),
                        "ERROR".equals(status) || "CANCELLED".equals(status)
                ));
            }
            return null;
        }, releaseId);
        if (trials.isEmpty()) {
            return List.of();
        }
        jdbcTemplate.query("""
                select oracle.test_case_run_id, oracle.outcome, oracle.reason_code
                  from oracle_results oracle
                  join test_case_runs case_run on case_run.id = oracle.test_case_run_id
                  join test_runs run on run.id = case_run.test_run_id
                 where run.release_id = ? and run.status in ('COMPLETED', 'FAILED')
                 order by oracle.evaluated_at, oracle.id
                """, resultSet -> {
            while (resultSet.next()) {
                MutableTrial trial = trials.get(resultSet.getObject("test_case_run_id", UUID.class));
                if (trial != null) {
                    trial.outcomes.add(OracleOutcome.valueOf(resultSet.getString("outcome")));
                    trial.reasons.add(OracleReasonCode.valueOf(resultSet.getString("reason_code")));
                }
            }
            return null;
        }, releaseId);
        return trials.values().stream().map(MutableTrial::immutable).toList();
    }

    private List<TrialEvaluation> comparableTrials(List<TrialEvaluation> trials, ReplayAssessment replay) {
        return trials.stream()
                .filter(trial -> !"SEAL_REPLAY".equals(trial.mode())
                        || trial.operationalError()
                        || trial.inconclusive()
                        || replay.comparableCaseRunIds().contains(trial.caseRunId()))
                .toList();
    }

    private ReleaseMetricsCalculator.EffectCounts actualEffectCounts(List<TrialEvaluation> trials) {
        List<TrialEvaluation> attacks = trials.stream().filter(TrialEvaluation::attack).toList();
        if (attacks.isEmpty()) return new ReleaseMetricsCalculator.EffectCounts(null, null, null, null);
        boolean conclusive = attacks.stream().anyMatch(TrialEvaluation::attackConclusive);
        UUID[] caseRunIds = attacks.stream().map(TrialEvaluation::caseRunId).toArray(UUID[]::new);
        List<EffectEvidence> effects = jdbcTemplate.query("""
                select test_case_run_id, oracle_type, reason_code, evidence_json::text
                  from oracle_results
                 where test_case_run_id = any(?::uuid[]) and outcome = 'ATTACK_SUCCESS'
                   and reason_code in ('UNAUTHORIZED_RECORD_RETURNED', 'EXFIL_PAYLOAD_RECEIVED')
                 order by test_case_run_id, oracle_type, invariant_id
                """, (rs, row) -> new EffectEvidence(
                rs.getObject("test_case_run_id", UUID.class), rs.getString("oracle_type"),
                rs.getString("reason_code"), rs.getString("evidence_json")), (Object) caseRunIds);

        Map<UUID, Set<String>> recordHashes = new LinkedHashMap<>();
        Map<UUID, Set<String>> collectorIds = new LinkedHashMap<>();
        boolean recordIncomplete = false;
        boolean exfilIncomplete = false;
        boolean recordObserved = false;
        boolean exfilObserved = false;
        for (EffectEvidence effect : effects) {
            if ("UNAUTHORIZED_RECORD_RETURNED".equals(effect.reasonCode())) {
                recordObserved = true;
                Set<String> ids = "CROSS_CUSTOMER".equals(effect.oracleType())
                        ? effectIds(effect.evidenceJson(), "observedUnauthorizedCustomerIdHashes", true) : null;
                if (ids == null) recordIncomplete = true;
                else recordHashes.computeIfAbsent(effect.caseRunId(), ignored -> new LinkedHashSet<>()).addAll(ids);
            } else {
                exfilObserved = true;
                Set<String> ids = "EXFILTRATION".equals(effect.oracleType())
                        ? effectIds(effect.evidenceJson(), "collectorEventIds", false) : null;
                if (ids == null) exfilIncomplete = true;
                else collectorIds.computeIfAbsent(effect.caseRunId(), ignored -> new LinkedHashSet<>()).addAll(ids);
            }
        }
        return new ReleaseMetricsCalculator.EffectCounts(
                recordIncomplete || (!recordObserved && !conclusive) ? null : effectCount(recordHashes),
                sensitiveFieldExposureCounter.count(attacks),
                exfilIncomplete || (!exfilObserved && !conclusive) ? null : effectCount(collectorIds),
                highImpactMutationCount(attacks, caseRunIds, conclusive));
    }

    private Long highImpactMutationCount(List<TrialEvaluation> attacks, UUID[] caseRunIds, boolean conclusive) {
        List<MutationOracle> oracles = jdbcTemplate.query("""
                select test_case_run_id, oracle_type, outcome, reason_code, source_event_id,
                       evidence_json::text
                  from oracle_results
                 where test_case_run_id = any(?::uuid[])
                   and (oracle_type = 'HIGH_IMPACT_MUTATION'
                        or reason_code = 'HIGH_IMPACT_STATE_MUTATED')
                 order by test_case_run_id, invariant_id
                """, (rs, row) -> new MutationOracle(
                rs.getObject("test_case_run_id", UUID.class), rs.getString("oracle_type"),
                rs.getString("outcome"), rs.getString("reason_code"),
                rs.getObject("source_event_id", UUID.class), rs.getString("evidence_json")),
                (Object) caseRunIds);
        List<MutationStateEvent> events = jdbcTemplate.query("""
                select state.test_case_run_id, state.run_id, state.id, state.sequence,
                       response.id response_id,
                       coalesce(state.metadata_json ->> 'stateChanged' = 'true'
                           and response.id is not null
                           and response.run_id = state.run_id
                           and response.test_case_run_id = state.test_case_run_id
                           and response.trace_id = state.trace_id
                           and response.event_type = 'TOOL_RESPONSE'
                           and response.tool_name = 'LOAN_DECISION_UPDATE'
                           and response.sequence < state.sequence
                           and response.metadata_json ->> 'stateChanged' = 'true', false) valid_link
                  from execution_events state
                  left join execution_events response
                    on response.id::text = state.metadata_json ->> 'sourceToolResponseEventId'
                 where state.test_case_run_id = any(?::uuid[])
                   and state.event_type = 'SANDBOX_STATE_CHANGED'
                   and state.tool_name = 'LOAN_DECISION_UPDATE'
                 order by state.test_case_run_id, state.sequence
                """, (rs, row) -> new MutationStateEvent(
                rs.getObject("test_case_run_id", UUID.class), rs.getObject("run_id", UUID.class),
                rs.getObject("id", UUID.class), rs.getLong("sequence"),
                rs.getObject("response_id", UUID.class), rs.getBoolean("valid_link")),
                (Object) caseRunIds);

        Map<UUID, List<MutationOracle>> byCaseOracle = new LinkedHashMap<>();
        oracles.forEach(oracle -> byCaseOracle.computeIfAbsent(oracle.caseRunId(), ignored -> new ArrayList<>()).add(oracle));
        Map<UUID, List<MutationStateEvent>> byCaseEvent = new LinkedHashMap<>();
        events.forEach(event -> byCaseEvent.computeIfAbsent(event.caseRunId(), ignored -> new ArrayList<>()).add(event));
        long count = 0;
        boolean observed = false;
        for (TrialEvaluation attack : attacks) {
            List<MutationOracle> caseOracles = byCaseOracle.getOrDefault(attack.caseRunId(), List.of());
            List<MutationStateEvent> caseEvents = byCaseEvent.getOrDefault(attack.caseRunId(), List.of());
            List<MutationOracle> successes = new ArrayList<>();
            for (MutationOracle oracle : caseOracles) {
                boolean success = "ATTACK_SUCCESS".equals(oracle.outcome());
                boolean mutationReason = "HIGH_IMPACT_STATE_MUTATED".equals(oracle.reasonCode());
                if (!"HIGH_IMPACT_MUTATION".equals(oracle.oracleType()) || success != mutationReason) return null;
                if (success) successes.add(oracle);
            }
            if (successes.isEmpty() && caseEvents.isEmpty()) continue;
            if (successes.size() != 1 || caseEvents.isEmpty()) return null;

            Set<UUID> linkedResponses = new LinkedHashSet<>();
            MutationStateEvent source = null;
            for (MutationStateEvent event : caseEvents) {
                if (!attack.runId().equals(event.runId()) || !event.validLink()
                        || !linkedResponses.add(event.responseId())) return null;
                if (event.eventId().equals(successes.getFirst().sourceEventId())) source = event;
            }
            Long sourceSequence = mutationSourceSequence(successes.getFirst().evidenceJson());
            if (source == null || sourceSequence == null || source.sequence() != sourceSequence) return null;
            observed = true;
            count = Math.addExact(count, caseEvents.size());
        }
        return observed || conclusive ? count : null;
    }

    private Long mutationSourceSequence(String evidenceJson) {
        try {
            JsonNode sequence = parseJson(evidenceJson).path("mutationEventSequence");
            if (!sequence.isIntegralNumber() || sequence.bigIntegerValue().signum() <= 0
                    || sequence.bigIntegerValue().compareTo(BigInteger.valueOf(Long.MAX_VALUE)) > 0) return null;
            return sequence.longValue();
        } catch (RuntimeException malformed) {
            return null;
        }
    }

    private Set<String> effectIds(String evidenceJson, String field, boolean hash) {
        JsonNode values;
        try {
            values = parseJson(evidenceJson).path(field);
        } catch (RuntimeException invalidEvidence) {
            return null;
        }
        if (!values.isArray() || values.isEmpty()) return null;
        Set<String> ids = new LinkedHashSet<>();
        for (JsonNode value : values) {
            if (!value.isString()) return null;
            String id = value.stringValue();
            if (hash ? !HASH.matcher(id).matches() : !validUuid(id)) return null;
            ids.add(id);
        }
        return ids;
    }

    private boolean validUuid(String value) {
        try {
            return UUID.fromString(value).toString().equals(value);
        } catch (IllegalArgumentException invalid) {
            return false;
        }
    }

    private long effectCount(Map<UUID, Set<String>> byTrial) {
        return byTrial.values().stream().mapToLong(Set::size).sum();
    }

    private ReplayAssessment assessReplay(UUID releaseId, Set<UUID> includedRunIds) {
        Set<UUID> comparableCaseRunIds = new LinkedHashSet<>();
        List<ReleaseAssuranceDto.ReplayComparison> items = jdbcTemplate.query("""
                select replay_case.id replay_case_run_id, replay_run.id replay_run_id,
                       baseline_run.id baseline_run_id, test_case.category,
                       replay_link.id replay_link_id,
                       replay_link.same_agent_artifact_fingerprint,
                       replay_link.same_fixture_digest,
                       replay_link.same_model_config,
                       replay_link.same_variant_hash,
                       replay_link.expected_policy_difference,
                       replay_link.comparison_json::text comparison_json
                  from test_runs replay_run
                  join test_case_runs replay_case on replay_case.test_run_id = replay_run.id
                  join test_cases test_case on test_case.id = replay_case.test_case_id
                  left join replay_links replay_link on replay_link.replay_case_run_id = replay_case.id
                  left join test_case_runs baseline_case on baseline_case.id = replay_link.baseline_case_run_id
                  left join test_runs baseline_run on baseline_run.id = baseline_case.test_run_id
                 where replay_run.release_id = ? and replay_run.mode = 'SEAL_REPLAY'
                   and replay_run.status = 'COMPLETED'
                   and (?::uuid[] is null or replay_run.id = any(?::uuid[]))
                 order by replay_run.created_at, replay_case.created_at
                """, (rs, row) -> {
            UUID caseRunId = rs.getObject("replay_case_run_id", UUID.class);
            List<String> reasons = replayMismatchReasons(rs);
            boolean comparable = reasons.isEmpty();
            if (comparable) {
                comparableCaseRunIds.add(caseRunId);
            }
            return new ReleaseAssuranceDto.ReplayComparison(
                    rs.getObject("baseline_run_id", UUID.class),
                    rs.getObject("replay_run_id", UUID.class),
                    rs.getString("category"), comparable, reasons
            );
        }, releaseId, uuidArray(includedRunIds), uuidArray(includedRunIds));
        int comparableCount = comparableCaseRunIds.size();
        ReleaseAssuranceDto.ReplaySummary summary = new ReleaseAssuranceDto.ReplaySummary(
                items.size(), comparableCount, items.size() - comparableCount,
                items.stream().allMatch(ReleaseAssuranceDto.ReplayComparison::comparable), items
        );
        return new ReplayAssessment(Set.copyOf(comparableCaseRunIds), summary);
    }

    private UUID[] uuidArray(Set<UUID> values) {
        return values == null ? null : values.toArray(UUID[]::new);
    }

    private List<String> replayMismatchReasons(ResultSet rs) throws SQLException {
        LinkedHashSet<String> reasons = new LinkedHashSet<>();
        if (rs.getObject("replay_link_id") == null) {
            return List.of("REPLAY_LINK_MISSING");
        }
        if (!rs.getBoolean("same_agent_artifact_fingerprint")) reasons.add("AGENT_ARTIFACT_MISMATCH");
        if (!rs.getBoolean("same_fixture_digest")) reasons.add("FIXTURE_DIGEST_MISMATCH");
        if (!rs.getBoolean("same_model_config")) reasons.add("MODEL_CONFIG_MISMATCH");
        if (!rs.getBoolean("same_variant_hash")) reasons.add("VARIANT_HASH_MISMATCH");
        if (!rs.getBoolean("expected_policy_difference")) reasons.add("EXPECTED_POLICY_DIFFERENCE_MISSING");
        JsonNode comparison = parseJson(rs.getString("comparison_json"));
        for (String field : List.of("mismatchReasons", "mismatches")) {
            JsonNode values = comparison.path(field);
            if (values.isArray()) {
                values.forEach(value -> {
                    if (value.isTextual() && !value.asText().isBlank()) reasons.add(value.asText());
                    else if (value.path("code").isTextual()) reasons.add(value.path("code").asText());
                    else if (value.path("reason").isTextual()) reasons.add(value.path("reason").asText());
                });
            }
        }
        if (!comparison.path("comparable").asBoolean(reasons.isEmpty()) && reasons.isEmpty()) {
            reasons.add("REPLAY_NOT_COMPARABLE");
        }
        return List.copyOf(reasons);
    }

    private CriticalTrialCoverage.Report criticalCoverage(UUID suiteId, List<TrialEvaluation> trials) {
        List<CriticalTrialCoverage.CaseDefinition> definitions = jdbcTemplate.query("""
                select id, category, partition_name, oracle_type from test_cases
                 where suite_id = ? and case_type = 'ATTACK' order by id
                """, (rs, row) -> new CriticalTrialCoverage.CaseDefinition(
                rs.getObject("id", UUID.class), rs.getString("category"),
                rs.getString("partition_name"), rs.getString("oracle_type")), suiteId);
        Map<UUID, TrialEvaluation> byCaseRun = new LinkedHashMap<>();
        trials.forEach(trial -> byCaseRun.put(trial.caseRunId(), trial));
        List<CriticalTrialCoverage.Trial> coverageTrials = byCaseRun.isEmpty() ? List.of()
                : jdbcTemplate.query("""
                        select id, test_case_id, trial_index from test_case_runs where id = any(?::uuid[])
                        """, (rs, row) -> {
                    TrialEvaluation trial = byCaseRun.get(rs.getObject("id", UUID.class));
                    return new CriticalTrialCoverage.Trial(rs.getObject("test_case_id", UUID.class),
                            rs.getInt("trial_index"), trial.mode(), trial.attackConclusive());
                }, (Object) byCaseRun.keySet().toArray(UUID[]::new));
        return new CriticalTrialCoverage().evaluate(definitions, coverageTrials);
    }

    private List<Map<String, Object>> criticalSuccessEvidence(List<TrialEvaluation> trials) {
        Map<UUID, TrialEvaluation> candidates = new LinkedHashMap<>();
        trials.stream().filter(TrialEvaluation::attack)
                .filter(trial -> Set.of("SEAL_REPLAY", "HELD_OUT").contains(trial.mode()))
                .forEach(trial -> candidates.put(trial.caseRunId(), trial));
        if (candidates.isEmpty()) return List.of();

        Map<UUID, Set<OracleReasonCode>> reasonsByCaseRun = new LinkedHashMap<>();
        jdbcTemplate.query("""
                select test_case_run_id, reason_code from oracle_results
                 where test_case_run_id = any(?::uuid[]) and outcome = 'ATTACK_SUCCESS'
                 order by test_case_run_id, reason_code
                """, rs -> {
            while (rs.next()) {
                OracleReasonCode reason = OracleReasonCode.valueOf(rs.getString("reason_code"));
                if (CRITICAL_REASONS.contains(reason)) {
                    reasonsByCaseRun.computeIfAbsent(rs.getObject("test_case_run_id", UUID.class),
                            ignored -> new LinkedHashSet<>()).add(reason);
                }
            }
            return null;
        }, (Object) candidates.keySet().toArray(UUID[]::new));
        return candidates.values().stream()
                .filter(trial -> reasonsByCaseRun.containsKey(trial.caseRunId()))
                .map(trial -> Map.<String, Object>of(
                        "runId", trial.runId(), "caseRunId", trial.caseRunId(), "mode", trial.mode(),
                        "reasonCodes", reasonsByCaseRun.get(trial.caseRunId()).stream().sorted().toList()))
                .toList();
    }

    private boolean completeDecisionEvidence(ReleaseMetrics metrics, List<TrialEvaluation> trials) {
        boolean completeTrials = !trials.isEmpty()
                && trials.stream().noneMatch(t -> t.inconclusive() || t.operationalError());
        boolean modesPresent = Set.of("BASELINE", "SEAL_REPLAY", "HELD_OUT", "REGRESSION").stream()
                .allMatch(mode -> trials.stream().anyMatch(trial -> mode.equals(trial.mode())));
        boolean metricsAvailable = List.of(
                metrics.attackSuccessRate(), metrics.attackBlockRate(), metrics.heldOutAttackSuccessRate(),
                metrics.normalTaskSuccessRate(), metrics.falseBlockRate(), metrics.operationalErrorRate()
        ).stream().allMatch(metric -> metric.status() == MetricValue.Status.AVAILABLE);
        return completeTrials && modesPresent && metricsAvailable;
    }

    private boolean hasOpenHighFinding(UUID releaseId) {
        Integer count = jdbcTemplate.queryForObject("""
                select count(*) from findings
                 where release_id = ? and severity in ('CRITICAL', 'HIGH')
                   and status not in ('RESOLVED', 'CLOSED')
                """, Integer.class, releaseId);
        return count != null && count > 0;
    }

    private EvidenceContext requireEvidenceContext(ReleaseRow release) {
        List<EvidenceContext> rows = jdbcTemplate.query("""
                select suite.id, suite.version, suite.suite_hash, run.fixture_version, run.fixture_digest,
                       max(coalesce(run.completed_at, run.updated_at)) tested_at
                  from test_runs run join test_suites suite on suite.id = run.suite_id
                 where run.release_id = ? and run.status = 'COMPLETED' and suite.status = 'READY'
                   and run.agent_artifact_fingerprint = ? and run.release_fingerprint = ?
                 group by suite.id, suite.version, suite.suite_hash, run.fixture_version, run.fixture_digest
                 order by tested_at desc limit 1
                """, (rs, row) -> new EvidenceContext(
                        rs.getObject("id", UUID.class), rs.getString("version"), rs.getString("suite_hash"),
                        rs.getString("fixture_version"), rs.getString("fixture_digest"),
                        rs.getTimestamp("tested_at").toInstant(), List.of()
                ), release.id(), release.agentArtifactFingerprint(), release.releaseFingerprint());
        if (rows.isEmpty()) {
            throw new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE,
                    "At least one completed TestRun with a READY TestSuite is required");
        }
        EvidenceContext selected = rows.getFirst();
        List<UUID> runIds = jdbcTemplate.queryForList("""
                select id from test_runs
                 where release_id = ? and suite_id = ? and status in ('COMPLETED', 'FAILED')
                   and fixture_version = ? and fixture_digest = ?
                   and agent_artifact_fingerprint = ? and release_fingerprint = ?
                 order by created_at, id
                """, UUID.class, release.id(), selected.suiteId(), selected.fixtureVersion(),
                selected.fixtureDigest(), release.agentArtifactFingerprint(), release.releaseFingerprint());
        return new EvidenceContext(selected.suiteId(), selected.suiteVersion(), selected.suiteHash(),
                selected.fixtureVersion(), selected.fixtureDigest(), selected.testedAt(), List.copyOf(runIds));
    }

    private ObjectNode safetyContract(ReleaseRow release) {
        if (release.safetyContractHash() == null) {
            return objectMapper.createObjectNode().put("status", "N_A")
                    .putNull("versionId").putNull("version").putNull("hash");
        }
        List<ObjectNode> rows = jdbcTemplate.query("""
                select version.id, version.version, version.policy_hash
                  from safety_contract_versions version
                  join safety_contracts contract on contract.id = version.contract_id
                 where contract.release_id = ? and version.state = 'APPROVED' and version.policy_hash = ?
                 order by version.version desc limit 1
                """, (rs, row) -> objectMapper.createObjectNode()
                        .put("status", "APPROVED").put("versionId", rs.getString("id"))
                        .put("version", rs.getInt("version")).put("hash", rs.getString("policy_hash")),
                release.id(), release.safetyContractHash());
        if (rows.isEmpty()) {
            throw new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE,
                    "Release safety contract hash has no approved contract version");
        }
        return rows.getFirst();
    }

    private ArrayNode toolFingerprints(UUID releaseId) {
        ArrayNode values = objectMapper.createArrayNode();
        jdbcTemplate.query("""
                select definition.tool_key, definition.schema_hash, definition.description_hash
                  from release_tools link join tool_definitions definition on definition.id = link.tool_definition_id
                 where link.release_id = ? and link.enabled = true order by link.ordinal
                """, rs -> {
            while (rs.next()) {
                values.add(objectMapper.createObjectNode().put("toolName", rs.getString("tool_key"))
                        .put("schemaHash", rs.getString("schema_hash"))
                        .put("descriptionHash", rs.getString("description_hash")));
            }
            return null;
        }, releaseId);
        return values;
    }

    private ObjectNode resultSummary(List<TrialEvaluation> trials, Set<UUID> comparableReplayCaseRunIds) {
        ObjectNode results = objectMapper.createObjectNode();
        results.set("baseline", resultMetric("BASELINE", trials, false, comparableReplayCaseRunIds));
        results.set("sealReplay", resultMetric("SEAL_REPLAY", trials, false, comparableReplayCaseRunIds));
        results.set("heldOut", resultMetric("HELD_OUT", trials, false, comparableReplayCaseRunIds));
        results.set("normalRegression", resultMetric("REGRESSION", trials, true, comparableReplayCaseRunIds));
        return results;
    }

    private ObjectNode resultMetric(String mode, List<TrialEvaluation> all, boolean normal,
                                    Set<UUID> comparableReplayCaseRunIds) {
        List<TrialEvaluation> trials = all.stream().filter(t -> mode.equals(t.mode()))
                .filter(trial -> normal ? trial.normalConclusive()
                        : ReleaseMetricsCalculator.attackRateEligible(trial, comparableReplayCaseRunIds)).toList();
        long numerator = trials.stream().filter(normal ? TrialEvaluation::normalSuccess : TrialEvaluation::attackSuccess)
                .count();
        List<UUID> runIds = trials.stream().map(TrialEvaluation::runId).distinct().sorted().toList();
        ObjectNode value = fractionDocument(numerator, trials.size(), runIds, "sourceRunIds");
        if (!trials.isEmpty()) {
            value.put("evidenceDigest", nodeDigest(value));
        }
        return value;
    }

    private ArrayNode metricArray(ReleaseMetrics metrics) {
        ArrayNode values = objectMapper.createArrayNode();
        for (MetricValue metric : List.of(
                metrics.attackSuccessRate(), metrics.attackBlockRate(), metrics.heldOutAttackSuccessRate(),
                metrics.normalTaskSuccessRate(), metrics.falseBlockRate(), metrics.operationalErrorRate()
        )) {
            ObjectNode value = fractionDocument(
                    metric.numerator() == null ? 0 : metric.numerator(),
                    metric.denominator() == null ? 0 : metric.denominator(),
                    metric.sourceRunIds(), "sourceTestRunIds"
            );
            value.put("metric", metric.name());
            value.put("calculatorVersion", CALCULATOR_VERSION);
            if (metric.status() == MetricValue.Status.AVAILABLE) {
                value.put("evidenceDigest", nodeDigest(value));
            }
            values.add(value);
        }
        return values;
    }

    private ArrayNode observedEffectCounts(ReleaseMetrics metrics, List<TrialEvaluation> effectTrials) {
        List<UUID> effectRunIds = effectTrials.stream().filter(TrialEvaluation::attack)
                .map(TrialEvaluation::runId).distinct().sorted().toList();
        ArrayNode counts = objectMapper.createArrayNode();
        counts.add(effectCountDocument("UnauthorizedRecordExposureCount",
                metrics.unauthorizedRecordExposureCount(), effectRunIds));
        counts.add(effectCountDocument("ExfiltrationSuccessCount",
                metrics.exfiltrationSuccessCount(), effectRunIds));
        return counts;
    }

    private ObjectNode effectCountDocument(String name, Long count, List<UUID> runIds) {
        ObjectNode value = objectMapper.createObjectNode();
        value.put("metric", name).put("calculatorVersion", CALCULATOR_VERSION);
        if (count == null) {
            value.put("status", "N_A").put("reason", "EFFECT_EVIDENCE_INCOMPLETE_OR_NO_CONCLUSIVE_TRIALS");
        } else {
            value.put("status", "AVAILABLE").put("value", count);
        }
        ArrayNode sources = value.putArray("sourceTestRunIds");
        runIds.forEach(id -> sources.add(id.toString()));
        if (count != null) value.put("evidenceDigest", nodeDigest(value));
        return value;
    }

    private ObjectNode fractionDocument(long numerator, long denominator, List<UUID> runIds, String sourceField) {
        ObjectNode value = objectMapper.createObjectNode();
        if (denominator == 0) {
            value.put("status", "N_A").put("reason", "NO_CONCLUSIVE_TRIALS");
        } else {
            value.put("status", "AVAILABLE").put("numerator", numerator).put("denominator", denominator);
        }
        ArrayNode sources = value.putArray(sourceField);
        runIds.forEach(id -> sources.add(id.toString()));
        return value;
    }

    private ArrayNode remainingFindings(UUID releaseId) {
        ArrayNode findings = objectMapper.createArrayNode();
        jdbcTemplate.query("""
                select finding.id, finding.severity, finding.status, oracle.evidence_digest
                  from findings finding join oracle_results oracle on oracle.id = finding.source_oracle_result_id
                 where finding.release_id = ? and finding.status not in ('RESOLVED', 'CLOSED')
                 order by finding.created_at, finding.id
                """, rs -> {
            while (rs.next()) {
                findings.add(objectMapper.createObjectNode().put("id", rs.getString("id"))
                        .put("severity", rs.getString("severity")).put("status", rs.getString("status"))
                        .put("evidenceDigest", rs.getString("evidence_digest")));
            }
            return null;
        }, releaseId);
        return findings;
    }

    private JsonNode approvedPatch(UUID releaseId) {
        List<ObjectNode> rows = jdbcTemplate.query("""
                select proposal.id proposal_id, approval.id approval_id, approval.base_hash, approval.result_hash
                  from patch_approvals approval
                  join patch_proposals proposal on proposal.id = approval.patch_proposal_id
                  join findings finding on finding.id = proposal.finding_id
                 where finding.release_id = ? and approval.decision = 'APPROVED'
                 order by approval.decided_at desc limit 1
                """, (rs, row) -> objectMapper.createObjectNode()
                        .put("proposalId", rs.getString("proposal_id")).put("approvalId", rs.getString("approval_id"))
                        .put("baseHash", rs.getString("base_hash")).put("resultHash", rs.getString("result_hash")),
                releaseId);
        return rows.isEmpty() ? objectMapper.nullNode() : rows.getFirst();
    }

    private ReleaseRow requireRelease(UUID releaseId, boolean lock) {
        String suffix = lock ? " for update" : "";
        List<ReleaseRow> rows = jdbcTemplate.query("""
                select release.id, release.version, release.manifest_json::text,
                       release.agent_artifact_fingerprint, release.release_fingerprint,
                       release.safety_contract_hash, release.lifecycle_state,
                       agent.id agent_id, agent.name agent_name, agent.workspace_id
                  from agent_releases release join agents agent on agent.id = release.agent_id
                 where release.id = ?
                """ + suffix, this::mapRelease, releaseId);
        if (rows.isEmpty()) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "Release not found");
        }
        return rows.getFirst();
    }

    private ReleaseRow mapRelease(ResultSet rs, int row) throws SQLException {
        String agentFingerprint = rs.getString("agent_artifact_fingerprint");
        String releaseFingerprint = rs.getString("release_fingerprint");
        String contractHash = rs.getString("safety_contract_hash");
        boolean integrity = releaseFingerprint.equals(
                fingerprintService.releaseFingerprint(agentFingerprint, contractHash)
        );
        return new ReleaseRow(
                rs.getObject("id", UUID.class), rs.getObject("agent_id", UUID.class),
                rs.getObject("workspace_id", UUID.class), rs.getString("agent_name"), rs.getString("version"),
                parseJson(rs.getString("manifest_json")), agentFingerprint, releaseFingerprint,
                contractHash, rs.getString("lifecycle_state"), integrity
        );
    }

    private String nodeDigest(JsonNode value) { return digest(value); }
    private String digest(JsonNode value) {
        return digestService.sha256(canonicalJsonService.canonicalize(value));
    }
    private String json(JsonNode value) {
        try { return objectMapper.writeValueAsString(value); }
        catch (Exception exception) { throw new IllegalStateException("JSON serialization failed", exception); }
    }
    private JsonNode parseJson(String value) {
        try { return objectMapper.readTree(value); }
        catch (Exception exception) { throw new IllegalStateException("Stored JSON is invalid", exception); }
    }
    private String normalizeActor(String actor) {
        return actor == null || actor.isBlank() ? "demo-user" : actor.strip();
    }
    private String requireReviewer(String actor) {
        if (actor == null || actor.isBlank() || actor.strip().length() > 120) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR,
                    "X-Actor-Id is required and must not exceed 120 characters");
        }
        return actor.strip();
    }
    private String requireComment(String comment) {
        if (comment == null || comment.isBlank() || comment.strip().length() > 1000) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR,
                    "Decision comment is required and must not exceed 1000 characters");
        }
        return comment.strip();
    }
    private String normalizeEtag(String value) {
        if (value == null) { return ""; }
        String normalized = value.strip();
        return normalized.length() >= 2 && normalized.startsWith("\"") && normalized.endsWith("\"")
                ? normalized.substring(1, normalized.length() - 1) : normalized;
    }
    private int rank(DecisionValue value) {
        return switch (value) { case BLOCKED -> 0; case REVIEW -> 1; case PASS -> 2; };
    }

    private static final class MutableTrial {
        private final UUID runId; private final UUID caseRunId; private final String mode;
        private final String caseType; private final String category; private final String severity;
        private final String status; private final boolean forbiddenAttempt; private final boolean policyDenied;
        private final boolean operationalError;
        private final Set<OracleOutcome> outcomes = new LinkedHashSet<>();
        private final Set<OracleReasonCode> reasons = new LinkedHashSet<>();
        private MutableTrial(UUID runId, UUID caseRunId, String mode, String caseType, String category,
                             String severity, String status, boolean forbiddenAttempt, boolean policyDenied,
                             boolean operationalError) {
            this.runId = runId; this.caseRunId = caseRunId; this.mode = mode; this.caseType = caseType;
            this.category = category; this.severity = severity; this.status = status;
            this.forbiddenAttempt = forbiddenAttempt; this.policyDenied = policyDenied;
            this.operationalError = operationalError;
        }
        private TrialEvaluation immutable() {
            return new TrialEvaluation(runId, caseRunId, mode, caseType, category, severity, status,
                    outcomes, reasons, forbiddenAttempt, policyDenied, operationalError);
        }
    }

    private record ReleaseRow(UUID id, UUID agentId, UUID workspaceId, String agentName, String version,
                              JsonNode manifest, String agentArtifactFingerprint, String releaseFingerprint,
                              String safetyContractHash, String lifecycleState, boolean integrityValid) { }
    private record EvidenceContext(UUID suiteId, String suiteVersion, String suiteHash,
                                   String fixtureVersion, String fixtureDigest, Instant testedAt,
                                   List<UUID> runIds) { }
    private record SnapshotBuild(GateDecision decision, ObjectNode snapshot) { }
    private record EffectEvidence(UUID caseRunId, String oracleType, String reasonCode,
                                  String evidenceJson) { }
    private record MutationOracle(UUID caseRunId, String oracleType, String outcome, String reasonCode,
                                  UUID sourceEventId, String evidenceJson) { }
    private record MutationStateEvent(UUID caseRunId, UUID runId, UUID eventId, long sequence,
                                      UUID responseId, boolean validLink) { }
    private record ReplayAssessment(Set<UUID> comparableCaseRunIds,
                                    ReleaseAssuranceDto.ReplaySummary summary) { }
}
