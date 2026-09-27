package com.finsecseal.attestation;

import com.finsecseal.audit.AuditService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.persistence.UuidV7;
import com.finsecseal.evidence.RedactionService;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.HtmlUtils;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

@Service
@Transactional(readOnly = true)
public class AttestationService {

    public static final String DISCLAIMER_VERSION = "finsec-internal/v1";
    public static final String DISCLAIMER_KO =
            "본 Release Decision은 FINSEC SEAL MVP 내부 평가 정책에 따른 것이며 "
                    + "공식 금융보안 인증 또는 규제 준수 판정이 아니다.";
    public static final String DISCLAIMER_EN =
            "This is an internal FINSEC SEAL MVP security assessment and not an official certification "
                    + "by any regulatory or financial-security authority.";

    private static final String FORMAT_VERSION = "1.0";
    private static final String ATTESTATION_TYPE = "FINSEC_SEAL_INTERNAL_RELEASE_ATTESTATION";
    private static final Pattern DIGEST = Pattern.compile("sha256:[0-9a-f]{64}");
    private static final Set<String> TERMINAL_DECISIONS = Set.of("PASS", "REVIEW", "BLOCKED");
    private static final List<String> GC_IDS = List.of("GC-01", "GC-02", "GC-03", "GC-04");
    private static final List<String> GC_INVARIANTS = List.of("INV-01", "INV-02", "INV-04", "INV-05");
    private static final List<String> REVALIDATION_TRIGGERS = List.of(
            "MODEL_CHANGE",
            "SYSTEM_PROMPT_CHANGE",
            "TOOL_SET_OR_SCHEMA_OR_DESCRIPTION_CHANGE",
            "RAG_CHANGE",
            "SAFETY_CONTRACT_CHANGE",
            "BUSINESS_PURPOSE_OR_CONTEXT_CHANGE"
    );

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final CanonicalJsonService canonicalJsonService;
    private final DigestService digestService;
    private final RedactionService redactionService;
    private final AuditService auditService;

    public AttestationService(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            CanonicalJsonService canonicalJsonService,
            DigestService digestService,
            RedactionService redactionService,
            AuditService auditService
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.canonicalJsonService = canonicalJsonService;
        this.digestService = digestService;
        this.redactionService = redactionService;
        this.auditService = auditService;
    }

    @Transactional
    public AttestationDto.View findOrCreate(UUID releaseId, String actorId) {
        lockRelease(releaseId);
        DecisionSnapshot decision = latestDecision(releaseId);
        Invalidation invalidation = findInvalidation(decision.id());
        validateDecisionState(decision, invalidation);
        JsonNode snapshot = decision.inputSnapshot();
        validateSnapshot(decision, snapshot, invalidation != null);
        StoredAttestation existing = findStored(decision.id());
        // A stored pre-report PASS remains readable only after the original
        // Decision/document/hash checks below. No new or modern-schema PASS
        // can be attested without a versioned GC negative-proof contract.
        if ("PASS".equals(decision.decision())
                && (existing == null || snapshot.has("criticalInvariantAnySuccess"))) {
            incomplete("PASS Attestation requires a verifiable GC negative-proof contract");
        }
        ObjectNode expectedDocument = buildDocument(decision, snapshot);
        String expectedHash = digestService.sha256(canonicalJsonService.canonicalize(expectedDocument));
        String expectedHtml = renderHtml(expectedDocument, expectedHash);
        boolean inserted = false;
        if (existing == null) {
            UUID attestationId = UuidV7.generate();
            inserted = jdbcTemplate.update("""
                    insert into release_attestations
                        (id, release_decision_id, format_version, document_json, document_hash,
                         html_content, generated_at, disclaimer_version)
                    values (?, ?, ?, ?::jsonb, ?, ?, ?, ?)
                    on conflict (release_decision_id) do nothing
                    """,
                    attestationId,
                    decision.id(),
                    FORMAT_VERSION,
                    json(expectedDocument),
                    expectedHash,
                    expectedHtml,
                    Timestamp.from(decision.confirmedAt()),
                    DISCLAIMER_VERSION
            ) == 1;
            existing = findStored(decision.id());
            if (existing == null) {
                throw new IllegalStateException("Attestation insert did not produce a readable row");
            }
            if (inserted) {
                ObjectNode metadata = objectMapper.createObjectNode();
                metadata.put("schemaVersion", FORMAT_VERSION);
                metadata.put("releaseId", releaseId.toString());
                metadata.put("releaseDecisionId", decision.id().toString());
                metadata.put("documentHash", expectedHash);
                auditService.append(
                        decision.workspaceId(), normalizeActor(actorId), "RELEASE_ATTESTATION_GENERATED",
                        "RELEASE_ATTESTATION", existing.id(), decision.inputDigest(), expectedHash, metadata
                );
            }
        }
        validateStored(decision, existing, expectedDocument, expectedHash, expectedHtml);
        return view(existing, invalidation);
    }

    @Transactional
    public AttestationDto.Export export(UUID releaseId, String format, String actorId) {
        AttestationDto.View view = findOrCreate(releaseId, actorId);
        String normalized = format == null ? "json" : format.toLowerCase(java.util.Locale.ROOT);
        String suffix = releaseId.toString().substring(0, 8);
        return switch (normalized) {
            case "json" -> new AttestationDto.Export(
                    canonicalJsonService.canonicalize(view.document()),
                    "application/json",
                    "finsec-attestation-" + suffix + ".json",
                    view.documentHash(),
                    view.stale()
            );
            case "html" -> {
                StoredAttestation stored = findStored(view.releaseDecisionId());
                String html = view.stale()
                        ? renderStaleHtml(stored.html(), view.invalidation())
                        : stored.html();
                yield new AttestationDto.Export(
                        html.getBytes(StandardCharsets.UTF_8),
                        "text/html; charset=UTF-8",
                        "finsec-attestation-" + suffix + ".html",
                        view.documentHash(),
                        view.stale()
                );
            }
            default -> throw new BusinessException(
                    ErrorCode.VALIDATION_ERROR,
                    "format must be json or html"
            );
        };
    }

    private void lockRelease(UUID releaseId) {
        List<UUID> rows = jdbcTemplate.query(
                "select id from agent_releases where id = ? for update",
                (resultSet, rowNumber) -> resultSet.getObject("id", UUID.class),
                releaseId
        );
        if (rows.isEmpty()) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "Release not found");
        }
    }

    private DecisionSnapshot latestDecision(UUID releaseId) {
        List<DecisionSnapshot> decisions = jdbcTemplate.query("""
                select decision.id, decision.release_id, decision.decision, decision.gate_policy_version,
                       decision.input_snapshot_json::text, decision.input_digest, decision.proposed_at,
                       decision.confirmed_by, decision.confirmed_at,
                       release.version release_version, release.agent_artifact_fingerprint,
                       release.release_fingerprint, release.safety_contract_hash, release.lifecycle_state,
                       agent.id agent_id, agent.workspace_id
                  from release_decisions decision
                  join agent_releases release on release.id = decision.release_id
                  join agents agent on agent.id = release.agent_id
                 where decision.release_id = ?
                 order by decision.confirmed_at desc, decision.created_at desc, decision.id desc
                 limit 1
                """, (resultSet, rowNumber) -> new DecisionSnapshot(
                        resultSet.getObject("id", UUID.class),
                        resultSet.getObject("release_id", UUID.class),
                        resultSet.getString("decision"),
                        resultSet.getString("gate_policy_version"),
                        parseJson(resultSet.getString("input_snapshot_json")),
                        resultSet.getString("input_digest"),
                        resultSet.getTimestamp("proposed_at").toInstant(),
                        resultSet.getString("confirmed_by"),
                        resultSet.getTimestamp("confirmed_at").toInstant(),
                        resultSet.getString("release_version"),
                        resultSet.getString("agent_artifact_fingerprint"),
                        resultSet.getString("release_fingerprint"),
                        resultSet.getString("safety_contract_hash"),
                        resultSet.getString("lifecycle_state"),
                        resultSet.getObject("agent_id", UUID.class),
                        resultSet.getObject("workspace_id", UUID.class)
                ), releaseId);
        if (decisions.isEmpty()) {
            throw new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, "A confirmed ReleaseDecision is required");
        }
        return decisions.getFirst();
    }

    private void validateDecisionState(DecisionSnapshot decision, Invalidation invalidation) {
        if (!TERMINAL_DECISIONS.contains(decision.decision())) {
            incomplete("ReleaseDecision must be terminal");
        }
        if (invalidation != null) {
            return;
        }
        if ("NEEDS_REVALIDATION".equals(decision.lifecycleState())) {
            incomplete("NEEDS_REVALIDATION requires Decision invalidation evidence");
        }
        if (!decision.decision().equals(decision.lifecycleState())) {
            incomplete("Release lifecycle does not match the confirmed Decision");
        }
    }

    private void validateSnapshot(DecisionSnapshot decision, JsonNode snapshot, boolean invalidated) {
        if (!snapshot.isObject()) {
            incomplete("Decision input snapshot must be an object");
        }
        String recomputedDigest = digestService.sha256(canonicalJsonService.canonicalize(snapshot));
        if (!decision.inputDigest().equals(recomputedDigest)) {
            incomplete("Decision input snapshot digest does not match stored inputDigest");
        }
        JsonNode redacted = redactionService.redact(snapshot).redacted();
        if (!redacted.equals(snapshot)) {
            incomplete("Decision input snapshot contains non-redacted classified values");
        }

        requireObject(snapshot, "agent");
        requireObject(snapshot, "release");
        requireObject(snapshot, "model");
        requireUuid(snapshot.at("/agent/id"), "agent.id");
        requireText(snapshot.at("/agent/name"), "agent.name");
        requireUuid(snapshot.at("/release/id"), "release.id");
        requireText(snapshot.at("/release/version"), "release.version");
        requireDigest(snapshot.at("/release/fingerprint"), "release.fingerprint");
        requireDigest(snapshot.at("/release/agentArtifactFingerprint"), "release.agentArtifactFingerprint");
        requireText(snapshot.at("/model/provider"), "model.provider");
        requireText(snapshot.at("/model/name"), "model.name");
        requireText(snapshot.at("/model/resolvedName"), "model.resolvedName");
        requireDigest(snapshot.at("/model/parametersHash"), "model.parametersHash");
        requireDigest(snapshot.path("systemPromptFingerprint"), "systemPromptFingerprint");
        requireDigest(snapshot.path("toolSetFingerprint"), "toolSetFingerprint");
        requireDigest(snapshot.path("ragConfigurationFingerprint"), "ragConfigurationFingerprint");
        requireArray(snapshot, "toolSchemaFingerprints");
        for (JsonNode tool : snapshot.path("toolSchemaFingerprints")) {
            if (!tool.isObject() || !tool.path("toolName").isString()) {
                incomplete("Each toolSchemaFingerprint requires toolName");
            }
            requireDigest(tool.path("schemaHash"), "toolSchemaFingerprints.schemaHash");
            requireDigest(tool.path("descriptionHash"), "toolSchemaFingerprints.descriptionHash");
        }
        requireObject(snapshot, "safetyContract");
        requireObject(snapshot, "testSuite");
        requireObject(snapshot, "sandbox");
        requireObject(snapshot, "results");
        requireArray(snapshot, "metrics");
        if (snapshot.has("observedEffectCounts")) requireArray(snapshot, "observedEffectCounts");
        requireArray(snapshot, "remainingFindings");
        if (!snapshot.has("approvedPatch")) {
            incomplete("Decision input snapshot requires approvedPatch, using null when not applicable");
        }
        requireObject(snapshot, "decision");
        requireArray(snapshot.path("decision"), "ruleTrace");
        validateEvidenceStructure(decision, snapshot);
        validateCriticalEvidence(decision, snapshot);
        if (!snapshot.path("testedAt").isString()) {
            incomplete("Decision input snapshot requires testedAt");
        }
        try {
            Instant.parse(snapshot.path("testedAt").asString());
        } catch (DateTimeParseException exception) {
            incomplete("testedAt must be an ISO-8601 instant");
        }

        if (!decision.agentId().toString().equals(snapshot.at("/agent/id").asString())
                || !decision.releaseId().toString().equals(snapshot.at("/release/id").asString())
                || !decision.releaseVersion().equals(snapshot.at("/release/version").asString())) {
            incomplete("Decision input snapshot Agent/Release identity does not match its ReleaseDecision");
        }
        JsonNode snapshotAgentFingerprint = snapshot.at("/release/agentArtifactFingerprint");
        if (!snapshotAgentFingerprint.isMissingNode()
                && !decision.agentFingerprint().equals(snapshotAgentFingerprint.asString())) {
            incomplete("Decision input snapshot Agent artifact fingerprint does not match the Release");
        }
        JsonNode snapshotDecisionValue = snapshot.at("/decision/value");
        if (!snapshotDecisionValue.isMissingNode()
                && !decision.decision().equals(snapshotDecisionValue.asString())) {
            incomplete("Decision input snapshot decision value does not match the confirmed Decision");
        }
        JsonNode snapshotGateVersion = snapshot.at("/decision/gatePolicyVersion");
        if (!snapshotGateVersion.isMissingNode()
                && !decision.gatePolicyVersion().equals(snapshotGateVersion.asString())) {
            incomplete("Decision input snapshot gate version does not match the confirmed Decision");
        }
        if (!invalidated) {
            if (!decision.releaseFingerprint().equals(snapshot.at("/release/fingerprint").asString())) {
                incomplete("Decision snapshot fingerprint does not match the current Release");
            }
            JsonNode contractHash = snapshot.at("/safetyContract/hash");
            if (decision.safetyContractHash() == null) {
                if (!contractHash.isMissingNode() && !contractHash.isNull()) {
                    incomplete("Decision snapshot contract hash is not attached to the Release");
                }
            } else if (!decision.safetyContractHash().equals(contractHash.asString())) {
                incomplete("Decision snapshot contract hash does not match the Release");
            }
        }
    }

    private ObjectNode buildDocument(DecisionSnapshot decision, JsonNode snapshot) {
        ObjectNode document = objectMapper.createObjectNode();
        document.put("schemaVersion", FORMAT_VERSION);
        document.put("attestationType", ATTESTATION_TYPE);
        document.put("canonicalizationVersion", CanonicalJsonService.VERSION);
        copy(document, snapshot, "agent");
        copy(document, snapshot, "release");
        copy(document, snapshot, "model");
        copy(document, snapshot, "systemPromptFingerprint");
        copy(document, snapshot, "toolSetFingerprint");
        copy(document, snapshot, "toolSchemaFingerprints");
        copy(document, snapshot, "ragConfigurationFingerprint");
        copy(document, snapshot, "safetyContract");
        copy(document, snapshot, "testSuite");
        copy(document, snapshot, "sandbox");
        copy(document, snapshot, "results");
        copy(document, snapshot, "metrics");
        if (snapshot.has("observedEffectCounts")) copy(document, snapshot, "observedEffectCounts");
        if (snapshot.has("criticalInvariantAnySuccess")) {
            copy(document, snapshot, "criticalInvariantAnySuccess");
            copy(document, snapshot, "criticalTrialCoverage");
        }
        copy(document, snapshot, "remainingFindings");
        copy(document, snapshot, "approvedPatch");

        ObjectNode decisionDocument = objectMapper.createObjectNode();
        decisionDocument.put("id", decision.id().toString());
        decisionDocument.put("value", decision.decision());
        decisionDocument.put("gatePolicyVersion", decision.gatePolicyVersion());
        decisionDocument.set("ruleTrace", snapshot.at("/decision/ruleTrace").deepCopy());
        decisionDocument.put("inputDigest", decision.inputDigest());
        decisionDocument.put("proposedAt", decision.proposedAt().toString());
        decisionDocument.put("confirmedAt", decision.confirmedAt().toString());
        document.set("decision", decisionDocument);

        ObjectNode reviewer = objectMapper.createObjectNode();
        reviewer.put("actorId", decision.confirmedBy());
        reviewer.put("role", "AI_GOVERNANCE_REVIEWER");
        reviewer.put("demoMode", true);
        document.set("reviewer", reviewer);
        document.set("testedAt", snapshot.path("testedAt").deepCopy());
        ArrayNode triggers = document.putArray("revalidationTriggers");
        REVALIDATION_TRIGGERS.forEach(triggers::add);
        ObjectNode disclaimer = objectMapper.createObjectNode();
        disclaimer.put("version", DISCLAIMER_VERSION);
        disclaimer.put("ko", DISCLAIMER_KO);
        disclaimer.put("en", DISCLAIMER_EN);
        document.set("disclaimer", disclaimer);
        document.put("generatedAt", decision.confirmedAt().toString());
        return document;
    }

    private StoredAttestation findStored(UUID decisionId) {
        List<StoredAttestation> rows = jdbcTemplate.query("""
                select id, release_decision_id, format_version, document_json::text, document_hash,
                       html_content, generated_at, disclaimer_version
                  from release_attestations
                 where release_decision_id = ?
                """, (resultSet, rowNumber) -> new StoredAttestation(
                        resultSet.getObject("id", UUID.class),
                        resultSet.getObject("release_decision_id", UUID.class),
                        resultSet.getString("format_version"),
                        parseJson(resultSet.getString("document_json")),
                        resultSet.getString("document_hash"),
                        resultSet.getString("html_content"),
                        resultSet.getTimestamp("generated_at").toInstant(),
                        resultSet.getString("disclaimer_version")
                ), decisionId);
        return rows.isEmpty() ? null : rows.getFirst();
    }

    private void validateStored(
            DecisionSnapshot decision,
            StoredAttestation stored,
            JsonNode expectedDocument,
            String expectedHash,
            String expectedHtml
    ) {
        String recomputed = digestService.sha256(canonicalJsonService.canonicalize(stored.document()));
        if (!FORMAT_VERSION.equals(stored.formatVersion())
                || !DISCLAIMER_VERSION.equals(stored.disclaimerVersion())
                || !recomputed.equals(stored.documentHash())
                || !expectedHash.equals(stored.documentHash())
                || !expectedDocument.equals(stored.document())
                || !expectedHtml.equals(stored.html())
                || !decision.id().toString().equals(stored.document().at("/decision/id").asString())
                || !decision.inputDigest().equals(stored.document().at("/decision/inputDigest").asString())
                || !decision.releaseId().toString().equals(stored.document().at("/release/id").asString())
                || !stored.generatedAt().equals(decision.confirmedAt())
                || !stored.html().contains(DISCLAIMER_KO)
                || !stored.html().contains(DISCLAIMER_EN)) {
            throw new BusinessException(ErrorCode.RELEASE_CHANGED, "Stored Attestation integrity check failed");
        }
    }

    private void validateEvidenceStructure(DecisionSnapshot decision, JsonNode snapshot) {
        JsonNode contract = snapshot.path("safetyContract");
        if ("N_A".equals(contract.path("status").asString())) {
            if ((!contract.path("versionId").isMissingNode() && !contract.path("versionId").isNull())
                    || (!contract.path("hash").isMissingNode() && !contract.path("hash").isNull())) {
                incomplete("N_A safetyContract must not claim a version or hash");
            }
        } else {
            requireUuid(contract.path("versionId"), "safetyContract.versionId");
            if (!contract.path("version").isIntegralNumber() || contract.path("version").longValue() < 1) {
                incomplete("safetyContract.version must be a positive integer");
            }
            requireDigest(contract.path("hash"), "safetyContract.hash");
            Integer matchingContracts = jdbcTemplate.queryForObject("""
                    select count(*)
                      from safety_contract_versions version
                      join safety_contracts contract on contract.id = version.contract_id
                     where version.id = ? and contract.release_id = ? and contract.workspace_id = ?
                       and version.version = ? and version.policy_hash = ? and version.state = 'APPROVED'
                    """, Integer.class,
                    UUID.fromString(contract.path("versionId").asString()),
                    decision.releaseId(),
                    decision.workspaceId(),
                    contract.path("version").intValue(),
                    contract.path("hash").asString()
            );
            if (matchingContracts == null || matchingContracts != 1) {
                incomplete("safetyContract version/hash does not close to this Release");
            }
        }

        JsonNode suite = snapshot.path("testSuite");
        requireUuid(suite.path("id"), "testSuite.id");
        requireText(suite.path("version"), "testSuite.version");
        requireDigest(suite.path("hash"), "testSuite.hash");
        Integer matchingSuites = jdbcTemplate.queryForObject("""
                select count(*) from test_suites
                 where id = ? and workspace_id = ? and version = ? and suite_hash = ?
                   and status = 'READY'
                """, Integer.class,
                UUID.fromString(suite.path("id").asString()),
                decision.workspaceId(),
                suite.path("version").asString(),
                suite.path("hash").asString()
        );
        if (matchingSuites == null || matchingSuites != 1) {
            incomplete("testSuite identity/version/hash does not close to stored evidence");
        }

        JsonNode sandbox = snapshot.path("sandbox");
        requireText(sandbox.path("fixtureVersion"), "sandbox.fixtureVersion");
        requireDigest(sandbox.path("fixtureDigest"), "sandbox.fixtureDigest");

        JsonNode results = snapshot.path("results");
        for (String name : List.of("baseline", "sealReplay", "heldOut", "normalRegression")) {
            JsonNode result = results.path(name);
            if (!result.isObject()) {
                incomplete("results." + name + " must be an object");
            }
            boolean notApplicable = "N_A".equals(result.path("status").asString());
            if (notApplicable) {
                requireText(result.path("reason"), "results." + name + ".reason");
            } else {
                validateFraction(result, "results." + name);
                requireDigest(result.path("evidenceDigest"), "results." + name + ".evidenceDigest");
            }
            int sourceCount = validateSourceRuns(
                    decision,
                    snapshot,
                    result.path("sourceRunIds"),
                    "results." + name + ".sourceRunIds"
            );
            if ("PASS".equals(decision.decision()) && (notApplicable || sourceCount == 0)) {
                incomplete("PASS Decision requires conclusive source evidence for results." + name);
            }
        }

        JsonNode metrics = snapshot.path("metrics");
        if (metrics.isEmpty()) {
            incomplete("metrics must contain explicit values or N_A entries");
        }
        Set<String> metricNames = new HashSet<>();
        for (int index = 0; index < metrics.size(); index++) {
            JsonNode metric = metrics.get(index);
            String path = "metrics[" + index + "]";
            if (!metric.isObject()) {
                incomplete(path + " must be an object");
            }
            requireText(metric.path("metric"), path + ".metric");
            String metricName = metric.path("metric").asString();
            if (!metricNames.add(metricName)) {
                incomplete("metric names must be unique");
            }
            requireText(metric.path("calculatorVersion"), path + ".calculatorVersion");
            boolean notApplicable = "N_A".equals(metric.path("status").asString());
            if (notApplicable) {
                requireText(metric.path("reason"), path + ".reason");
            } else {
                validateFraction(metric, path);
                requireDigest(metric.path("evidenceDigest"), path + ".evidenceDigest");
            }
            int sourceCount = validateSourceRuns(
                    decision,
                    snapshot,
                    metric.path("sourceTestRunIds"),
                    path + ".sourceTestRunIds",
                    "OperationalErrorRate".equals(metricName)
                            ? RunSourceScope.SCHEDULED : RunSourceScope.COMPLETED
            );
            if ("PASS".equals(decision.decision()) && (notApplicable || sourceCount == 0)) {
                incomplete("PASS Decision requires conclusive source evidence for " + path);
            }
        }

        if (snapshot.has("observedEffectCounts")) {
            validateObservedEffectCounts(decision, snapshot);
        }

        JsonNode findings = snapshot.path("remainingFindings");
        for (int index = 0; index < findings.size(); index++) {
            JsonNode finding = findings.get(index);
            String path = "remainingFindings[" + index + "]";
            if (!finding.isObject()) {
                incomplete(path + " must be an object");
            }
            requireUuid(finding.path("id"), path + ".id");
            requireText(finding.path("severity"), path + ".severity");
            requireText(finding.path("status"), path + ".status");
            requireDigest(finding.path("evidenceDigest"), path + ".evidenceDigest");
            Integer matchingFinding = jdbcTemplate.queryForObject("""
                    select count(*)
                      from findings finding
                      join oracle_results source on source.id = finding.source_oracle_result_id
                     where finding.id = ? and finding.release_id = ?
                       and finding.severity = ?
                       and source.evidence_digest = ?
                    """, Integer.class,
                    UUID.fromString(finding.path("id").asString()),
                    decision.releaseId(),
                    finding.path("severity").asString(),
                    finding.path("evidenceDigest").asString()
            );
            if (matchingFinding == null || matchingFinding != 1) {
                incomplete(path + " does not close to a Finding for this Release");
            }
        }

        JsonNode patch = snapshot.path("approvedPatch");
        if (!patch.isNull()) {
            if (!patch.isObject()) {
                incomplete("approvedPatch must be an object or null");
            }
            requireUuid(patch.path("proposalId"), "approvedPatch.proposalId");
            requireUuid(patch.path("approvalId"), "approvedPatch.approvalId");
            requireDigest(patch.path("baseHash"), "approvedPatch.baseHash");
            requireDigest(patch.path("resultHash"), "approvedPatch.resultHash");
            Integer matchingPatch = jdbcTemplate.queryForObject("""
                    select count(*)
                      from patch_approvals approval
                      join patch_proposals proposal on proposal.id = approval.patch_proposal_id
                      join findings finding on finding.id = proposal.finding_id
                     where proposal.id = ? and approval.id = ? and finding.release_id = ?
                       and approval.decision = 'APPROVED'
                       and approval.base_hash = ? and approval.result_hash = ?
                    """, Integer.class,
                    UUID.fromString(patch.path("proposalId").asString()),
                    UUID.fromString(patch.path("approvalId").asString()),
                    decision.releaseId(),
                    patch.path("baseHash").asString(),
                    patch.path("resultHash").asString()
            );
            if (matchingPatch == null || matchingPatch != 1) {
                incomplete("approvedPatch does not close to an approved Patch for this Release");
            }
        }

        JsonNode ruleTrace = snapshot.at("/decision/ruleTrace");
        if (ruleTrace.isEmpty()) {
            incomplete("decision.ruleTrace must contain at least one applied rule");
        }
        for (int index = 0; index < ruleTrace.size(); index++) {
            JsonNode rule = ruleTrace.get(index);
            if (!rule.isObject()) {
                incomplete("decision.ruleTrace entries must be objects");
            }
            requireText(rule.path("ruleId"), "decision.ruleTrace[" + index + "].ruleId");
        }
    }

    private void validateObservedEffectCounts(DecisionSnapshot decision, JsonNode snapshot) {
        JsonNode counts = snapshot.path("observedEffectCounts");
        List<String> expectedNames = List.of("UnauthorizedRecordExposureCount", "ExfiltrationSuccessCount");
        if (!counts.isArray() || counts.size() != expectedNames.size()) {
            incomplete("observedEffectCounts requires exactly two ordered entries");
        }
        for (int index = 0; index < expectedNames.size(); index++) {
            JsonNode count = counts.get(index);
            String path = "observedEffectCounts[" + index + "]";
            if (!count.isObject() || !expectedNames.get(index).equals(count.path("metric").asString())) {
                incomplete(path + " requires the expected metric name and order");
            }
            if (!"mvp-metrics/1".equals(count.path("calculatorVersion").asString())) {
                incomplete(path + ".calculatorVersion is unsupported");
            }
            String status = count.path("status").asString();
            boolean notApplicable = "N_A".equals(status);
            if (notApplicable) {
                if (count.size() != 5 || count.has("value") || count.has("evidenceDigest")) {
                    incomplete(path + " must not report a value or digest when N_A");
                }
                requireText(count.path("reason"), path + ".reason");
            } else if ("AVAILABLE".equals(status)) {
                if (count.size() != 6 || count.has("reason") || !count.path("value").isIntegralNumber()
                        || count.path("value").bigIntegerValue().signum() < 0
                        || count.path("value").bigIntegerValue().compareTo(BigInteger.valueOf(Long.MAX_VALUE)) > 0) {
                    incomplete(path + ".value must be a non-negative JSON integer");
                }
                requireDigest(count.path("evidenceDigest"), path + ".evidenceDigest");
                ObjectNode unsigned = (ObjectNode) count.deepCopy();
                unsigned.remove("evidenceDigest");
                String computed = digestService.sha256(canonicalJsonService.canonicalize(unsigned));
                if (!computed.equals(count.path("evidenceDigest").asString())) {
                    incomplete(path + ".evidenceDigest does not match the count evidence");
                }
            } else {
                incomplete(path + ".status must be AVAILABLE or N_A");
            }
            int sourceCount = validateSourceRuns(decision, snapshot, count.path("sourceTestRunIds"),
                    path + ".sourceTestRunIds", true);
            if ((!notApplicable && sourceCount == 0) || ("PASS".equals(decision.decision()) && notApplicable)) {
                incomplete(path + " requires conclusive effect source evidence");
            }
        }
    }

    private void validateCriticalEvidence(DecisionSnapshot decision, JsonNode snapshot) {
        if (!snapshot.has("criticalInvariantAnySuccess")) {
            // Pre-report Decisions remain historical; coverage alone is not a GC report.
            return;
        }
        JsonNode report = snapshot.path("criticalInvariantAnySuccess");
        JsonNode invariants = report.path("invariants");
        if (!report.isObject() || !invariants.isArray() || invariants.size() != GC_IDS.size()) {
            incomplete("criticalInvariantAnySuccess requires four ordered GC entries");
        }
        validateCriticalTrialCoverage(snapshot.path("criticalTrialCoverage"));
        for (int index = 0; index < GC_IDS.size(); index++) {
            JsonNode invariant = invariants.get(index);
            String path = "criticalInvariantAnySuccess.invariants[" + index + "]";
            if (!invariant.isObject()
                    || !GC_IDS.get(index).equals(invariant.path("gcId").asString())
                    || !GC_INVARIANTS.get(index).equals(invariant.path("invariantId").asString())) {
                incomplete(path + " has an invalid GC identity or order");
            }
            String status = invariant.path("status").asString();
            int sourceRunCount = validateSourceRuns(decision, snapshot, invariant.path("sourceRunIds"),
                    path + ".sourceRunIds", true);
            int sourceCaseCount = validateUuidEvidenceIds(invariant.path("sourceCaseRunIds"),
                    path + ".sourceCaseRunIds");
            int sourceOracleCount = validateUuidEvidenceIds(invariant.path("sourceOracleResultIds"),
                    path + ".sourceOracleResultIds");
            int sourceEventCount = validateUuidEvidenceIds(invariant.path("sourceEventIds"),
                    path + ".sourceEventIds");
            if ("N_A".equals(status)) {
                requireText(invariant.path("reason"), path + ".reason");
                if (!invariant.path("anySuccess").isNull()
                        || sourceRunCount != 0 || sourceCaseCount != 0
                        || sourceOracleCount != 0 || sourceEventCount != 0) {
                    incomplete(path + " cannot turn missing GC evidence into a result");
                }
            } else if ("AVAILABLE".equals(status)) {
                if (invariant.path("anySuccess").isBoolean()
                        && !invariant.path("anySuccess").booleanValue()) {
                    incomplete(path + " has no versioned negative proof for false");
                }
                if (!invariant.path("anySuccess").isBoolean()
                        || !invariant.path("anySuccess").booleanValue()
                        || !invariant.path("reason").isNull()
                        || sourceRunCount == 0 || sourceCaseCount == 0
                        || sourceOracleCount == 0 || sourceEventCount == 0) {
                    incomplete(path + " requires a sourced positive report");
                }
                for (JsonNode sourceRunId : invariant.path("sourceRunIds")) {
                    Integer protectedRun = jdbcTemplate.queryForObject("""
                            select count(*) from test_runs
                             where id = ? and mode in ('SEAL_REPLAY', 'HELD_OUT')
                            """, Integer.class, UUID.fromString(sourceRunId.asString()));
                    if (protectedRun == null || protectedRun != 1) {
                        incomplete(path + " requires a protected source Run");
                    }
                }
            } else {
                incomplete(path + ".status must be AVAILABLE or N_A");
            }
        }
    }

    private void validateCriticalTrialCoverage(JsonNode coverage) {
        if (!coverage.isObject() || !coverage.path("complete").isBoolean()
                || !coverage.path("requiredCategoriesPresent").isBoolean()
                || !coverage.path("cases").isArray()) {
            incomplete("criticalTrialCoverage requires completion and case evidence");
        }
        if (coverage.path("complete").booleanValue()
                && !coverage.path("requiredCategoriesPresent").booleanValue()) {
            incomplete("criticalTrialCoverage cannot be complete without required categories");
        }
        Set<UUID> uniqueCases = new HashSet<>();
        for (JsonNode item : coverage.path("cases")) {
            if (!item.isObject()) {
                incomplete("criticalTrialCoverage.cases entries must be objects");
            }
            requireUuid(item.path("testCaseId"), "criticalTrialCoverage.cases.testCaseId");
            if (!uniqueCases.add(UUID.fromString(item.path("testCaseId").asString()))) {
                incomplete("criticalTrialCoverage.cases contains duplicate TestCases");
            }
            requireText(item.path("category"), "criticalTrialCoverage.cases.category");
            requireText(item.path("partition"), "criticalTrialCoverage.cases.partition");
            if (!item.path("mode").isNull()) {
                requireText(item.path("mode"), "criticalTrialCoverage.cases.mode");
            }
            JsonNode required = item.path("requiredTrials");
            JsonNode conclusive = item.path("conclusiveTrials");
            if ((!required.isNull() && (!required.isIntegralNumber()
                    || required.bigIntegerValue().signum() <= 0))
                    || !conclusive.isIntegralNumber() || conclusive.bigIntegerValue().signum() < 0
                    || !item.path("complete").isBoolean()) {
                incomplete("criticalTrialCoverage.cases has invalid trial counts or completion");
            }
            if (item.path("complete").booleanValue()) {
                if (required.isNull() || conclusive.bigIntegerValue().compareTo(required.bigIntegerValue()) < 0
                        || !item.path("reason").isNull()) {
                    incomplete("criticalTrialCoverage.cases complete entry lacks conclusive trials");
                }
            } else {
                requireText(item.path("reason"), "criticalTrialCoverage.cases.reason");
            }
        }
    }

    private int validateUuidEvidenceIds(JsonNode ids, String field) {
        if (!ids.isArray()) {
            incomplete(field + " must be an array");
        }
        Set<UUID> unique = new HashSet<>();
        for (JsonNode id : ids) {
            requireUuid(id, field);
            if (!unique.add(UUID.fromString(id.asString()))) {
                incomplete(field + " must not contain duplicate IDs");
            }
        }
        return unique.size();
    }

    private int validateSourceRuns(
            DecisionSnapshot decision,
            JsonNode snapshot,
            JsonNode sourceIds,
            String field
    ) {
        return validateSourceRuns(decision, snapshot, sourceIds, field, RunSourceScope.COMPLETED);
    }

    private int validateSourceRuns(
            DecisionSnapshot decision,
            JsonNode snapshot,
            JsonNode sourceIds,
            String field,
            boolean effectSource
    ) {
        return validateSourceRuns(decision, snapshot, sourceIds, field,
                effectSource ? RunSourceScope.ATTACK_EFFECT : RunSourceScope.COMPLETED);
    }

    private int validateSourceRuns(
            DecisionSnapshot decision,
            JsonNode snapshot,
            JsonNode sourceIds,
            String field,
            RunSourceScope scope
    ) {
        if (!sourceIds.isArray()) {
            incomplete(field + " must be an array");
        }
        Set<UUID> unique = new HashSet<>();
        for (JsonNode sourceId : sourceIds) {
            requireUuid(sourceId, field);
            UUID runId = UUID.fromString(sourceId.asString());
            if (!unique.add(runId)) {
                incomplete(field + " must not contain duplicate Run IDs");
            }
            String sourceScope = switch (scope) {
                case COMPLETED -> " and run.status = 'COMPLETED'";
                case ATTACK_EFFECT -> """
                           and run.status in ('COMPLETED', 'FAILED')
                           and exists (
                               select 1 from test_case_runs trial
                               join test_cases test_case on test_case.id = trial.test_case_id
                               where trial.test_run_id = run.id and test_case.suite_id = run.suite_id
                                 and test_case.case_type = 'ATTACK'
                           )
                        """;
                case SCHEDULED -> """
                           and run.status in ('QUEUED', 'PREPARING', 'RUNNING', 'CANCELLING',
                                              'COMPLETED', 'FAILED', 'CANCELLED')
                        """;
            };
            Integer matches = jdbcTemplate.queryForObject("""
                    select count(*) from test_runs run
                     where run.id = ? and run.release_id = ? and run.suite_id = ?
                       and run.fixture_version = ? and run.fixture_digest = ?
                       and run.agent_artifact_fingerprint = ? and run.release_fingerprint = ?
                    """ + sourceScope, Integer.class,
                    runId,
                    decision.releaseId(),
                    UUID.fromString(snapshot.at("/testSuite/id").asString()),
                    snapshot.at("/sandbox/fixtureVersion").asString(),
                    snapshot.at("/sandbox/fixtureDigest").asString(),
                    snapshot.at("/release/agentArtifactFingerprint").asString(),
                    snapshot.at("/release/fingerprint").asString()
            );
            if (matches == null || matches != 1) {
                incomplete(field + " contains a Run outside this Release");
            }
        }
        return unique.size();
    }

    private void validateFraction(JsonNode value, String field) {
        BigInteger numerator = fractionInteger(value.path("numerator"), field + ".numerator");
        BigInteger denominator = fractionInteger(value.path("denominator"), field + ".denominator");
        if (numerator.signum() < 0 || denominator.signum() <= 0 || numerator.compareTo(denominator) > 0) {
            incomplete(field + " requires 0 <= numerator <= denominator and denominator > 0");
        }
    }

    private BigInteger fractionInteger(JsonNode value, String field) {
        if (value.isIntegralNumber()) {
            return value.bigIntegerValue();
        }
        if (value.isString() && value.asString().matches("0|[1-9][0-9]*")) {
            return new BigInteger(value.asString());
        }
        incomplete(field + " must be a non-negative integer");
        return BigInteger.ZERO;
    }

    private Invalidation findInvalidation(UUID decisionId) {
        List<Invalidation> rows = jdbcTemplate.query("""
                select reasons_json::text, invalidated_by, invalidated_at
                  from decision_invalidations
                 where release_decision_id = ?
                """, (resultSet, rowNumber) -> new Invalidation(
                        parseJson(resultSet.getString("reasons_json")),
                        resultSet.getString("invalidated_by"),
                        resultSet.getTimestamp("invalidated_at").toInstant()
                ), decisionId);
        return rows.isEmpty() ? null : rows.getFirst();
    }

    private AttestationDto.View view(StoredAttestation stored, Invalidation invalidation) {
        JsonNode invalidationDocument = objectMapper.nullNode();
        if (invalidation != null) {
            ObjectNode value = objectMapper.createObjectNode();
            value.set("reasons", invalidation.reasons());
            value.put("invalidatedBy", invalidation.invalidatedBy());
            value.put("invalidatedAt", invalidation.invalidatedAt().toString());
            invalidationDocument = value;
        }
        return new AttestationDto.View(
                stored.id(),
                stored.decisionId(),
                stored.document().deepCopy(),
                stored.documentHash(),
                stored.generatedAt(),
                stored.disclaimerVersion(),
                invalidation != null,
                invalidationDocument
        );
    }

    private String renderHtml(JsonNode document, String documentHash) {
        String pretty;
        try {
            pretty = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(document);
        } catch (Exception exception) {
            throw new IllegalStateException("Attestation HTML serialization failed", exception);
        }
        String decision = HtmlUtils.htmlEscape(document.at("/decision/value").asString());
        String release = HtmlUtils.htmlEscape(document.at("/release/id").asString());
        return """
                <!doctype html>
                <html lang="ko">
                <head>
                  <meta charset="utf-8">
                  <meta name="viewport" content="width=device-width, initial-scale=1">
                  <title>FINSEC SEAL Internal Release Attestation</title>
                  <style>
                    body{font-family:system-ui,sans-serif;max-width:1100px;margin:0 auto;padding:32px;color:#172033}
                    .notice{border:2px solid #8a5b00;background:#fff8df;padding:16px;border-radius:10px}
                    .meta{display:grid;grid-template-columns:160px 1fr;gap:8px;margin:24px 0}
                    pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f6fa;padding:20px;border-radius:10px}
                    footer{margin-top:28px;border-top:1px solid #ccd3df;padding-top:16px}
                  </style>
                </head>
                <body>
                  <div class="notice"><strong>Internal assessment — not an official certification</strong><br>
                    %s<br>%s
                  </div>
                  <h1>FINSEC SEAL Internal Release Attestation</h1>
                  <div class="meta"><strong>Release</strong><span>%s</span>
                    <strong>Decision</strong><span>%s</span>
                    <strong>Document hash</strong><span>%s</span></div>
                  <pre>%s</pre>
                  <footer>%s<br>%s</footer>
                </body>
                </html>
                """.formatted(
                HtmlUtils.htmlEscape(DISCLAIMER_KO),
                HtmlUtils.htmlEscape(DISCLAIMER_EN),
                release,
                decision,
                HtmlUtils.htmlEscape(documentHash),
                HtmlUtils.htmlEscape(pretty),
                HtmlUtils.htmlEscape(DISCLAIMER_KO),
                HtmlUtils.htmlEscape(DISCLAIMER_EN)
        );
    }

    private String renderStaleHtml(String html, JsonNode invalidation) {
        String banner = "<aside class=\"notice\"><strong>STALE / NEEDS_REVALIDATION</strong><br>"
                + HtmlUtils.htmlEscape(invalidation.toString()) + "</aside>";
        return html.replace("<body>", "<body>" + banner);
    }

    private void requireObject(JsonNode root, String field) {
        if (!root.path(field).isObject()) {
            incomplete("Decision input snapshot requires object field " + field);
        }
    }

    private void requireArray(JsonNode root, String field) {
        if (!root.path(field).isArray()) {
            incomplete("Decision input snapshot requires array field " + field);
        }
    }

    private void requireDigest(JsonNode value, String field) {
        if (!value.isString() || !DIGEST.matcher(value.asString()).matches()) {
            incomplete(field + " must be a sha256 digest");
        }
    }

    private void requireText(JsonNode value, String field) {
        if (!value.isString() || value.asString().isBlank()) {
            incomplete(field + " must be a non-blank string");
        }
    }

    private void requireUuid(JsonNode value, String field) {
        requireText(value, field);
        try {
            UUID.fromString(value.asString());
        } catch (IllegalArgumentException exception) {
            incomplete(field + " must be a UUID");
        }
    }

    private void copy(ObjectNode target, JsonNode source, String field) {
        target.set(field, source.path(field).deepCopy());
    }

    private String normalizeActor(String actorId) {
        if (actorId == null || actorId.isBlank()) {
            return "system:attestation-builder";
        }
        if (actorId.length() > 120) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "X-Actor-Id exceeds 120 characters");
        }
        return actorId;
    }

    private String json(JsonNode value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception exception) {
            throw new IllegalArgumentException("Attestation JSON serialization failed", exception);
        }
    }

    private JsonNode parseJson(String value) {
        try {
            return objectMapper.readTree(value);
        } catch (Exception exception) {
            throw new IllegalStateException("Stored Attestation JSON is invalid", exception);
        }
    }

    private void incomplete(String message) {
        throw new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, message);
    }

    private enum RunSourceScope {
        COMPLETED,
        ATTACK_EFFECT,
        SCHEDULED
    }

    private record DecisionSnapshot(
            UUID id,
            UUID releaseId,
            String decision,
            String gatePolicyVersion,
            JsonNode inputSnapshot,
            String inputDigest,
            Instant proposedAt,
            String confirmedBy,
            Instant confirmedAt,
            String releaseVersion,
            String agentFingerprint,
            String releaseFingerprint,
            String safetyContractHash,
            String lifecycleState,
            UUID agentId,
            UUID workspaceId
    ) {
    }

    private record StoredAttestation(
            UUID id,
            UUID decisionId,
            String formatVersion,
            JsonNode document,
            String documentHash,
            String html,
            Instant generatedAt,
            String disclaimerVersion
    ) {
    }

    private record Invalidation(JsonNode reasons, String invalidatedBy, Instant invalidatedAt) {
    }
}
