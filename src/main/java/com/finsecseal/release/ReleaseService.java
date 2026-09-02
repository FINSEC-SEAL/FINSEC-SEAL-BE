package com.finsecseal.release;

import com.finsecseal.agent.AgentEntity;
import com.finsecseal.agent.AgentService;
import com.finsecseal.audit.AuditService;
import com.finsecseal.audit.PromptAccessAuditService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ArtifactType;
import com.finsecseal.common.domain.ReleaseLifecycleState;
import com.finsecseal.common.domain.Sensitivity;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

@Service
@Transactional(readOnly = true)
public class ReleaseService {

    private static final Map<String, List<String>> COMPONENT_POINTERS = Map.ofEntries(
            Map.entry("businessPurposeHash", List.of("/businessPurpose")),
            Map.entry("modelHash", List.of("/model")),
            Map.entry("systemPromptHash", List.of("/systemPrompt/text")),
            Map.entry("toolSetHash", List.of("/tools")),
            Map.entry("ragConfigHash", List.of("/ragSources")),
            Map.entry("networkRequirementsHash", List.of("/networkRequirements")),
            Map.entry("workflowHash", List.of("/businessWorkflow")),
            Map.entry("humanBoundaryHash", List.of("/humanApprovalBoundaries")),
            Map.entry("runtimeContextHash", List.of("/runtimeContextRequirements"))
    );

    private final AgentService agentService;
    private final AgentReleaseRepository releaseRepository;
    private final ReleaseArtifactRepository artifactRepository;
    private final ManifestValidationService validationService;
    private final FingerprintService fingerprintService;
    private final EncryptionService encryptionService;
    private final DigestService digestService;
    private final ObjectMapper objectMapper;
    private final ReleaseCatalogWriter catalogWriter;
    private final DecisionInvalidationWriter invalidationWriter;
    private final AuditService auditService;
    private final PromptAccessAuditService promptAccessAuditService;
    private final ReleaseIntegrityVerifier integrityVerifier;

    public ReleaseService(
            AgentService agentService,
            AgentReleaseRepository releaseRepository,
            ReleaseArtifactRepository artifactRepository,
            ManifestValidationService validationService,
            FingerprintService fingerprintService,
            EncryptionService encryptionService,
            DigestService digestService,
            ObjectMapper objectMapper,
            ReleaseCatalogWriter catalogWriter,
            DecisionInvalidationWriter invalidationWriter,
            AuditService auditService,
            PromptAccessAuditService promptAccessAuditService,
            ReleaseIntegrityVerifier integrityVerifier
    ) {
        this.agentService = agentService;
        this.releaseRepository = releaseRepository;
        this.artifactRepository = artifactRepository;
        this.validationService = validationService;
        this.fingerprintService = fingerprintService;
        this.encryptionService = encryptionService;
        this.digestService = digestService;
        this.objectMapper = objectMapper;
        this.catalogWriter = catalogWriter;
        this.invalidationWriter = invalidationWriter;
        this.auditService = auditService;
        this.promptAccessAuditService = promptAccessAuditService;
        this.integrityVerifier = integrityVerifier;
    }

    @Transactional
    public ReleaseDto.Response create(UUID agentId, JsonNode requestManifest) {
        return create(agentId, requestManifest, "demo-user");
    }

    @Transactional
    public ReleaseDto.Response create(UUID agentId, JsonNode requestManifest, String actorId) {
        AgentEntity agent = agentService.getRequiredForUpdate(agentId);
        agentService.requireActive(agent);
        JsonNode manifest = requireManifest(requestManifest);
        ManifestValidationService.ValidationResult validation = validationService.validate(manifest);
        requireValid(validation);
        if (!agent.getAgentKey().equals(manifest.at("/agent/id").asString(""))) {
            throw new BusinessException(ErrorCode.MANIFEST_INVALID, "Manifest agent.id must match Agent agentKey");
        }

        FingerprintService.Result fingerprint;
        try {
            fingerprint = fingerprintService.fingerprint(manifest, null);
        } catch (IllegalArgumentException exception) {
            throw new BusinessException(
                    ErrorCode.MANIFEST_INVALID,
                    "Manifest canonicalization failed: " + exception.getMessage()
            );
        }
        JsonNode storedManifest = redactPrompt(fingerprint.normalizedManifest());
        AgentReleaseEntity release = new AgentReleaseEntity(
                agentId,
                manifest.at("/release/version").asString(),
                manifest.at("/businessPurpose/code").asString(),
                manifest.path("schemaVersion").asString(),
                storedManifest,
                fingerprint.agentArtifactFingerprint(),
                fingerprint.releaseFingerprint()
        );
        try {
            releaseRepository.saveAndFlush(release);
            artifactRepository.saveAll(buildArtifacts(release.getId(), fingerprint.normalizedManifest()));
            artifactRepository.flush();
            catalogWriter.write(agent.getWorkspaceId(), release.getId(), fingerprint.normalizedManifest());
            ObjectNode auditMetadata = releaseStateDocument(release);
            auditService.append(
                    agent.getWorkspaceId(), normalizeActor(actorId), "AGENT_RELEASE_CREATED",
                    "AGENT_RELEASE", release.getId(), null, release.getReleaseFingerprint(), auditMetadata
            );
        } catch (DataIntegrityViolationException exception) {
            throw new BusinessException(ErrorCode.RESOURCE_CONFLICT, "Release version or fingerprint already exists");
        }
        return ReleaseDto.Response.from(release);
    }

    public ReleaseDto.Response find(UUID releaseId) {
        return ReleaseDto.Response.from(getRequired(releaseId));
    }

    public List<ReleaseDto.Response> findByAgent(UUID agentId) {
        agentService.getRequired(agentId);
        return releaseRepository.findAllByAgentIdOrderByCreatedAtDesc(agentId).stream()
                .map(ReleaseDto.Response::from)
                .toList();
    }

    @Transactional
    public ReleaseDto.ValidationResponse validate(UUID releaseId) {
        return validate(releaseId, "system:release-integrity");
    }

    @Transactional
    public ReleaseDto.ValidationResponse validate(UUID releaseId, String actorId) {
        AgentReleaseEntity release = getRequired(releaseId);
        if (release.getLifecycleState() != ReleaseLifecycleState.DRAFT) {
            throw new BusinessException(ErrorCode.INVALID_STATE_TRANSITION, "Only DRAFT Release can be validated");
        }
        JsonNode manifest = loadFullManifest(release, actorId, "MANIFEST_VALIDATION");
        ManifestValidationService.ValidationResult result = validationService.validate(manifest);
        if (result.valid()) {
            AgentEntity agent = agentService.getRequired(release.getAgentId());
            integrityVerifier.verify(agent.getWorkspaceId(), release.getId(), manifest);
        }
        return new ReleaseDto.ValidationResponse(result.valid(), result.issues());
    }

    @Transactional
    public ReleaseDto.Response analyze(UUID releaseId) {
        return analyze(releaseId, "system:release-integrity");
    }

    @Transactional
    public ReleaseDto.Response analyze(UUID releaseId, String actorId) {
        AgentReleaseEntity release = getRequiredForUpdate(releaseId);
        if (release.getLifecycleState() == ReleaseLifecycleState.ANALYZED) {
            return ReleaseDto.Response.from(release);
        }
        if (release.getLifecycleState() != ReleaseLifecycleState.DRAFT) {
            throw new BusinessException(ErrorCode.INVALID_STATE_TRANSITION, "Only DRAFT Release can be analyzed");
        }
        String beforeDigest = release.getReleaseFingerprint();
        JsonNode manifest = loadFullManifest(release, actorId, "RELEASE_ANALYSIS");
        requireValid(validationService.validate(manifest));
        AgentEntity agent = agentService.getRequired(release.getAgentId());
        integrityVerifier.verify(agent.getWorkspaceId(), release.getId(), manifest);
        FingerprintService.Result recomputed = fingerprintService.fingerprint(manifest, release.getSafetyContractHash());
        if (!recomputed.agentArtifactFingerprint().equals(release.getAgentArtifactFingerprint())
                || !recomputed.releaseFingerprint().equals(release.getReleaseFingerprint())) {
            throw new BusinessException(ErrorCode.RELEASE_CHANGED, "Stored Release artifacts do not match fingerprints");
        }
        release.transitionTo(ReleaseLifecycleState.ANALYZED);
        auditService.append(
                agent.getWorkspaceId(), normalizeActor(actorId), "AGENT_RELEASE_ANALYZED",
                "AGENT_RELEASE", release.getId(), beforeDigest, release.getReleaseFingerprint(),
                releaseStateDocument(release)
        );
        return ReleaseDto.Response.from(release);
    }

    @Transactional
    public ReleaseDto.FingerprintResponse fingerprint(UUID releaseId) {
        return fingerprint(releaseId, "system:release-integrity");
    }

    @Transactional
    public ReleaseDto.FingerprintResponse fingerprint(UUID releaseId, String actorId) {
        AgentReleaseEntity release = getRequired(releaseId);
        JsonNode manifest = loadFullManifest(release, actorId, "FINGERPRINT_INTEGRITY_CHECK");
        AgentEntity agent = agentService.getRequired(release.getAgentId());
        integrityVerifier.verify(agent.getWorkspaceId(), release.getId(), manifest);
        FingerprintService.Result result = fingerprintService.fingerprint(
                manifest,
                release.getSafetyContractHash()
        );
        if (!result.agentArtifactFingerprint().equals(release.getAgentArtifactFingerprint())
                || !result.releaseFingerprint().equals(release.getReleaseFingerprint())) {
            throw new BusinessException(ErrorCode.RELEASE_CHANGED, "Release fingerprint integrity check failed");
        }
        return new ReleaseDto.FingerprintResponse(
                CanonicalJsonService.VERSION,
                release.getAgentArtifactFingerprint(),
                release.getReleaseFingerprint(),
                release.getSafetyContractHash(),
                result.componentDigests()
        );
    }

    @Transactional
    public ReleaseDto.DiffResponse diff(UUID releaseId, UUID againstId) {
        return diff(releaseId, againstId, "system:release-integrity");
    }

    @Transactional
    public ReleaseDto.DiffResponse diff(UUID releaseId, UUID againstId, String actorId) {
        AgentReleaseEntity release = getRequired(releaseId);
        AgentReleaseEntity against = getRequired(againstId);
        if (!release.getAgentId().equals(against.getAgentId())) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "Release diff requires the same Agent");
        }
        Map<String, String> current = fingerprintService.fingerprint(
                verifiedManifest(release, actorId, "RELEASE_DIFF"), release.getSafetyContractHash()
        ).componentDigests();
        Map<String, String> previous = fingerprintService.fingerprint(
                verifiedManifest(against, actorId, "RELEASE_DIFF"), against.getSafetyContractHash()
        ).componentDigests();
        Set<String> keys = new LinkedHashSet<>(previous.keySet());
        keys.addAll(current.keySet());
        List<ReleaseDto.DiffItem> items = keys.stream()
                .sorted()
                .map(key -> new ReleaseDto.DiffItem(
                        key,
                        COMPONENT_POINTERS.getOrDefault(key, List.of()),
                        previous.get(key),
                        current.get(key),
                        !java.util.Objects.equals(previous.get(key), current.get(key)),
                        java.util.Objects.equals(previous.get(key), current.get(key))
                                ? "No semantic change"
                                : "Canonical digest changed; raw sensitive values are redacted"
                ))
                .toList();
        return new ReleaseDto.DiffResponse(
                againstId,
                releaseId,
                items,
                items.stream().anyMatch(ReleaseDto.DiffItem::changed)
        );
    }

    @Transactional
    public ReleaseDto.Response invalidate(UUID releaseId, JsonNode reason) {
        return invalidate(releaseId, reason, "demo-user");
    }

    @Transactional
    public ReleaseDto.Response invalidate(UUID releaseId, JsonNode reason, String actorId) {
        AgentReleaseEntity release = getRequiredForUpdate(releaseId);
        ObjectNode reasonDocument = objectMapper.createObjectNode();
        reasonDocument.put("schemaVersion", "1.0");
        reasonDocument.set("reason", reason == null ? objectMapper.nullNode() : reason);
        invalidationWriter.invalidateLatest(releaseId, reasonDocument, normalizeActor(actorId));
        ReleaseLifecycleState beforeState = release.getLifecycleState();
        release.invalidate(reasonDocument);
        AgentEntity agent = agentService.getRequired(release.getAgentId());
        ObjectNode metadata = releaseStateDocument(release);
        metadata.put("fromState", beforeState.name());
        auditService.append(
                agent.getWorkspaceId(), normalizeActor(actorId), "AGENT_RELEASE_INVALIDATED",
                "AGENT_RELEASE", releaseId, release.getReleaseFingerprint(), release.getReleaseFingerprint(), metadata
        );
        return ReleaseDto.Response.from(release);
    }

    @Transactional
    public ReleaseDto.Response applySafetyContractHash(UUID releaseId, String contractHash, JsonNode reason) {
        AgentReleaseEntity release = getRequiredForUpdate(releaseId);
        String previousFingerprint = release.getReleaseFingerprint();
        String finalFingerprint = fingerprintService.releaseFingerprint(
                release.getAgentArtifactFingerprint(),
                contractHash
        );
        if (release.getLifecycleState().isTerminalDecision()) {
            ObjectNode reasonDocument = objectMapper.createObjectNode();
            reasonDocument.put("schemaVersion", "1.0");
            reasonDocument.put("reasonCode", "SAFETY_CONTRACT_CHANGED");
            reasonDocument.set("details", reason == null ? objectMapper.nullNode() : reason);
            invalidationWriter.invalidateLatest(releaseId, reasonDocument, "system:contract-approval");
        }
        release.applySafetyContract(contractHash, finalFingerprint, reason);
        AgentEntity agent = agentService.getRequired(release.getAgentId());
        auditService.append(
                agent.getWorkspaceId(), "system:contract-approval", "RELEASE_CONTRACT_FINGERPRINT_APPLIED",
                "AGENT_RELEASE", releaseId, previousFingerprint, finalFingerprint,
                releaseStateDocument(release)
        );
        return ReleaseDto.Response.from(release);
    }

    public AgentReleaseEntity getRequired(UUID id) {
        return releaseRepository.findById(id)
                .orElseThrow(() -> new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "Release not found"));
    }

    private AgentReleaseEntity getRequiredForUpdate(UUID id) {
        return releaseRepository.findByIdForUpdate(id)
                .orElseThrow(() -> new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "Release not found"));
    }

    private JsonNode requireManifest(JsonNode manifest) {
        if (manifest == null) {
            throw new BusinessException(ErrorCode.MANIFEST_INVALID, "Manifest is required");
        }
        return manifest;
    }

    private void requireValid(ManifestValidationService.ValidationResult validation) {
        if (!validation.valid()) {
            String details = validation.issues().stream()
                    .map(issue -> issue.path() + " " + issue.code())
                    .limit(10)
                    .collect(java.util.stream.Collectors.joining(", "));
            throw new BusinessException(ErrorCode.MANIFEST_INVALID, "Manifest validation failed: " + details);
        }
    }

    private JsonNode redactPrompt(JsonNode manifest) {
        ObjectNode copy = (ObjectNode) manifest.deepCopy();
        ObjectNode prompt = (ObjectNode) copy.path("systemPrompt");
        String text = prompt.path("text").asString();
        prompt.put("text", "[ENCRYPTED]");
        prompt.put("storedSha256", digestService.sha256(text));
        return copy;
    }

    private JsonNode loadFullManifest(AgentReleaseEntity release, String actorId, String purpose) {
        ObjectNode manifest = (ObjectNode) release.getManifestJson().deepCopy();
        ReleaseArtifactEntity promptArtifact = artifactRepository
                .findByReleaseIdAndArtifactTypeAndName(release.getId(), ArtifactType.SYSTEM_PROMPT, "system-prompt")
                .orElseThrow(() -> new BusinessException(ErrorCode.RELEASE_CHANGED, "System prompt artifact is missing"));
        ObjectNode prompt = (ObjectNode) manifest.path("systemPrompt");
        prompt.put("text", encryptionService.decrypt(promptArtifact.getEncryptedText()));
        prompt.remove("storedSha256");
        AgentEntity agent = agentService.getRequired(release.getAgentId());
        ObjectNode auditMetadata = objectMapper.createObjectNode();
        auditMetadata.put("schemaVersion", "1.0");
        auditMetadata.put("purpose", purpose);
        auditMetadata.put("artifactType", ArtifactType.SYSTEM_PROMPT.name());
        auditMetadata.put("plaintextReturned", false);
        promptAccessAuditService.appendRollbackSafe(
                agent.getWorkspaceId(),
                normalizeActor(actorId),
                release.getId(),
                promptArtifact.getSha256(),
                auditMetadata
        );
        return manifest;
    }

    private JsonNode verifiedManifest(AgentReleaseEntity release, String actorId, String purpose) {
        JsonNode manifest = loadFullManifest(release, actorId, purpose);
        AgentEntity agent = agentService.getRequired(release.getAgentId());
        integrityVerifier.verify(agent.getWorkspaceId(), release.getId(), manifest);
        return manifest;
    }

    private String normalizeActor(String actorId) {
        if (actorId == null || actorId.isBlank()) {
            return "system:release-integrity";
        }
        if (actorId.length() > 120) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "X-Actor-Id exceeds 120 characters");
        }
        return actorId;
    }

    private ObjectNode releaseStateDocument(AgentReleaseEntity release) {
        ObjectNode state = objectMapper.createObjectNode();
        state.put("schemaVersion", "1.0");
        state.put("version", release.getVersion());
        state.put("lifecycleState", release.getLifecycleState().name());
        state.put("effectiveStatus", release.getEffectiveStatus().name());
        state.put("agentArtifactFingerprint", release.getAgentArtifactFingerprint());
        state.put("releaseFingerprint", release.getReleaseFingerprint());
        if (release.getSafetyContractHash() == null) {
            state.putNull("safetyContractHash");
        } else {
            state.put("safetyContractHash", release.getSafetyContractHash());
        }
        return state;
    }

    private List<ReleaseArtifactEntity> buildArtifacts(UUID releaseId, JsonNode manifest) {
        List<ReleaseArtifactEntity> artifacts = new ArrayList<>();
        artifacts.add(jsonArtifact(releaseId, ArtifactType.MODEL_CONFIG, "model", manifest.path("model")));
        artifacts.add(jsonArtifact(releaseId, ArtifactType.BUSINESS_PURPOSE, "business-purpose", manifest.path("businessPurpose")));
        artifacts.add(jsonArtifact(releaseId, ArtifactType.RAG_CONFIG, "rag-sources", manifest.path("ragSources")));
        artifacts.add(jsonArtifact(releaseId, ArtifactType.BUSINESS_WORKFLOW, "business-workflow", manifest.path("businessWorkflow")));
        artifacts.add(jsonArtifact(releaseId, ArtifactType.HUMAN_BOUNDARY, "human-boundaries", manifest.path("humanApprovalBoundaries")));
        ObjectNode runtime = objectMapper.createObjectNode();
        runtime.set("runtimeContextRequirements", manifest.path("runtimeContextRequirements"));
        runtime.set("networkRequirements", manifest.path("networkRequirements"));
        artifacts.add(jsonArtifact(releaseId, ArtifactType.RUNTIME_CONTEXT, "runtime-context", runtime));

        String prompt = manifest.at("/systemPrompt/text").asString();
        ObjectNode promptMetadata = objectMapper.createObjectNode();
        promptMetadata.put("length", prompt.length());
        promptMetadata.put("sha256", digestService.sha256(prompt));
        artifacts.add(new ReleaseArtifactEntity(
                releaseId,
                ArtifactType.SYSTEM_PROMPT,
                "system-prompt",
                promptMetadata,
                encryptionService.encrypt(prompt),
                digestService.sha256(prompt),
                Sensitivity.SECRET
        ));

        JsonNode tools = manifest.path("tools");
        if (tools instanceof ArrayNode array) {
            array.forEach(tool -> {
                String name = tool.path("name").asString();
                ObjectNode schemas = objectMapper.createObjectNode();
                schemas.set("inputSchema", tool.path("inputSchema"));
                schemas.set("outputSchema", tool.path("outputSchema"));
                schemas.set("metadata", tool.deepCopy());
                schemas.remove("description");
                artifacts.add(jsonArtifact(releaseId, ArtifactType.TOOL_SCHEMA, name, schemas));
                ObjectNode description = objectMapper.createObjectNode();
                description.put("description", tool.path("description").asString());
                artifacts.add(jsonArtifact(releaseId, ArtifactType.TOOL_DESCRIPTION, name, description));
            });
        }
        return artifacts;
    }

    private ReleaseArtifactEntity jsonArtifact(UUID releaseId, ArtifactType type, String name, JsonNode value) {
        JsonNode copy = value.deepCopy();
        return new ReleaseArtifactEntity(
                releaseId,
                type,
                name,
                copy,
                null,
                fingerprintService.hash(copy),
                Sensitivity.NORMAL
        );
    }
}
