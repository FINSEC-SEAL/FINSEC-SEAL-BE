package com.finsecseal.attack;

import com.finsecseal.attack.AttackMutationCandidateValidator.TrustedSeed;
import com.finsecseal.attack.AttackMutationCandidateValidator.ValidatedCandidate;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import com.finsecseal.release.EncryptionService;
import com.finsecseal.runtime.ai.ModelTokenUsage;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/** Persists validated FA-01 mutations and freezes their suite as one immutable snapshot. */
@Service
public final class AttackMutationSuitePersistenceService {

    private static final String BUILDING = "BUILDING";
    private static final String READY = "READY";
    private static final String FA01 = "FA-01";
    private static final String DOCUMENT_CONTENT = "DOCUMENT_CONTENT";

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final AttackSeedCatalog seedCatalog;
    private final AttackVariantFactory variantFactory;
    private final AttackMutationGenerationService generationService;
    private final EncryptionService encryptionService;
    private final CanonicalJsonService canonicalJsonService;
    private final DigestService digestService;
    private final TransactionTemplate transaction;

    public AttackMutationSuitePersistenceService(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            AttackSeedCatalog seedCatalog,
            AttackVariantFactory variantFactory,
            AttackMutationGenerationService generationService,
            EncryptionService encryptionService,
            CanonicalJsonService canonicalJsonService,
            DigestService digestService,
            PlatformTransactionManager transactions
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.seedCatalog = seedCatalog;
        this.variantFactory = variantFactory;
        this.generationService = generationService;
        this.encryptionService = encryptionService;
        this.canonicalJsonService = canonicalJsonService;
        this.digestService = digestService;
        this.transaction = new TransactionTemplate(transactions);
    }

    public Result generateAndFreeze(UUID suiteId, UUID parentSeedId, int mutationCount) {
        if (suiteId == null || parentSeedId == null || mutationCount < 1
                || mutationCount > AttackMutationCandidateValidator.MAX_BATCH_SIZE) {
            throw new BusinessException(
                    ErrorCode.VALIDATION_ERROR,
                    "Suite, parent seed, and a mutation count between 1 and 20 are required"
            );
        }

        Snapshot beforeGeneration = requireSnapshot(suiteId, parentSeedId, false);
        TrustedSeed trustedSeed = validateTrustedSeed(beforeGeneration.seed());

        // Provider I/O must never retain a database transaction or suite row lock.
        AttackMutationGenerationService.GenerationResult generation =
                generationService.generate(trustedSeed, mutationCount);

        Result persisted = transaction.execute(status -> persistAndFreeze(beforeGeneration, generation, mutationCount));
        if (persisted == null) {
            throw new IllegalStateException("Mutation suite transaction did not return a result");
        }
        return persisted;
    }

    private Result persistAndFreeze(
            Snapshot beforeGeneration,
            AttackMutationGenerationService.GenerationResult generation,
            int requestedCount
    ) {
        Snapshot locked = requireSnapshot(beforeGeneration.suite().id(), beforeGeneration.seed().id(), true);
        if (!beforeGeneration.equals(locked)) {
            throw new BusinessException(
                    ErrorCode.RESOURCE_CONFLICT,
                    "TestSuite or parent seed changed while mutations were generated"
            );
        }

        ObjectNode generationConfig = requireObject(locked.suite().generationConfigJson(), "generation config");
        if (generationConfig.has("mutationGeneration")) {
            throw new BusinessException(
                    ErrorCode.INVALID_STATE_TRANSITION,
                    "TestSuite already contains mutation generation metadata"
            );
        }
        generationConfig.set(
                "mutationGeneration",
                mutationMetadata(generation, requestedCount)
        );

        List<UUID> created = new ArrayList<>();
        if (!generation.generationDegraded()) {
            AttackSeed curated = seedCatalog.requireSeed(FA01);
            for (ValidatedCandidate candidate : generation.candidates()) {
                UUID caseId = UUID.randomUUID();
                insertMutationCase(locked.suite().id(), locked.seed(), curated, candidate, caseId);
                created.add(caseId);
            }
        }

        String suiteHash = calculateSuiteHash(locked.suite(), generationConfig);
        int changed = jdbcTemplate.update("""
                update test_suites
                   set generation_config_json = ?::jsonb,
                       suite_hash = ?, status = ?, updated_at = now()
                 where id = ? and status = ?
                """, json(generationConfig), suiteHash, READY, locked.suite().id(), BUILDING);
        if (changed != 1) {
            throw new BusinessException(ErrorCode.RESOURCE_CONFLICT, "TestSuite could not be frozen");
        }
        return new Result(
                locked.suite().id(),
                List.copyOf(created),
                suiteHash,
                generation.generationDegraded(),
                generation.provider(),
                generation.model(),
                generation.tokenUsage(),
                generation.degradationCode()
        );
    }

    private Snapshot requireSnapshot(UUID suiteId, UUID parentSeedId, boolean lockSuite) {
        String lock = lockSuite ? " for update of suite" : "";
        List<Snapshot> snapshots = jdbcTemplate.query("""
                select suite.id suite_id, suite.workspace_id, suite.suite_key, suite.version,
                       suite.fixture_version, suite.generation_config_json::text generation_config_json,
                       suite.suite_hash, suite.status,
                       seed.id seed_id, seed.case_key, seed.case_type, seed.partition_name,
                       seed.category, seed.severity, seed.delivery_channel, seed.target_tool,
                       seed.attack_goal, seed.payload_encrypted, seed.payload_hash,
                       seed.preconditions_json::text preconditions_json,
                       seed.expected_invariant, seed.oracle_type, seed.generation_source,
                       seed.parent_seed_id, seed.hidden_from_patch_generator,
                       seed.expected_result_json::text expected_result_json,
                       seed.trial_policy_json::text trial_policy_json
                  from test_suites suite
                  join test_cases seed on seed.suite_id = suite.id and seed.id = ?
                 where suite.id = ?
                """ + lock, (resultSet, rowNumber) -> new Snapshot(
                new SuiteSnapshot(
                        resultSet.getObject("suite_id", UUID.class),
                        resultSet.getObject("workspace_id", UUID.class),
                        resultSet.getString("suite_key"),
                        resultSet.getString("version"),
                        resultSet.getString("fixture_version"),
                        resultSet.getString("generation_config_json"),
                        resultSet.getString("suite_hash"),
                        resultSet.getString("status")
                ),
                new SeedSnapshot(
                        resultSet.getObject("seed_id", UUID.class),
                        resultSet.getString("case_key"),
                        resultSet.getString("case_type"),
                        resultSet.getString("partition_name"),
                        resultSet.getString("category"),
                        resultSet.getString("severity"),
                        resultSet.getString("delivery_channel"),
                        resultSet.getString("target_tool"),
                        resultSet.getString("attack_goal"),
                        resultSet.getString("payload_encrypted"),
                        resultSet.getString("payload_hash"),
                        resultSet.getString("preconditions_json"),
                        resultSet.getString("expected_invariant"),
                        resultSet.getString("oracle_type"),
                        resultSet.getString("generation_source"),
                        resultSet.getObject("parent_seed_id", UUID.class),
                        resultSet.getBoolean("hidden_from_patch_generator"),
                        resultSet.getString("expected_result_json"),
                        resultSet.getString("trial_policy_json")
                )
        ), parentSeedId, suiteId);
        if (snapshots.isEmpty()) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "TestSuite or parent seed not found");
        }
        Snapshot snapshot = snapshots.getFirst();
        if (!BUILDING.equals(snapshot.suite().status())) {
            throw new BusinessException(ErrorCode.INVALID_STATE_TRANSITION, "TestSuite must be BUILDING");
        }
        return snapshot;
    }

    private TrustedSeed validateTrustedSeed(SeedSnapshot stored) {
        if (!"ATTACK".equals(stored.caseType())
                || !"SEED".equals(stored.partitionName())
                || !FA01.equals(stored.category())
                || !DOCUMENT_CONTENT.equals(stored.deliveryChannel())
                || stored.parentSeedId() != null
                || stored.hiddenFromPatchGenerator()
                || stored.payloadEncrypted() == null) {
            throw incomplete("Parent TestCase is not an eligible curated FA-01 document seed");
        }

        AttackSeed curated = seedCatalog.requireSeed(FA01);
        if (!Objects.equals(curated.severity(), stored.severity())
                || !Objects.equals(curated.targetTool(), stored.targetTool())
                || !Objects.equals(curated.invariantId(), stored.expectedInvariant())
                || !Objects.equals(curated.oracleType(), stored.oracleType())
                || !Objects.equals(variantFactory.fromSeed(curated).variantHash(), stored.payloadHash())) {
            throw incomplete("Stored seed identity or payload hash does not match the curated attack template");
        }

        String payload;
        try {
            payload = encryptionService.decrypt(stored.payloadEncrypted());
        } catch (RuntimeException exception) {
            throw incomplete("Stored seed payload cannot be decrypted");
        }
        String curatedPayload = curated.toolArguments().path("documents").path(0).path("content").asString(null);
        if (curatedPayload == null || !curatedPayload.equals(payload)) {
            throw incomplete("Stored seed payload does not match the curated attack template");
        }
        return new TrustedSeed(
                stored.id(),
                stored.category(),
                stored.severity(),
                stored.targetTool(),
                stored.expectedInvariant(),
                stored.oracleType(),
                stored.deliveryChannel(),
                payload
        );
    }

    private void insertMutationCase(
            UUID suiteId,
            SeedSnapshot parent,
            AttackSeed curated,
            ValidatedCandidate candidate,
            UUID caseId
    ) {
        ObjectNode preconditions = requireObject(parent.preconditionsJson(), "seed preconditions");
        preconditions.put("mutationInsertionLocation", candidate.insertionLocation());
        preconditions.put("mutationPayloadHash", candidate.normalizedPayloadHash());
        AttackVariant variant = variantFactory.fromDocumentMutation(curated, candidate);
        jdbcTemplate.update("""
                insert into test_cases
                    (id, suite_id, case_key, case_type, partition_name, category, severity,
                     delivery_channel, target_tool, attack_goal, payload_encrypted, payload_hash,
                     preconditions_json, expected_invariant, oracle_type, generation_source,
                     parent_seed_id, hidden_from_patch_generator, expected_result_json,
                     trial_policy_json)
                values (?, ?, ?, 'ATTACK', 'MUTATION', ?, ?, ?, ?, ?, ?, ?, ?::jsonb,
                        ?, ?, 'AI_MUTATION', ?, false, ?::jsonb, ?::jsonb)
                """,
                caseId,
                suiteId,
                mutationCaseKey(parent.caseKey(), candidate.normalizedPayloadHash()),
                parent.category(),
                parent.severity(),
                parent.deliveryChannel(),
                parent.targetTool(),
                parent.attackGoal(),
                encryptionService.encrypt(candidate.payload()),
                variant.variantHash(),
                json(preconditions),
                parent.expectedInvariant(),
                parent.oracleType(),
                parent.id(),
                parent.expectedResultJson(),
                parent.trialPolicyJson()
        );
    }

    private ObjectNode mutationMetadata(
            AttackMutationGenerationService.GenerationResult generation,
            int requestedCount
    ) {
        ObjectNode metadata = objectMapper.createObjectNode();
        metadata.put("schemaVersion", "1.0");
        metadata.put("requestedCount", requestedCount);
        metadata.put("acceptedCount", generation.candidates().size());
        metadata.put("generationDegraded", generation.generationDegraded());
        if (generation.provider() != null) {
            metadata.put("provider", generation.provider());
        }
        if (generation.model() != null) {
            metadata.put("model", generation.model());
        }
        if (generation.degradationCode() != null) {
            metadata.put("degradationCode", generation.degradationCode().name());
        }
        ModelTokenUsage usage = generation.tokenUsage();
        ObjectNode tokenUsage = metadata.putObject("tokenUsage");
        tokenUsage.put("promptTokens", usage.promptTokens());
        tokenUsage.put("completionTokens", usage.completionTokens());
        tokenUsage.put("totalTokens", usage.totalTokens());
        return metadata;
    }

    private String calculateSuiteHash(SuiteSnapshot suite, ObjectNode generationConfig) {
        ObjectNode snapshot = objectMapper.createObjectNode();
        snapshot.put("schemaVersion", "1.0");
        snapshot.put("suiteKey", suite.suiteKey());
        snapshot.put("version", suite.version());
        snapshot.put("fixtureVersion", suite.fixtureVersion());
        snapshot.set("generationConfig", generationConfig.deepCopy());
        ArrayNode cases = snapshot.putArray("cases");

        jdbcTemplate.query("""
                select test_case.case_key, test_case.case_type, test_case.partition_name,
                       test_case.category, test_case.severity, test_case.delivery_channel,
                       test_case.target_tool, test_case.attack_goal, test_case.payload_hash,
                       test_case.preconditions_json::text preconditions_json,
                       test_case.expected_invariant, test_case.oracle_type,
                       test_case.generation_source, parent.case_key parent_seed_case_key,
                       test_case.hidden_from_patch_generator,
                       test_case.expected_result_json::text expected_result_json,
                       test_case.trial_policy_json::text trial_policy_json
                  from test_cases test_case
                  left join test_cases parent on parent.id = test_case.parent_seed_id
                 where test_case.suite_id = ?
                 order by test_case.case_key
                """, resultSet -> {
            ObjectNode value = cases.addObject();
            value.put("caseKey", resultSet.getString("case_key"));
            value.put("caseType", resultSet.getString("case_type"));
            value.put("partition", resultSet.getString("partition_name"));
            value.put("category", resultSet.getString("category"));
            value.put("severity", resultSet.getString("severity"));
            value.put("deliveryChannel", resultSet.getString("delivery_channel"));
            putNullable(value, "targetTool", resultSet.getString("target_tool"));
            putNullable(value, "attackGoal", resultSet.getString("attack_goal"));
            value.put("payloadHash", resultSet.getString("payload_hash"));
            value.set("preconditions", parseJson(resultSet.getString("preconditions_json"), "case preconditions"));
            value.put("expectedInvariant", resultSet.getString("expected_invariant"));
            value.put("oracleType", resultSet.getString("oracle_type"));
            value.put("generationSource", resultSet.getString("generation_source"));
            putNullable(value, "parentSeedCaseKey", resultSet.getString("parent_seed_case_key"));
            value.put("hiddenFromPatchGenerator", resultSet.getBoolean("hidden_from_patch_generator"));
            value.set("expectedResult", parseJson(resultSet.getString("expected_result_json"), "expected result"));
            value.set("trialPolicy", parseJson(resultSet.getString("trial_policy_json"), "trial policy"));
        }, suite.id());
        return digestService.sha256(canonicalJsonService.canonicalize(snapshot));
    }

    private ObjectNode requireObject(String value, String label) {
        JsonNode parsed = parseJson(value, label);
        if (!(parsed instanceof ObjectNode object)) {
            throw incomplete("Stored " + label + " must be a JSON object");
        }
        return object.deepCopy();
    }

    private JsonNode parseJson(String value, String label) {
        try {
            return objectMapper.readTree(value);
        } catch (RuntimeException exception) {
            throw incomplete("Stored " + label + " is invalid JSON");
        }
    }

    private String json(JsonNode value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (RuntimeException exception) {
            throw new IllegalArgumentException("JSON serialization failed", exception);
        }
    }

    private void putNullable(ObjectNode object, String field, String value) {
        if (value == null) {
            object.putNull(field);
        } else {
            object.put(field, value);
        }
    }

    private String mutationCaseKey(String parentKey, String normalizedPayloadHash) {
        String suffix = normalizedPayloadHash.startsWith("sha256:")
                ? normalizedPayloadHash.substring(7, 19)
                : normalizedPayloadHash.substring(0, Math.min(12, normalizedPayloadHash.length()));
        int maxParentLength = 100 - 3 - suffix.length();
        String boundedParent = parentKey.substring(0, Math.min(parentKey.length(), maxParentLength));
        return boundedParent + "-M-" + suffix;
    }

    private BusinessException incomplete(String message) {
        return new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, message);
    }

    public record Result(
            UUID suiteId,
            List<UUID> createdCaseIds,
            String suiteHash,
            boolean generationDegraded,
            String provider,
            String model,
            ModelTokenUsage tokenUsage,
            AttackMutationGenerationService.DegradationCode degradationCode
    ) {
        public Result {
            createdCaseIds = List.copyOf(createdCaseIds);
        }
    }

    private record Snapshot(SuiteSnapshot suite, SeedSnapshot seed) {
    }

    private record SuiteSnapshot(
            UUID id,
            UUID workspaceId,
            String suiteKey,
            String version,
            String fixtureVersion,
            String generationConfigJson,
            String suiteHash,
            String status
    ) {
    }

    private record SeedSnapshot(
            UUID id,
            String caseKey,
            String caseType,
            String partitionName,
            String category,
            String severity,
            String deliveryChannel,
            String targetTool,
            String attackGoal,
            String payloadEncrypted,
            String payloadHash,
            String preconditionsJson,
            String expectedInvariant,
            String oracleType,
            String generationSource,
            UUID parentSeedId,
            boolean hiddenFromPatchGenerator,
            String expectedResultJson,
            String trialPolicyJson
    ) {
    }
}
