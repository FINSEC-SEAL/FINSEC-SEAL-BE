package com.finsecseal.contract;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.finsecseal.contract.ReleaseToolCatalogContractAdapter.SourceBoundCatalog;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ContractVersionSnapshot;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionIdentity;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionState;
import com.finsecseal.contract.SafetyContractPatchOperation.AddConstraint;
import com.finsecseal.contract.SafetyContractPatchOperation.ConstraintKind;
import com.finsecseal.contract.SafetyContractPatchOperation.DenyTool;
import com.finsecseal.contract.SafetyContractPatchOperation.LimitKind;
import com.finsecseal.contract.SafetyContractPatchOperation.LowerLimit;
import com.finsecseal.contract.SafetyContractPatchOperation.NarrowSet;
import com.finsecseal.contract.SafetyContractPatchOperation.SetHumanOnly;
import com.finsecseal.contract.SafetyContractPatchOperation.SetKind;
import com.finsecseal.contract.SafetyContractPatchProposalFacts.FindingSourceFacts;
import com.finsecseal.contract.SafetyContractPatchProposalFacts.ProposedPatch;
import com.finsecseal.contract.SafetyContractPatchProposalFacts.Status;
import com.finsecseal.contract.SafetyContractPatchResponseProcessor.FailureCode;
import com.finsecseal.contract.SafetyContractPatchResponseProcessor.PatchAssessment;
import com.finsecseal.contract.SafetyContractPatchResponseProcessor.PatchResponseException;
import com.finsecseal.contract.SafetyContractSemanticValidator.ContractValidationCatalog;
import com.finsecseal.contract.SafetyContractSemanticValidator.EnabledTool;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/** Pure C protocol/decision tests. Supplied facts are not evidence of authorized database retrieval. */
class SafetyContractPatchResponseProcessorTest {
    private static final UUID WORKSPACE = UUID.fromString("0198f200-0000-7000-8000-000000000601");
    private static final UUID RELEASE = UUID.fromString("0198f200-0000-7000-8000-000000000602");
    private static final UUID VERSION = UUID.fromString("0198f200-0000-7000-8000-000000000603");
    private static final UUID FINDING = UUID.fromString("0198f200-0000-7000-8000-000000000604");
    private static final UUID OTHER = UUID.fromString("0198f200-0000-7000-8000-000000000699");
    private static final String CANARY = "UNTRUSTED-PATCH-CONTENT-CANARY";
    private static final String NARROW_FIELDS = """
            {"type":"NARROW_SET","setKind":"ALLOWED_FIELDS","toolName":"CUSTOMER_DATA_READ",
             "retainedValues":["incomeBand","employmentStatus"]}
            """;

    private ObjectMapper mapper;
    private SafetyContractCanonicalizer canonicalizer;
    private SafetyContractPatchProposalPolicy policy;
    private SafetyContractPatchResponseProcessor processor;
    private ObjectNode valid;
    private ObjectNode broad;
    private ObjectNode narrowed;
    private FindingSourceFacts source;
    private SourceBoundCatalog catalog;

    @BeforeEach
    void prepareActualPolicyEnginesAndDirectValueFixtures() throws Exception {
        mapper = new ObjectMapper();
        var schema = new SafetyContractSchemaValidator();
        canonicalizer = new SafetyContractCanonicalizer(schema, new CanonicalJsonService(mapper), new DigestService());
        policy = new SafetyContractPatchProposalPolicy(canonicalizer,
                new SafetyContractNarrowingValidator(schema, canonicalizer),
                new SafetyContractSemanticValidator(schema));
        processor = new SafetyContractPatchResponseProcessor(policy);
        try (var input = getClass().getResourceAsStream("/fixtures/loan-review-safety-contract.json")) {
            valid = (ObjectNode) mapper.readTree(input);
        }
        broad = valid.deepCopy();
        ((ArrayNode) broad.at("/fieldPolicy/CUSTOMER_DATA_READ/allowed")).add("accountNumber");
        narrowed = valid.deepCopy().put("version", 2);
        source = new FindingSourceFacts(FINDING, WORKSPACE, RELEASE, "OPEN", "SEED", false, digest('9'), "INV-02");
        catalog = new SourceBoundCatalog(RELEASE, "1.1", digest('1'), digest('2'), digest('3'),
                new ContractValidationCatalog(List.of(
                        new EnabledTool("CASE_CONTEXT_READ", List.of("caseId")),
                        new EnabledTool("DOCUMENT_READER", List.of("documents")),
                        new EnabledTool("CUSTOMER_DATA_READ", List.of("incomeBand", "employmentStatus", "accountNumber")),
                        new EnabledTool("LOAN_POLICY_SEARCH", List.of("policies")),
                        new EnabledTool("REVIEW_NOTE_WRITE", List.of("status"))), List.of("LOAN_DECISION_UPDATE")));
    }

    @Test
    void rawNarrowingResponsePreservesExactCandidateAndActualDecisionEvidence() {
        var base = snapshot(broad);
        var envelope = response(narrowed, NARROW_FIELDS);
        var result = processor.process(source, base, catalog, envelope.toString());

        assertThat(result.decision().status()).isEqualTo(Status.PROPOSED);
        assertThat(result.candidate().resultPolicy().toString()).isEqualTo(narrowed.toString());
        assertThat(result.candidate().resultPolicy().path("version").isIntegralNumber()).isTrue();
        assertThat(result.candidate().resultPolicy().path("version").bigIntegerValue()).isEqualTo(BigInteger.valueOf(2));
        assertThat(result.candidate().operations()).containsExactly(
                new NarrowSet(SetKind.ALLOWED_FIELDS, "CUSTOMER_DATA_READ", List.of("incomeBand", "employmentStatus")));
        assertThat(result.candidate().rootCause()).isEqualTo(CANARY);
        assertThat(result.candidate().normalWorkflowImpact()).isEqualTo("Keep required review fields");
        assertThat(result.candidate().rollback()).isEqualTo("Create a reviewed replacement version");
        assertThat(result.decision().acceptedProposal()).hasValueSatisfying(accepted -> {
            assertThat(accepted.source()).isEqualTo(source);
            assertThat(accepted.baseIdentity()).isEqualTo(base.identity());
            assertThat(accepted.basePolicyHash()).isEqualTo(base.policyHash());
            assertThat(accepted.resultPolicy()).isEqualTo(canonicalizer.canonicalizeAndHash(narrowed));
            assertThat(accepted.catalogBinding().serverToolCatalogHash()).isEqualTo(catalog.serverToolCatalogHash());
        });
        assertThat(result.toString()).doesNotContain(CANARY, "loan-review-default", envelope.toString());
        assertThat(base.state()).isEqualTo(VersionState.CANDIDATE);
        assertThat(base.policy()).isEqualTo(broad);
    }

    @ParameterizedTest
    @MethodSource("typedOperations")
    void decodesEveryClosedOperationTargetIntoTheExistingDomainType(String operation, SafetyContractPatchOperation expected) {
        var result = process(broad, response(narrowed, operation));
        assertThat(result.candidate().operations()).containsExactly(expected);
        // Decoding alone never claims this arbitrary operation describes the supplied policy delta.
        if (!expected.equals(new NarrowSet(SetKind.ALLOWED_FIELDS, "CUSTOMER_DATA_READ",
                List.of("incomeBand", "employmentStatus")))) {
            assertInvalid(result);
        }
    }

    static Stream<Arguments> typedOperations() {
        return Stream.of(
                Arguments.of("{\"type\":\"ADD_CONSTRAINT\",\"constraintKind\":\"CURRENT_APPLICANT_ONLY\"}",
                        new AddConstraint(ConstraintKind.CURRENT_APPLICANT_ONLY)),
                Arguments.of("{\"type\":\"ADD_CONSTRAINT\",\"constraintKind\":\"CURRENT_CASE_ONLY\",\"toolName\":\"DOCUMENT_READER\"}",
                        new AddConstraint(ConstraintKind.CURRENT_CASE_ONLY, "DOCUMENT_READER")),
                Arguments.of("{\"type\":\"ADD_CONSTRAINT\",\"constraintKind\":\"ALLOWED_DOCUMENTS_ONLY\",\"toolName\":\"DOCUMENT_READER\"}",
                        new AddConstraint(ConstraintKind.ALLOWED_DOCUMENTS_ONLY, "DOCUMENT_READER")),
                Arguments.of("{\"type\":\"ADD_CONSTRAINT\",\"constraintKind\":\"DENY_UNKNOWN_FIELDS\",\"toolName\":\"CUSTOMER_DATA_READ\"}",
                        new AddConstraint(ConstraintKind.DENY_UNKNOWN_FIELDS, "CUSTOMER_DATA_READ")),
                Arguments.of("{\"type\":\"ADD_CONSTRAINT\",\"constraintKind\":\"REQUIRE_TRUSTED_TOOL\"}",
                        new AddConstraint(ConstraintKind.REQUIRE_TRUSTED_TOOL)),
                Arguments.of("{\"type\":\"ADD_CONSTRAINT\",\"constraintKind\":\"DISABLE_EXTERNAL_EGRESS\"}",
                        new AddConstraint(ConstraintKind.DISABLE_EXTERNAL_EGRESS)),
                Arguments.of(NARROW_FIELDS, new NarrowSet(SetKind.ALLOWED_FIELDS, "CUSTOMER_DATA_READ", List.of("incomeBand", "employmentStatus"))),
                Arguments.of("{\"type\":\"NARROW_SET\",\"setKind\":\"ALLOWED_DESTINATIONS\",\"retainedValues\":[]}",
                        new NarrowSet(SetKind.ALLOWED_DESTINATIONS, List.of())),
                Arguments.of("{\"type\":\"NARROW_SET\",\"setKind\":\"WORKFLOW_STAGES\",\"retainedValues\":[\"DOCUMENT_REVIEW\"]}",
                        new NarrowSet(SetKind.WORKFLOW_STAGES, List.of("DOCUMENT_REVIEW"))),
                Arguments.of("{\"type\":\"NARROW_SET\",\"setKind\":\"ALLOWED_TRUST_LEVELS\",\"retainedValues\":[\"TRUSTED_INTERNAL\"]}",
                        new NarrowSet(SetKind.ALLOWED_TRUST_LEVELS, List.of("TRUSTED_INTERNAL"))),
                Arguments.of("{\"type\":\"NARROW_SET\",\"setKind\":\"REVIEW_STATUSES\",\"retainedValues\":[\"READY_FOR_HUMAN_REVIEW\"]}",
                        new NarrowSet(SetKind.REVIEW_STATUSES, List.of("READY_FOR_HUMAN_REVIEW"))),
                Arguments.of("{\"type\":\"LOWER_LIMIT\",\"limitKind\":\"MAX_REQUESTED_RECORDS\",\"toolName\":\"CUSTOMER_DATA_READ\",\"newLimit\":1}",
                        new LowerLimit(LimitKind.MAX_REQUESTED_RECORDS, "CUSTOMER_DATA_READ", 1)),
                Arguments.of("{\"type\":\"LOWER_LIMIT\",\"limitKind\":\"MAX_RETURNED_RECORDS\",\"toolName\":\"CUSTOMER_DATA_READ\",\"newLimit\":9223372036854775809}",
                        new LowerLimit(LimitKind.MAX_RETURNED_RECORDS, "CUSTOMER_DATA_READ", new BigInteger("9223372036854775809"))),
                Arguments.of("{\"type\":\"DENY_TOOL\",\"toolName\":\"CUSTOMER_DATA_READ\"}", new DenyTool("CUSTOMER_DATA_READ")),
                Arguments.of("{\"type\":\"SET_HUMAN_ONLY\",\"toolName\":\"LOAN_DECISION_UPDATE\"}", new SetHumanOnly("LOAN_DECISION_UPDATE")));
    }

    @Test
    void noChangeRequiresTheExactUnchangedAndSemanticallyValidPolicy() {
        var result = process(valid, response(valid));
        assertThat(result.decision().status()).isEqualTo(Status.NO_CHANGE_NEEDED);
        assertThat(result.decision().acceptedProposal().orElseThrow().resultPolicy().policyHash())
                .isEqualTo(snapshot(valid).policyHash());
        assertInvalid(process(broad, response(broad)));
        assertInvalid(process(valid, response(narrowed)));
    }

    @Test
    void rejectsExpansionAndUndeclaredChangesThroughTheRawResponsePath() {
        String expandedFields = NARROW_FIELDS.replace("\"incomeBand\",\"employmentStatus\"",
                "\"incomeBand\",\"employmentStatus\",\"accountNumber\"");
        assertInvalid(process(valid, response(broad.deepCopy().put("version", 2), expandedFields)));
        assertInvalid(process(broad, response(narrowed.deepCopy().put("purpose", "UNDECLARED"), NARROW_FIELDS)));
        assertInvalid(process(broad, response(narrowed, NARROW_FIELDS, NARROW_FIELDS)));
        assertInvalid(process(broad, response(narrowed, NARROW_FIELDS.replace("\"employmentStatus\"", "\"incomeBand\""))));
    }

    @Test
    void narrowerPolicyCannotRemoveMinimumWorkflowFields() {
        var resultPolicy = narrowed.deepCopy();
        ((ObjectNode) resultPolicy.at("/fieldPolicy/CUSTOMER_DATA_READ")).putArray("allowed").add("incomeBand");
        var result = process(broad, response(resultPolicy, NARROW_FIELDS.replace(",\"employmentStatus\"", "")));
        assertInvalid(result);
        assertThat(result.decision().narrowing().orElseThrow().valid()).isTrue();
        assertThat(result.decision().semantic().orElseThrow().issues())
                .extracting(SafetyContractSemanticValidator.Issue::code).contains("REQUIRED_FIELD_MISSING");
    }

    @Test
    void noChangeCannotLegitimizeHumanOnlyConflictOrUndeclaredOutputFields() {
        var conflict = valid.deepCopy();
        ((ArrayNode) conflict.path("allowedTools")).add("LOAN_DECISION_UPDATE");
        var conflictResult = process(conflict, response(conflict));
        assertInvalid(conflictResult);
        assertThat(conflictResult.decision().semantic().orElseThrow().issues())
                .extracting(SafetyContractSemanticValidator.Issue::code).contains("HUMAN_ONLY_TOOL_ALLOWED");
        var unknownField = valid.deepCopy();
        ((ArrayNode) unknownField.at("/fieldPolicy/CUSTOMER_DATA_READ/allowed")).add("undeclaredField");
        var fieldResult = process(unknownField, response(unknownField));
        assertInvalid(fieldResult);
        assertThat(fieldResult.decision().semantic().orElseThrow().issues())
                .extracting(SafetyContractSemanticValidator.Issue::code).contains("FIELD_NOT_IN_TOOL_OUTPUT");
    }

    @ParameterizedTest
    @ValueSource(strings = {"3", "4294967298", "2.0", "2e0", "\"2\""})
    void wrongOrCoercedPolicyVersionCannotProduceAcceptance(String version) {
        var body = response(narrowed, NARROW_FIELDS).toString().replace("\"version\":2", "\"version\":" + version);
        assertInvalid(processor.process(source, snapshot(broad), catalog, body));
    }

    @ParameterizedTest
    @ValueSource(strings = {"cafe\u0301", "line\r\nkey", "일반 계약 키"})
    void keepsOriginalGeneralStringIdentityAndRejectsCanonicalAliases(String key) {
        var basePolicy = broad.deepCopy().put("contractId", key);
        var resultPolicy = narrowed.deepCopy().put("contractId", key);
        assertThat(process(basePolicy, response(resultPolicy, NARROW_FIELDS)).decision().status()).isEqualTo(Status.PROPOSED);
        String changed = Normalizer.normalize(key.replace("\r\n", "\n"), Normalizer.Form.NFC);
        if (changed.equals(key)) changed = key + " ";
        resultPolicy.put("contractId", changed);
        var unused = mock(SafetyContractPatchProposalPolicy.class);
        expect(new SafetyContractPatchResponseProcessor(unused), FailureCode.IDENTITY_MISMATCH,
                snapshot(basePolicy), response(resultPolicy, NARROW_FIELDS).toString());
        verifyNoInteractions(unused);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "null", "[]", "true", "7", "\"text\"", "{", "{} {}",
            "// comment\n{}", "/* comment */ {}", "{'resultPolicy':{}}", "```json\n{}\n```"})
    void malformedJsonNeverCallsThePolicy(String raw) {
        malformed(raw);
    }

    @Test
    void rejectsDuplicateEscapedAndNestedKeysAndTrailingContent() {
        String raw = response(narrowed, NARROW_FIELDS).toString();
        malformed(raw.replace("\"rootCause\":", "\"rootCause\":\"duplicate\",\"rootCause\":"));
        malformed(raw.replace("\"rootCause\":", "\"rootCause\":\"duplicate\",\"root\\u0043ause\":"));
        malformed(raw.replace("\"version\":2", "\"version\":2,\"version\":2"));
        malformed(raw.replace("\"type\":\"NARROW_SET\"", "\"type\":\"DENY_TOOL\",\"type\":\"NARROW_SET\""));
        malformed(raw + " {}");
        malformed(raw + " explanatory text");
    }

    @ParameterizedTest
    @ValueSource(strings = {"resultPolicy", "operations", "rootCause", "normalWorkflowImpact", "rollback"})
    void rejectsMissingNullAndWrongTypeEnvelopeFields(String field) {
        var missing = response(narrowed, NARROW_FIELDS);
        missing.remove(field);
        malformed(missing.toString());
        var nullValue = response(narrowed, NARROW_FIELDS);
        nullValue.putNull(field);
        malformed(nullValue.toString());
        var wrongType = response(narrowed, NARROW_FIELDS);
        wrongType.put(field, 7);
        malformed(wrongType.toString());
        if (!field.equals("resultPolicy") && !field.equals("operations")) {
            // Blank explanations are valid strings, but the existing domain policy rejects them.
            assertInvalid(process(broad, response(narrowed, NARROW_FIELDS).put(field, " ")));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"source", "base", "catalog", "approved", "status", "policyHash", "provider", "@class"})
    void modelCannotSupplyOwnerFactsOrAuthorityFields(String field) {
        malformed(response(narrowed, NARROW_FIELDS).put(field, CANARY).toString());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "null", "7", "{}", "{\"op\":\"replace\",\"path\":\"/allowedTools\",\"value\":[]}",
            "{\"type\":\"ALLOW_TOOL\",\"toolName\":\"CUSTOMER_DATA_READ\"}",
            "{\"type\":\"deny_tool\",\"toolName\":\"CUSTOMER_DATA_READ\"}",
            "{\"type\":7,\"toolName\":\"CUSTOMER_DATA_READ\"}",
            "{\"type\":\"DENY_TOOL\"}", "{\"type\":\"DENY_TOOL\",\"toolName\":null}",
            "{\"type\":\"DENY_TOOL\",\"toolName\":3}", "{\"type\":\"DENY_TOOL\",\"toolName\":\" \"}",
            "{\"type\":\"DENY_TOOL\",\"toolName\":\"CUSTOMER_DATA_READ\",\"newLimit\":0}",
            "{\"type\":\"ADD_CONSTRAINT\",\"constraintKind\":\"UNKNOWN\"}",
            "{\"type\":\"ADD_CONSTRAINT\",\"constraintKind\":\"CURRENT_CASE_ONLY\"}",
            "{\"type\":\"ADD_CONSTRAINT\",\"constraintKind\":\"CURRENT_APPLICANT_ONLY\",\"toolName\":\"CUSTOMER_DATA_READ\"}",
            "{\"type\":\"ADD_CONSTRAINT\",\"constraintKind\":\"CURRENT_APPLICANT_ONLY\",\"toolName\":null}",
            "{\"type\":\"NARROW_SET\",\"setKind\":\"ALLOWED_FIELDS\",\"retainedValues\":[]}",
            "{\"type\":\"NARROW_SET\",\"setKind\":\"WORKFLOW_STAGES\",\"toolName\":\"DOCUMENT_READER\",\"retainedValues\":[]}",
            "{\"type\":\"NARROW_SET\",\"setKind\":\"WORKFLOW_STAGES\",\"retainedValues\":\"DOCUMENT_REVIEW\"}",
            "{\"type\":\"NARROW_SET\",\"setKind\":\"WORKFLOW_STAGES\",\"retainedValues\":[1]}",
            "{\"type\":\"LOWER_LIMIT\",\"limitKind\":\"UNKNOWN\",\"toolName\":\"CUSTOMER_DATA_READ\",\"newLimit\":1}",
            "{\"type\":\"LOWER_LIMIT\",\"limitKind\":\"MAX_RETURNED_RECORDS\",\"toolName\":\"CUSTOMER_DATA_READ\",\"newLimit\":\"1\"}",
            "{\"type\":\"LOWER_LIMIT\",\"limitKind\":\"MAX_RETURNED_RECORDS\",\"toolName\":\"CUSTOMER_DATA_READ\",\"newLimit\":1.0}",
            "{\"type\":\"LOWER_LIMIT\",\"limitKind\":\"MAX_RETURNED_RECORDS\",\"toolName\":\"CUSTOMER_DATA_READ\",\"newLimit\":1e0}"
    })
    void rejectsInvalidTypedOperationShapesWithoutCallingPolicy(String operation) {
        malformed(response(narrowed, operation).toString());
    }

    @Test
    void delegatedSourceScopeAndHashFailuresCannotBecomeAcceptance() {
        var body = response(narrowed, NARROW_FIELDS).toString();
        for (var ineligible : List.of(
                new FindingSourceFacts(FINDING, WORKSPACE, RELEASE, "CLOSED", "SEED", false, digest('9'), "INV-02"),
                new FindingSourceFacts(FINDING, WORKSPACE, RELEASE, "OPEN", "HELD_OUT", false, digest('9'), "INV-02"),
                new FindingSourceFacts(FINDING, WORKSPACE, RELEASE, "OPEN", "SEED", true, digest('9'), "INV-02"),
                new FindingSourceFacts(FINDING, OTHER, RELEASE, "OPEN", "SEED", false, digest('9'), "INV-02"),
                new FindingSourceFacts(FINDING, WORKSPACE, OTHER, "OPEN", "SEED", false, digest('9'), "INV-02"))) {
            assertInvalid(processor.process(ineligible, snapshot(broad), catalog, body));
        }
        var base = snapshot(broad);
        var badHash = new ContractVersionSnapshot(base.identity(), base.state(), base.policy(), digest('8'),
                base.resourceHash(), Optional.empty(), Optional.empty());
        assertInvalid(processor.process(source, badHash, catalog, body));
        var otherCatalog = new SourceBoundCatalog(OTHER, catalog.manifestSchemaVersion(),
                catalog.agentArtifactFingerprint(), catalog.releaseFingerprint(), catalog.serverToolCatalogHash(), catalog.semanticCatalog());
        assertInvalid(processor.process(source, base, otherCatalog, body));
    }

    @Test
    void resultPolicyAndTypedCollectionsCannotMutateAcceptedEvidence() {
        var envelope = response(narrowed, NARROW_FIELDS);
        var result = process(broad, envelope);
        String accepted = result.decision().acceptedProposal().orElseThrow().resultPolicy().canonicalJson();
        ((ObjectNode) envelope.path("resultPolicy")).put("version", 999);
        ((ObjectNode) result.candidate().resultPolicy()).put("version", 888);
        assertThat(result.candidate().resultPolicy().path("version").intValue()).isEqualTo(2);
        assertThat(result.decision().acceptedProposal().orElseThrow().resultPolicy().canonicalJson()).isEqualTo(accepted);
        assertThatThrownBy(() -> result.candidate().operations().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> ((NarrowSet) result.candidate().operations().getFirst()).retainedValues().add("accountNumber"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void byteLimitAcceptsBoundaryAndRejectsCharacterAndUtf8Overflow() {
        String raw = response(narrowed, NARROW_FIELDS).toString();
        int max = SafetyContractPatchResponseProcessor.MAX_RESPONSE_BYTES;
        String boundary = raw + " ".repeat(max - raw.getBytes(StandardCharsets.UTF_8).length);
        assertThat(processor.process(source, snapshot(broad), catalog, boundary).decision().status()).isEqualTo(Status.PROPOSED);
        expect(processor, FailureCode.RESPONSE_TOO_LARGE, snapshot(broad), boundary + " ");
        var multi = response(narrowed, NARROW_FIELDS);
        multi.put("rootCause", "한".repeat(8000));
        multi.put("normalWorkflowImpact", "한".repeat(8000));
        multi.put("rollback", "한".repeat(8000));
        assertThat(multi.toString().length()).isLessThan(max);
        expect(processor, FailureCode.RESPONSE_TOO_LARGE, snapshot(broad), multi.toString());
    }

    @ParameterizedTest
    @ValueSource(strings = {"string", "name", "number", "depth", "tokens"})
    void parserResourceBoundsRejectOverflowBeforePolicy(String limit) {
        ObjectNode within = response(narrowed, NARROW_FIELDS);
        ObjectNode over = response(narrowed, NARROW_FIELDS);
        ObjectNode insidePolicy = (ObjectNode) within.path("resultPolicy");
        ObjectNode overPolicy = (ObjectNode) over.path("resultPolicy");
        switch (limit) {
            case "string" -> {
                insidePolicy.put("unexpected", "x".repeat(SafetyContractPatchResponseProcessor.MAX_STRING_LENGTH));
                overPolicy.put("unexpected", "x".repeat(SafetyContractPatchResponseProcessor.MAX_STRING_LENGTH + 1));
            }
            case "name" -> {
                insidePolicy.put("x".repeat(SafetyContractPatchResponseProcessor.MAX_NAME_LENGTH), true);
                overPolicy.put("x".repeat(SafetyContractPatchResponseProcessor.MAX_NAME_LENGTH + 1), true);
            }
            case "number" -> {
                insidePolicy.put("unexpected", new BigInteger("9".repeat(SafetyContractPatchResponseProcessor.MAX_NUMBER_LENGTH)));
                overPolicy.put("unexpected", new BigInteger("9".repeat(SafetyContractPatchResponseProcessor.MAX_NUMBER_LENGTH + 1)));
            }
            case "depth" -> {
                int depth = SafetyContractPatchResponseProcessor.MAX_DEPTH - 2;
                insidePolicy.set("unexpected", mapper.readTree("[".repeat(depth) + "0" + "]".repeat(depth)));
                overPolicy.set("unexpected", mapper.readTree("[".repeat(depth + 1) + "0" + "]".repeat(depth + 1)));
            }
            case "tokens" -> {
                var values = insidePolicy.putArray("unexpected");
                int remaining = SafetyContractPatchResponseProcessor.MAX_TOKEN_COUNT - tokens(within.toString());
                for (int i = 0; i < remaining; i++) values.add(0);
                over = within.deepCopy();
                ((ArrayNode) over.at("/resultPolicy/unexpected")).add(0);
            }
            default -> throw new AssertionError(limit);
        }
        assertThat(over.toString().getBytes(StandardCharsets.UTF_8).length)
                .isLessThan(SafetyContractPatchResponseProcessor.MAX_RESPONSE_BYTES);
        assertInvalid(process(broad, within));
        malformed(over.toString());
    }

    @ParameterizedTest
    @ValueSource(strings = {"throws", "null"})
    void engineFailureProducesNoAssessmentAndNoRawCauseOrRetry(String fault) {
        var engine = mock(SafetyContractPatchProposalPolicy.class);
        if (fault.equals("throws")) {
            when(engine.evaluate(any(), any(), any(), any())).thenThrow(new IllegalStateException(CANARY));
        }
        expect(new SafetyContractPatchResponseProcessor(engine), FailureCode.PROCESSING_FAILURE,
                snapshot(broad), response(narrowed, NARROW_FIELDS).toString());
        verify(engine, times(1)).evaluate(any(), any(), any(ProposedPatch.class), any());
        verifyNoMoreInteractions(engine);
    }

    @Test
    void nullRequestInputsAreRejectedBeforePolicy() {
        var engine = mock(SafetyContractPatchProposalPolicy.class);
        var subject = new SafetyContractPatchResponseProcessor(engine);
        var base = snapshot(broad);
        String raw = response(narrowed, NARROW_FIELDS).toString();
        assertInvalidRequest(() -> subject.process(null, base, catalog, raw));
        assertInvalidRequest(() -> subject.process(source, null, catalog, raw));
        assertInvalidRequest(() -> subject.process(source, base, null, raw));
        assertInvalidRequest(() -> subject.process(source, base, catalog, null));
        verifyNoInteractions(engine);
    }

    private int tokens(String raw) {
        int count = 0;
        try (var parser = mapper.createParser(raw)) {
            while (parser.nextToken() != null) count++;
        }
        return count;
    }

    private PatchAssessment process(JsonNode base, ObjectNode response) {
        return processor.process(source, snapshot(base), catalog, response.toString());
    }

    private ObjectNode response(JsonNode result, String... operations) {
        var body = mapper.createObjectNode();
        body.set("resultPolicy", result.deepCopy());
        var array = body.putArray("operations");
        for (String operation : operations) array.add(mapper.readTree(operation));
        return body.put("rootCause", CANARY).put("normalWorkflowImpact", "Keep required review fields")
                .put("rollback", "Create a reviewed replacement version");
    }

    private ContractVersionSnapshot snapshot(JsonNode document) {
        return new ContractVersionSnapshot(new VersionIdentity(VERSION, WORKSPACE, RELEASE,
                document.path("contractId").stringValue(), document.path("version").intValue()),
                VersionState.CANDIDATE, document, canonicalizer.canonicalizeAndHash(document).policyHash(),
                digest('4'), Optional.empty(), Optional.empty());
    }

    private void malformed(String raw) {
        var unused = mock(SafetyContractPatchProposalPolicy.class);
        expect(new SafetyContractPatchResponseProcessor(unused), FailureCode.MALFORMED_RESPONSE, snapshot(broad), raw);
        verifyNoInteractions(unused);
    }

    private void expect(SafetyContractPatchResponseProcessor subject, FailureCode code, ContractVersionSnapshot base, String raw) {
        assertThatThrownBy(() -> subject.process(source, base, catalog, raw))
                .isInstanceOfSatisfying(PatchResponseException.class, exception -> {
                    assertThat(exception.code()).isEqualTo(code);
                    assertThat(exception.getCause()).isNull();
                    assertThat(exception.getSuppressed()).isEmpty();
                    assertThat(exception.getMessage()).doesNotContain(CANARY);
                });
    }

    private static void assertInvalidRequest(org.assertj.core.api.ThrowableAssert.ThrowingCallable action) {
        assertThatThrownBy(action).isInstanceOfSatisfying(PatchResponseException.class,
                exception -> assertThat(exception.code()).isEqualTo(FailureCode.INVALID_REQUEST));
    }

    private static void assertInvalid(PatchAssessment result) {
        assertThat(result.decision().status()).isEqualTo(Status.INVALID);
        assertThat(result.decision().acceptedProposal()).isEmpty();
        assertThat(result.decision().issues()).isNotEmpty();
    }

    private static String digest(char value) { return "sha256:" + String.valueOf(value).repeat(64); }
}
