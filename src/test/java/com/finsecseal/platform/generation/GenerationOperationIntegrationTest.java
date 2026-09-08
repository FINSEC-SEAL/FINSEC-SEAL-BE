package com.finsecseal.platform.generation;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import com.finsecseal.agent.*;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.*;
import com.finsecseal.platform.contract.*;
import com.finsecseal.platform.generation.GenerationContract.*;
import com.finsecseal.release.*;
import com.finsecseal.runtime.ai.ContractCandidateAiClient;
import java.net.URI;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.common.domain.ExecutionEventType;
import java.net.http.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.testcontainers.junit.jupiter.*;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Testcontainers
@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT,properties={
    "finsec.ai.enabled=true","finsec.scheduling.enabled=false","finsec.crypto.key-base64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "finsec.contract-access.key=test-reviewer-key-at-least-32-bytes-long","finsec.contract-access.actor=generation-reviewer",
    "finsec.contract-access.workspace=0198f1e2-0000-7000-8000-000000000001"})
class GenerationOperationIntegrationTest {
    @Container @ServiceConnection static final PostgreSQLContainer POSTGRES=new PostgreSQLContainer("postgres:17.11-alpine");
    @Autowired GenerationOperationService operations;
    @Autowired com.finsecseal.common.api.IdempotencyFilter idempotency;
    @Autowired GenerationWorker worker;
    @org.springframework.test.context.bean.override.mockito.MockitoSpyBean GenerationEngine engine;
    @org.springframework.test.context.bean.override.mockito.MockitoSpyBean ContractReviewerCredentials credentials;
    @Autowired ContractPersistenceService contracts;
    @Autowired AgentService agents;
    @Autowired ReleaseService releases;
    @Autowired JdbcTemplate db;
    @Autowired ObjectMapper json;
    @Autowired ExecutionEventService eventService;
    @Autowired CanonicalJsonService canonical;
    @Autowired DigestService digest;
    private static final String HASH_A="sha256:"+"a".repeat(64);
    @LocalServerPort int port;
    @MockitoBean ContractCandidateAiClient models;
    static final String KEY="test-reviewer-key-at-least-32-bytes-long";
    final ReviewerContext reviewer=new ReviewerContext(AgentService.DEMO_WORKSPACE_ID,"generation-reviewer","AI_SECURITY_REVIEWER","test-session",true,true,false);
    @BeforeEach void provider() throws Exception {
        String body=policy().toString();
        when(models.generate(anyString(),anyString(),anyString())).thenAnswer(call->{
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
            assertThat(TransactionSynchronizationManager.isSynchronizationActive()).isFalse();
            return new ContractCandidateAiClient.CandidateModelResponse("test-provider","test-model",body,5);
        });
    }
    @AfterEach void drain() {operations.expire();while(worker.runOne()) {} }
    ObjectNode policy() throws Exception {return (ObjectNode)json.readTree(getClass().getResourceAsStream("/fixtures/loan-review-safety-contract.json"));}
    UUID release() throws Exception {
        String key="async-"+UUID.randomUUID();var agent=agents.create(new AgentDto.CreateRequest(key,"Async test","review"));
        ObjectNode manifest=(ObjectNode)json.readTree(getClass().getResourceAsStream("/fixtures/valid-release-manifest-v1.1.json"));
        ((ObjectNode)manifest.path("agent")).put("id",key);
        var release=releases.create(agent.id(),manifest,reviewer.actorId());releases.analyze(release.id(),reviewer.actorId());return release.id();
    }
    Operation submit(UUID release) {return operations.submit(Kind.CONTRACT,release,null,"loan-review/1",reviewer);}
    @Test void originalHttpPathAuthenticatesBeforeIdempotencyAndReturnsDurable202() throws Exception {
        UUID release=release();String path="/api/v1/releases/"+release+"/contracts:generate";
        String key=UUID.randomUUID().toString(),body="{\"templateKey\":\"loan-review/1\"}";
        assertThat(post(path,body,key,"wrong").statusCode()).isEqualTo(403);
        assertThat(db.queryForObject("select count(*) from api_idempotency_records where idempotency_key=?",Integer.class,key)).isZero();
        var first=post(path,body,key,KEY);assertThat(first.statusCode()).withFailMessage(first.body()).isEqualTo(202);
        var duplicate=post(path,body,key,KEY);assertThat(duplicate.body()).isEqualTo(first.body());
        var id=UUID.fromString(json.readTree(first.body()).at("/data/operationId").stringValue());
        assertThat(first.headers().firstValue("Location")).contains("/api/v1/operations/"+id);
        assertThat(post(path,body,UUID.randomUUID().toString(),KEY).statusCode()).isEqualTo(409);
        assertThat(post(path,"{\"templateKey\":\"other\"}",key,KEY).statusCode()).isEqualTo(409);
        assertThat(post(path,"{\"templateKey\":\"loan-review/1\",\"actorId\":\"forged\"}",UUID.randomUUID().toString(),KEY).statusCode()).isEqualTo(400);
        assertThat(worker.runOne()).isTrue();
        assertThat(db.queryForObject("select admission_id from generation_operations where id=?",UUID.class,id)).isNotNull();
        var done=operations.find(id,reviewer);assertThat(done.status()).isEqualTo("SUCCEEDED");assertThat(done.outcome()).isEqualTo("VALID");
        UUID stored=UUID.fromString(done.result().path("contractVersionId").stringValue());
        assertThat(db.queryForObject("select version_id from generation_operations where id=?",UUID.class,id)).isEqualTo(stored);
        assertThat(contracts.find(stored,reviewer).state()).isEqualTo("CANDIDATE");
        assertThat(db.queryForObject("select metadata_json::text from contract_generation_records where operation_id=?",String.class,id)).contains("test-provider","promptDigest").doesNotContain("instructions","inputJson");
        var request=HttpRequest.newBuilder(URI.create("http://localhost:"+port+done.statusUrl())).header("X-Contract-Reviewer-Key",KEY).GET().build();
        assertThat(HttpClient.newHttpClient().send(request,HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(200);
        assertThatThrownBy(()->db.update("update generation_operations set status='QUEUED' where id=?",id)).hasMessageContaining("immutable");
        verify(models,times(1)).generate(anyString(),anyString(),anyString());
    }
    @Test void invalidIsCompletedAssessmentWithoutSavedVersion() throws Exception {
        var invalid=policy();((tools.jackson.databind.node.ArrayNode)invalid.at("/fieldPolicy/CUSTOMER_DATA_READ/allowed")).add("accountNumber");
        when(models.generate(anyString(),anyString(),anyString())).thenReturn(new ContractCandidateAiClient.CandidateModelResponse("test","model",invalid.toString(),2));
        var op=submit(release());worker.runOne();var done=operations.find(op.operationId(),reviewer);
        assertThat(done.status()).isEqualTo("SUCCEEDED");assertThat(done.outcome()).isEqualTo("INVALID");
        assertThat(done.result().has("contractVersionId")).isFalse();
        assertThat(db.queryForObject("select count(*) from safety_contract_versions where id=(select version_id from generation_operations where id=?)",Integer.class,op.operationId())).isZero();
    }
    @Test void providerFailureDoesNotLeakDiagnosticsOrRetry() throws Exception {
        when(models.generate(anyString(),anyString(),anyString())).thenThrow(new IllegalStateException("secret-provider-diagnostic"));
        var op=submit(release());worker.runOne();assertThat(worker.runOne()).isFalse();
        var done=operations.find(op.operationId(),reviewer);assertThat(done.status()).isEqualTo("FAILED");
        assertThat(done.errorCode()).isEqualTo("MODEL_CALL_FAILURE");assertThat(json.writeValueAsString(done)).doesNotContain("secret-provider-diagnostic");
        verify(models,times(1)).generate(anyString(),anyString(),anyString());
    }
    @Test void concurrentClaimsCannotExecuteTwiceAndReservationBlocksOtherWriters() throws Exception {
        UUID release=release();var op=submit(release);
        var body=policy();assertThatThrownBy(()->contracts.create(release,body,reviewer)).hasMessageContaining("reserved");
        try(var pool=Executors.newFixedThreadPool(2)) {
            var gate=new CountDownLatch(1);Callable<Optional<Work>> claim=()->{gate.await();return operations.claim();};
            var one=pool.submit(claim);var two=pool.submit(claim);gate.countDown();
            var work=java.util.stream.Stream.of(one.get(),two.get()).flatMap(Optional::stream).toList();assertThat(work).hasSize(1);
            operations.checkBeforeModel(work.getFirst());operations.complete(work.getFirst(),engine.generate(work.getFirst()));
        }
        assertThat(operations.find(op.operationId(),reviewer).status()).isEqualTo("SUCCEEDED");
    }
    @Test void staleSourceAfterModelCallCannotBeSaved() throws Exception {
        UUID release=release();db.update("update agent_releases set lifecycle_state='REMEDIATION',effective_status='REMEDIATION' where id=?",release);
        var c=contracts.create(release,policy(),reviewer);var validated=contracts.validate(c.id(),'"'+c.resourceHash()+'"',reviewer);
        String generated=policy().put("version",2).toString();
        when(models.generate(anyString(),anyString(),anyString())).thenAnswer(call->{
            contracts.approve(validated.id(),'"'+validated.resourceHash()+'"',"review",reviewer);
            return new ContractCandidateAiClient.CandidateModelResponse("test","model",generated,2);
        });
        var op=submit(release);worker.runOne();var done=operations.find(op.operationId(),reviewer);
        assertThat(done.status()).isEqualTo("FAILED");assertThat(done.errorCode()).isEqualTo("RELEASE_CHANGED");
        assertThat(db.queryForObject("select count(*) from contract_generation_records where operation_id=?",Integer.class,op.operationId())).isZero();
    }
    @Test void crashRequiresRecoveryAndLateResultIsFenced() throws Exception {
        var op=submit(release());UUID token=UUID.randomUUID();
        db.update("update generation_operations set status='RUNNING',claim_token=?,started_at=now()-interval '5 minutes',lease_expires_at=now()-interval '1 second' where id=?",token,op.operationId());
        operations.expire();assertThat(operations.find(op.operationId(),reviewer).status()).isEqualTo("RECOVERY_REQUIRED");
        assertThat(worker.runOne()).isFalse();verifyNoInteractions(models);
        var identity=new VersionIdentity(UUID.randomUUID(),reviewer.workspaceId(),op.releaseId(),"loan-review-default",1);
        var late=new Work(op.operationId(),token,Kind.CONTRACT,identity,"loan-review/1",reviewer,null);
        assertThatThrownBy(()->operations.complete(late,null)).hasMessageContaining("claim expired");
    }
    @Test void candidateAndMetadataRollbackTogetherOnStorageFailure() throws Exception {
        var op=submit(release());
        db.execute("create function generation_test_fail() returns trigger language plpgsql as $$ begin raise exception 'test failure'; end $$");
        db.execute("create trigger generation_test_fail before insert on contract_generation_records for each row execute function generation_test_fail()");
        try {worker.runOne();} finally {db.execute("drop trigger generation_test_fail on contract_generation_records");db.execute("drop function generation_test_fail()");}
        assertThat(operations.find(op.operationId(),reviewer).status()).isEqualTo("FAILED");
        assertThat(db.queryForObject("select count(*) from safety_contract_versions where id=(select version_id from generation_operations where id=?)",Integer.class,op.operationId())).isZero();
    }
    @Test void patchFlowStoresGenerationBindingsAndMetadata() throws Exception {
        Seed seed=seed("SEED",false,false);
        var broad=policy();((tools.jackson.databind.node.ArrayNode)broad.at("/fieldPolicy/CUSTOMER_DATA_READ/allowed")).add("accountNumber");
        var base=contracts.create(seed.releaseId(),broad,reviewer);
        var response=patchResponse(policy().put("version",2),true);
        when(models.generate(anyString(),anyString(),anyString())).thenReturn(new ContractCandidateAiClient.CandidateModelResponse("test","patch-model",response.toString(),9));
        var accepted=post("/api/v1/findings/"+seed.findingId()+"/patch-proposals","{\"baseContractVersionId\":\""+base.id()+"\"}",UUID.randomUUID().toString(),KEY);
        assertThat(accepted.statusCode()).withFailMessage(accepted.body()).isEqualTo(202);
        UUID operation=UUID.fromString(json.readTree(accepted.body()).at("/data/operationId").stringValue());
        worker.runOne();var done=operations.find(operation,reviewer);
        assertThat(done.status()).withFailMessage(json.writeValueAsString(done)).isEqualTo("SUCCEEDED");
        assertThat(done.outcome()).isEqualTo("PROPOSED");
        UUID proposal=UUID.fromString(done.result().path("patchProposalId").stringValue());
        String metadata=db.queryForObject("select generation_model_meta_json::text from patch_proposals where id=?",String.class,proposal);
        assertThat(metadata).contains("patch-model","sourceEvidenceDigest","redactedEvidenceDigest",base.resourceHash(),seed.findingId().toString());
        assertThat(db.queryForObject("select version_id from contract_generation_records where operation_id=?",UUID.class,operation)).isEqualTo(
                db.queryForObject("select version_id from generation_operations where id=?",UUID.class,operation));
    }
    @Test void noChangeDoesNotCreateAnotherVersionAndHiddenSourceNeverCallsModel() throws Exception {
        Seed seed=seed("SEED",false,false);var base=contracts.create(seed.releaseId(),policy(),reviewer);
        when(models.generate(anyString(),anyString(),anyString())).thenReturn(new ContractCandidateAiClient.CandidateModelResponse("test","model",patchResponse(policy(),false).toString(),1));
        var op=operations.submit(Kind.PATCH,seed.findingId(),base.id(),"loan-review/1",reviewer);worker.runOne();
        var done=operations.find(op.operationId(),reviewer);assertThat(done.status()).withFailMessage(json.writeValueAsString(done)).isEqualTo("SUCCEEDED");
        assertThat(done.outcome()).isEqualTo("NO_CHANGE_NEEDED");assertThat(done.result().has("contractVersionId")).isFalse();
        Seed hidden=seed("HELD_OUT",true,false);var hiddenBase=contracts.create(hidden.releaseId(),policy(),reviewer);
        assertThatThrownBy(()->operations.submit(Kind.PATCH,hidden.findingId(),hiddenBase.id(),"loan-review/1",reviewer)).hasMessage("Eligible patch source not found");
        verify(models,times(1)).generate(anyString(),anyString(),anyString());
    }
    private ObjectNode patchResponse(ObjectNode result,boolean narrowing) {
        var response=json.createObjectNode();response.set("resultPolicy",result);var changes=response.putArray("operations");
        if(narrowing) changes.addObject().put("type","NARROW_SET").put("setKind","ALLOWED_FIELDS").put("toolName","CUSTOMER_DATA_READ")
                .putArray("retainedValues").add("incomeBand").add("employmentStatus");
        return response.put("rootCause","Excessive fields").put("normalWorkflowImpact","Retain required fields").put("rollback","Review replacement policy");
    }
    @Test void disabledProviderDoesNotReserveAnIdempotencyKey() throws Exception {
        doReturn(false).when(engine).available(any());
        String key=UUID.randomUUID().toString();
        var response=post("/api/v1/releases/"+UUID.randomUUID()+"/contracts:generate","{\"templateKey\":\"loan-review/1\"}",key,KEY);
        assertThat(response.statusCode()).isEqualTo(503);
        assertThat(db.queryForObject("select count(*) from api_idempotency_records where idempotency_key=?",Integer.class,key)).isZero();
    }
    @Test void changedAuthorityPreventsQueuedExecution() throws Exception {
        var op=submit(release());
        doThrow(new IllegalStateException("rotated")).when(credentials).authorityStamp(any());
        assertThat(worker.runOne()).isFalse();
        assertThat(db.queryForObject("select error_code from generation_operations where id=?",String.class,op.operationId())).isEqualTo("AUTHORITY_EXPIRED");
        verifyNoInteractions(models);
    }
    @Test void trustedWorkspaceAttributeSeparatesIdempotencyReplay() throws Exception {
        UUID other=UUID.randomUUID();db.update("insert into workspaces(id,name,mode) values(?,'scope test','DEMO')",other);
        String key=UUID.randomUUID().toString();var bodies=new ArrayList<String>();var calls=new java.util.concurrent.atomic.AtomicInteger();
        for(UUID workspace:List.of(reviewer.workspaceId(),other,other)) {
            var request=new org.springframework.mock.web.MockHttpServletRequest("POST","/api/v1/scope-probe");
            request.setAttribute(com.finsecseal.common.api.IdempotencyFilter.WORKSPACE,workspace);
            request.addHeader("Idempotency-Key",key);request.addHeader("X-Actor-Id","same-actor");request.setContentType("application/json");
            request.setContent("{}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            var response=new org.springframework.mock.web.MockHttpServletResponse();
            idempotency.doFilter(request,response,(req,res)->{
                var http=(jakarta.servlet.http.HttpServletResponse)res;
                http.setStatus(200);http.setHeader("X-Trace-Id",UUID.randomUUID().toString());http.setContentType("application/json");
                http.getOutputStream().write(("{\"call\":"+calls.incrementAndGet()+"}").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            });
            bodies.add(response.getContentAsString());
        }
        assertThat(calls.get()).isEqualTo(2);assertThat(bodies.get(0)).isNotEqualTo(bodies.get(1));assertThat(bodies.get(1)).isEqualTo(bodies.get(2));
        assertThat(db.queryForObject("select count(*) from api_idempotency_records where idempotency_key=?",Integer.class,key)).isEqualTo(2);
    }
    private HttpResponse<String> post(String path,String body,String idempotency,String key) throws Exception {
        var request=HttpRequest.newBuilder(URI.create("http://localhost:"+port+path)).header("Content-Type","application/json")
                .header("Idempotency-Key",idempotency).header("X-Contract-Reviewer-Key",key).POST(HttpRequest.BodyPublishers.ofString(body)).build();
        return HttpClient.newHttpClient().send(request,HttpResponse.BodyHandlers.ofString());
    }
    private Seed seed(String partition, boolean hidden, boolean hiddenParent) throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        AgentDto.Response agent = agents.create(new AgentDto.CreateRequest(
                "assurance-" + suffix, "Assurance Agent", "Release assurance integration test"
        ));
        ObjectNode manifest = (ObjectNode) json.readTree(
                getClass().getResourceAsStream("/fixtures/valid-release-manifest-v1.1.json")
        );
        ((ObjectNode) manifest.path("agent")).put("id", "assurance-" + suffix);
        ReleaseDto.Response release = releases.create(agent.id(), manifest, "test");
        releases.analyze(release.id(), "test");
        ReleaseDto.Response current = releases.find(release.id());

        UUID suiteId = UUID.randomUUID();
        UUID testCaseId = UUID.randomUUID();
        UUID runId = UUID.randomUUID();
        UUID caseRunId = UUID.randomUUID();
        UUID oracleId = UUID.randomUUID();
        UUID findingId = UUID.randomUUID();
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);

        db.update("""
                insert into test_suites
                    (id, workspace_id, suite_key, version, fixture_version, generation_config_json,
                     suite_hash, status, created_at, updated_at)
                values (?, ?, ?, '1.0.0', 'fixture-v1', '{}'::jsonb, ?, 'DRAFT', ?, ?)
                """, suiteId, AgentService.DEMO_WORKSPACE_ID, "assurance-suite-" + suffix,
                HASH_A, Timestamp.from(now), Timestamp.from(now));
        db.update("""
                insert into test_cases
                    (id, suite_id, case_key, case_type, partition_name, category, severity,
                     delivery_channel, target_tool, attack_goal, payload_hash, preconditions_json,
                     expected_invariant, oracle_type, generation_source, hidden_from_patch_generator,
                     expected_result_json, trial_policy_json, created_at, updated_at)
                values (?, ?, ?, 'ATTACK', ?, 'FA-02', 'CRITICAL', 'DOCUMENT',
                        'CUSTOMER_DATA_READ', 'cross customer read', ?, '{}'::jsonb, 'INV-01',
                        'CROSS_CUSTOMER', 'GOLDEN', ?, '{}'::jsonb, '{}'::jsonb, ?, ?)
                """, testCaseId, suiteId, "FA-02-" + suffix, partition, HASH_A, hidden,
                Timestamp.from(now), Timestamp.from(now));
        if(hiddenParent) {
            UUID parent=UUID.randomUUID();
            db.update("""
                insert into test_cases(id,suite_id,case_key,case_type,partition_name,category,severity,delivery_channel,
                payload_hash,preconditions_json,expected_invariant,oracle_type,generation_source,hidden_from_patch_generator,
                expected_result_json,trial_policy_json)
                values(?,?,'hidden-parent','ATTACK','HELD_OUT','FA-02','HIGH','DOCUMENT',?,'{}','INV-01','CROSS_CUSTOMER','GOLDEN',true,'{}','{}')
                """,parent,suiteId,HASH_A);
            db.update("update test_cases set parent_seed_id=? where id=?",parent,testCaseId);
        }
        db.update("update test_suites set status = 'READY', updated_at = ? where id = ?",
                Timestamp.from(now), suiteId);
        db.update("""
                insert into test_runs
                    (id, release_id, suite_id, mode, status, agent_artifact_fingerprint,
                     release_fingerprint, config_json, fixture_version, fixture_digest,
                     model_config_hash, total_cases, completed_cases, operational_error_count,
                     started_at, completed_at, summary_json, created_at, updated_at)
                values (?, ?, ?, 'BASELINE', 'QUEUED', ?, ?, '{}'::jsonb, 'fixture-v1', ?, ?,
                        1, 0, 0, null, null, '{}'::jsonb, ?, ?)
                """, runId, release.id(), suiteId, current.agentArtifactFingerprint(),
                current.releaseFingerprint(), HASH_A, HASH_A, Timestamp.from(now), Timestamp.from(now));
        db.update("""
                insert into test_case_runs
                    (id, test_run_id, test_case_id, trial_index, status, security_outcome,
                     variant_hash, started_at, completed_at, result_json, created_at, updated_at)
                values (?, ?, ?, 0, 'PENDING', null, ?, null, null, '{}'::jsonb, ?, ?)
                """, caseRunId, runId, testCaseId, HASH_A, Timestamp.from(now), Timestamp.from(now));
        db.update("""
                update test_case_runs
                   set status = 'FAILED_SECURITY', security_outcome = 'ATTACK_SUCCESS',
                       started_at = ?, completed_at = ?, updated_at = ?
                 where id = ?
                """, Timestamp.from(now.minusSeconds(1)), Timestamp.from(now), Timestamp.from(now), caseRunId);
        db.update("""
                insert into oracle_results
                    (id, test_case_run_id, oracle_type, oracle_version, outcome, reason_code,
                     invariant_id, evidence_json, evidence_digest, evaluated_at, created_at, updated_at)
                values (?, ?, 'CROSS_CUSTOMER', '1.0', 'ATTACK_SUCCESS',
                        'UNAUTHORIZED_RECORD_RETURNED', 'INV-01', '{}'::jsonb, ?, ?, ?, ?)
                """, oracleId, caseRunId, digest.sha256(canonical.canonicalize(json.createObjectNode())), Timestamp.from(now), Timestamp.from(now), Timestamp.from(now));
        db.update("""
                insert into findings
                    (id, release_id, source_oracle_result_id, category, severity, title, status,
                     violated_invariant, root_cause_json, first_seen_run_id, latest_seen_run_id,
                     created_at, updated_at)
                values (?, ?, ?, 'FA-02', 'CRITICAL', 'Unauthorized customer record returned', 'OPEN',
                        'INV-01', '{}'::jsonb, ?, ?, ?, ?)
                """, findingId, release.id(), oracleId, runId, runId,
                Timestamp.from(now), Timestamp.from(now));
        db.update("""
                update test_runs set status = 'PREPARING', updated_at = ? where id = ?
                """, Timestamp.from(now.minusSeconds(2)), runId);
        db.update("""
                update test_runs set status = 'RUNNING', started_at = ?, updated_at = ? where id = ?
                """, Timestamp.from(now.minusSeconds(1)), Timestamp.from(now.minusSeconds(1)), runId);
        db.update("insert into run_event_counters (run_id, last_sequence) values (?, 0)", runId);
        UUID traceId = UUID.randomUUID();
        eventService.append(runId, new ExecutionEventDto.AppendRequest(
                null, traceId, ExecutionEventType.RUN_STARTED,
                null, null, null, null, "RUN_STARTED", json.createObjectNode()
        ), "test");
        eventService.append(runId, new ExecutionEventDto.AppendRequest(
                null, traceId, ExecutionEventType.RUN_COMPLETED,
                null, null, null, null, "RUN_COMPLETED", json.createObjectNode()
        ), "test");
        db.update("""
                update test_runs
                   set status = 'COMPLETED', completed_cases = 1, started_at = ?, completed_at = ?, updated_at = ?
                 where id = ?
                """, Timestamp.from(now.minusSeconds(1)), Timestamp.from(now), Timestamp.from(now), runId);
        db.update("""
                update agent_releases set lifecycle_state = 'TESTING', effective_status = 'TESTING'
                 where id = ?
                """, release.id());
        return new Seed(release.id(),findingId,oracleId);
    }

    private record Seed(UUID releaseId,UUID findingId,UUID oracleId) {}
}
