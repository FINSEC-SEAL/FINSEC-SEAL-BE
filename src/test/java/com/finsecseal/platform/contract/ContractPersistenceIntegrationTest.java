package com.finsecseal.platform.contract;

import static org.assertj.core.api.Assertions.*;
import com.finsecseal.agent.*;
import com.finsecseal.release.*;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import java.net.URI;
import java.net.http.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.junit.jupiter.*;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.*;
import tools.jackson.databind.node.ObjectNode;

@Testcontainers
@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT,properties={
    "finsec.crypto.key-base64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","finsec.scheduling.enabled=false",
    "finsec.cors.allowed-origins=http://localhost:5173",
    "finsec.contract-access.key=test-reviewer-key-at-least-32-bytes-long",
    "finsec.contract-access.actor=contract-integration-reviewer",
    "finsec.contract-access.workspace=0198f1e2-0000-7000-8000-000000000001"
})
class ContractPersistenceIntegrationTest {
    @Container @ServiceConnection static final PostgreSQLContainer POSTGRES=new PostgreSQLContainer("postgres:17.11-alpine");
    @Autowired AgentService agents;
    @Autowired ReleaseService releases;
    @Autowired ContractPersistenceService service;
    @Autowired ObjectMapper json;
    @Autowired JdbcTemplate db;
    @LocalServerPort int port;
    private static final String KEY="test-reviewer-key-at-least-32-bytes-long";
    private final ReviewerContext reviewer=new ReviewerContext(AgentService.DEMO_WORKSPACE_ID,"contract-integration-reviewer",
        "AI_SECURITY_REVIEWER","test-session",true,true,false);
    private UUID release() throws Exception {
        String key="contract-"+UUID.randomUUID();
        var a=agents.create(new AgentDto.CreateRequest(key,"Contract test","Document review"));
        ObjectNode manifest=(ObjectNode)fixture("valid-release-manifest-v1.1.json");
        ((ObjectNode)manifest.get("agent")).put("id",key);
        var release=releases.create(a.id(),manifest,"contract-integration-reviewer");
        releases.analyze(release.id(),"contract-integration-reviewer");
        return release.id();
    }
    private JsonNode fixture(String name) throws Exception {return json.readTree(getClass().getResourceAsStream("/fixtures/"+name));}
    private String etag(ContractPersistenceService.Version v) {return '"'+v.resourceHash()+'"';}
    @Test void validatesApprovesAndBindsReleaseWithImmutableEvidence() throws Exception {
        UUID release=release();
        db.update("update agent_releases set lifecycle_state='REMEDIATION',effective_status='REMEDIATION' where id=?",release);
        String before=releases.find(release).releaseFingerprint();
        var candidate=service.create(release,fixture("loan-review-safety-contract.json"),reviewer);
        var validated=service.validate(candidate.id(),etag(candidate),reviewer);
        assertThat(validated.state()).isEqualTo("VALIDATED");
        assertThat(validated.resourceHash()).isNotEqualTo(candidate.resourceHash());
        assertThatThrownBy(()->service.approve(candidate.id(),etag(candidate),"reviewed",reviewer)).hasMessageContaining("Stale");
        var approved=service.approve(candidate.id(),etag(validated),"Reviewed scope and regression impact",reviewer);
        assertThat(approved.state()).isEqualTo("APPROVED");
        assertThat(releases.find(release).releaseFingerprint()).isNotEqualTo(before);
        assertThat(service.approved(release,approved.id(),reviewer).version()).isEqualTo(approved);
        assertThat(db.queryForObject("select count(*) from audit_records where resource_id=?",Integer.class,approved.id())).isEqualTo(3);
        assertThatThrownBy(()->db.update("update safety_contract_versions set state='REJECTED' where id=?",approved.id())).hasMessageContaining("immutable");
        assertThatThrownBy(()->db.update("update contract_version_evidence set review_json='{}' where version_id=?",approved.id())).hasMessageContaining("immutable");
        assertThatThrownBy(()->service.reject(approved.id(),etag(approved),"reject",reviewer)).isInstanceOf(RuntimeException.class);
    }
    @Test void validationFailureDoesNotApproveAndRejectionRemainsPossible() throws Exception {
        UUID release=release();ObjectNode policy=(ObjectNode)fixture("loan-review-safety-contract.json");
        ((tools.jackson.databind.node.ArrayNode)policy.at("/fieldPolicy/CUSTOMER_DATA_READ/allowed")).add("accountNumber");
        var v=service.create(release,policy,reviewer);v=service.validate(v.id(),etag(v),reviewer);
        assertThat(v.state()).isEqualTo("CANDIDATE");
        var candidate=v;
        assertThatThrownBy(()->service.approve(candidate.id(),etag(candidate),"approve",reviewer)).isInstanceOf(RuntimeException.class);
        assertThat(service.reject(v.id(),etag(v),"Excessive fields",reviewer).state()).isEqualTo("REJECTED");
        assertThat(releases.find(release).safetyContractHash()).isNull();
    }
    @Test void rejectsForeignWorkspaceAndTamperedPolicy() throws Exception {
        UUID release=release();var v=service.create(release,fixture("loan-review-safety-contract.json"),reviewer);
        var foreign=new ReviewerContext(UUID.randomUUID(),reviewer.actorId(),reviewer.role(),"s",true,true,false);
        assertThatThrownBy(()->service.find(v.id(),foreign)).hasMessageContaining("workspace");
        db.update("update safety_contract_versions set policy_hash=? where id=?","sha256:"+"a".repeat(64),v.id());
        assertThatThrownBy(()->service.find(v.id(),reviewer)).hasMessageContaining("integrity");
    }
    @Test void authenticatesBeforeIdempotencyAndReplaysExactCandidate() throws Exception {
        UUID release=release();String path="/api/v1/platform/contracts";String key=UUID.randomUUID().toString();
        String body=json.createObjectNode().put("releaseId",release.toString()).set("policy",fixture("loan-review-safety-contract.json")).toString();
        var bad=post(path,body,key,"wrong",null);assertThat(bad.statusCode()).isEqualTo(403);
        assertThat(db.queryForObject("select count(*) from api_idempotency_records where idempotency_key=?",Integer.class,key)).isZero();
        var first=post(path,body,key,KEY,null);assertThat(first.statusCode()).withFailMessage(first.body()).isEqualTo(201);
        var replay=post(path,body,key,KEY,null);assertThat(replay.statusCode()).isEqualTo(201);assertThat(replay.body()).isEqualTo(first.body());
        assertThat(post(path,body,key,KEY,"forged-actor").statusCode()).isEqualTo(403);
    }
    @Test void competingApprovalsCommitExactlyOnce() throws Exception {
        UUID release=release();
        db.update("update agent_releases set lifecycle_state='REMEDIATION',effective_status='REMEDIATION' where id=?",release);
        var candidate=service.create(release,fixture("loan-review-safety-contract.json"),reviewer);
        var v=service.validate(candidate.id(),etag(candidate),reviewer);
        try(var pool=java.util.concurrent.Executors.newFixedThreadPool(2)) {
            var gate=new java.util.concurrent.CountDownLatch(1);
            java.util.concurrent.Callable<Boolean> attempt=()->{gate.await();try{service.approve(v.id(),etag(v),"reviewed",reviewer);return true;}catch(RuntimeException e){return false;}};
            var a=pool.submit(attempt);var b=pool.submit(attempt);gate.countDown();
            assertThat(java.util.List.of(a.get(),b.get())).containsExactlyInAnyOrder(true,false);
        }
        assertThat(db.queryForObject("select count(*) from audit_records where resource_id=? and action='CONTRACT_APPROVED'",Integer.class,v.id())).isEqualTo(1);
    }
    @Test void preservesStateWhenReleaseIsNotReadyForApproval() throws Exception {
        UUID release=release();var c=service.create(release,fixture("loan-review-safety-contract.json"),reviewer);
        var v=service.validate(c.id(),etag(c),reviewer);
        assertThatThrownBy(()->service.approve(v.id(),etag(v),"review",reviewer)).hasMessageContaining("REMEDIATION");
        assertThat(service.find(v.id(),reviewer).state()).isEqualTo("VALIDATED");
        assertThat(releases.find(release).safetyContractHash()).isNull();
    }
    @Test void allowsOnlyConfiguredOriginPreflightWithoutAuthenticatingActualRequests() throws Exception {
        for (String origin : List.of("http://localhost:5173", "https://untrusted.invalid")) {
            var request=HttpRequest.newBuilder(URI.create("http://localhost:"+port+"/api/v1/platform/contracts"))
                    .header("Origin",origin).header("Access-Control-Request-Method","POST")
                    .header("Access-Control-Request-Headers","X-Contract-Reviewer-Key,Idempotency-Key,If-Match,Content-Type")
                    .method("OPTIONS",HttpRequest.BodyPublishers.noBody()).build();
            var response=HttpClient.newHttpClient().send(request,HttpResponse.BodyHandlers.ofString());
            assertThat(response.statusCode()).isEqualTo(origin.contains("localhost")?200:403);
            if(response.statusCode()==200)
                assertThat(response.headers().firstValue("Access-Control-Allow-Origin")).contains(origin);
        }
        var unauthenticated=HttpRequest.newBuilder(URI.create("http://localhost:"+port+"/api/v1/platform/contracts?releaseId="+UUID.randomUUID()))
                .header("Origin","http://localhost:5173").GET().build();
        assertThat(HttpClient.newHttpClient().send(unauthenticated,HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(403);
    }
    @Test void specificationPathsReturnValidationResultAndContractScopedHistory() throws Exception {
        UUID release=release();
        db.update("update agent_releases set lifecycle_state='REMEDIATION',effective_status='REMEDIATION' where id=?", release);
        var first=service.create(release,fixture("loan-review-safety-contract.json"),reviewer);
        var second=service.create(release,((ObjectNode)fixture("loan-review-safety-contract.json")).put("version",2),reviewer);
        String path="/api/v1/contract-versions/"+second.id();
        var detail=api("GET",path,null,Map.of("X-Contract-Reviewer-Key",KEY));
        assertThat(detail.statusCode()).isEqualTo(200);
        var value=json.readTree(detail.body()).path("data");
        String contract=value.path("contractId").stringValue();
        assertThat(value.path("diff").isArray()).isTrue();
        assertThat(detail.headers().firstValue("ETag")).contains(etag(second));
        var page=api("GET","/api/v1/contracts/"+contract+"/versions?limit=1",null,Map.of("X-Contract-Reviewer-Key",KEY));
        var history=json.readTree(page.body()).path("data");
        assertThat(history.path("items").size()).isEqualTo(1);
        assertThat(history.at("/items/0/id").stringValue()).isEqualTo(first.id().toString());
        var next=api("GET","/api/v1/contracts/"+contract+"/versions?limit=1&cursor="+history.path("nextCursor").stringValue(),null,Map.of("X-Contract-Reviewer-Key",KEY));
        assertThat(json.readTree(next.body()).at("/data/items/0/id").stringValue()).isEqualTo(second.id().toString());
        assertThat(json.readTree(next.body()).at("/data/nextCursor").isNull()).isTrue();
        assertThat(api("GET","/api/v1/contracts/"+second.id()+"/versions",null,Map.of("X-Contract-Reviewer-Key",KEY)).statusCode()).isEqualTo(404);
        assertThat(api("GET","/api/v1/contracts/"+contract+"/versions?limit=101",null,Map.of("X-Contract-Reviewer-Key",KEY)).statusCode()).isEqualTo(400);
        assertThat(api("GET","/api/v1/contracts/"+contract+"/versions?cursor=invalid",null,Map.of("X-Contract-Reviewer-Key",KEY)).statusCode()).isEqualTo(400);
        var headers=Map.of("X-Contract-Reviewer-Key",KEY,"If-Match",etag(second));
        assertThat(api("POST",path+":validate","{\"role\":\"AI_SECURITY_REVIEWER\"}",headers).statusCode()).isEqualTo(400);
        var validated=api("POST",path+":validate","{}",headers);
        assertThat(validated.statusCode()).withFailMessage(validated.body()).isEqualTo(200);
        var result=json.readTree(validated.body()).path("data");
        assertThat(result.path("status").stringValue()).isEqualTo("VALID");
        assertThat(result.path("state").stringValue()).isEqualTo("VALIDATED");
        assertThat(result.path("issues").isArray()).isTrue();
        String match='"'+result.path("resourceHash").stringValue()+'"';
        assertThat(api("POST",path+":approve","{\"comment\":\"review\"}",headers).statusCode()).isEqualTo(409);
        var approved=api("POST",path+":approve","{\"comment\":\"review\",\"patchProposalId\":null}",Map.of("X-Contract-Reviewer-Key",KEY,"If-Match",match));
        assertThat(approved.statusCode()).withFailMessage(approved.body()).isEqualTo(200);
        assertThat(json.readTree(approved.body()).at("/data/state").stringValue()).isEqualTo("APPROVED");
        assertThat(api("GET",path+"/approved?releaseId="+release,null,Map.of("X-Contract-Reviewer-Key",KEY)).statusCode()).isEqualTo(200);
    }

    @Test void unknownPatchOrReviewFieldsCannotSilentlyApprove() throws Exception {
        UUID release=release();
        db.update("update agent_releases set lifecycle_state='REMEDIATION',effective_status='REMEDIATION' where id=?",release);
        var c=service.create(release,fixture("loan-review-safety-contract.json"),reviewer);
        var v=service.validate(c.id(),etag(c),reviewer);
        var headers=Map.of("X-Contract-Reviewer-Key",KEY,"If-Match",etag(v));
        String path="/api/v1/contract-versions/"+v.id()+":approve";
        assertThat(api("POST",path,"{\"comment\":\"review\",\"patchProposalId\":\""+UUID.randomUUID()+"\"}",headers).statusCode()).isEqualTo(404);
        assertThat(api("POST",path,"{\"comment\":\"review\",\"role\":\"AI_SECURITY_REVIEWER\"}",headers).statusCode()).isEqualTo(400);
        assertThat(service.find(v.id(),reviewer).state()).isEqualTo("VALIDATED");
    }

    @Test void reviewerSessionRequiresTrustedIssuanceAndCsrfBeforeIdempotency() throws Exception {
        assertThat(api("GET","/api/v1/reviewer-session",null,Map.of()).statusCode()).isEqualTo(403);
        assertThat(api("GET","/api/v1/%72eviewer-session",null,Map.of()).statusCode()).isEqualTo(400);
        assertThat(api("GET","/api/v1/contract-versions/"+UUID.randomUUID(),null,Map.of()).statusCode()).isEqualTo(403);
        var issued=api("GET","/api/v1/reviewer-session",null,Map.of("X-Contract-Reviewer-Key",KEY));
        assertThat(issued.statusCode()).isEqualTo(200);
        String cookieHeader=issued.headers().firstValue("Set-Cookie").orElseThrow();
        assertThat(cookieHeader).contains("HttpOnly","Secure","SameSite=Lax","Path=/");
        String cookie=cookieHeader.split(";",2)[0];
        String csrf=json.readTree(issued.body()).at("/data/csrfToken").stringValue();
        var c=service.create(release(),fixture("loan-review-safety-contract.json"),reviewer);
        String path="/api/v1/contract-versions/"+c.id();
        assertThat(api("GET",path,null,Map.of("Cookie",cookie)).statusCode()).isEqualTo(200);
        assertThat(api("GET",path,null,Map.of("Cookie",cookie+"x")).statusCode()).isEqualTo(403);
        String idem=UUID.randomUUID().toString();
        assertThat(api("POST",path+":validate","{}",Map.of("Cookie",cookie,"If-Match",etag(c),"Idempotency-Key",idem)).statusCode()).isEqualTo(403);
        assertThat(db.queryForObject("select count(*) from api_idempotency_records where idempotency_key=?",Integer.class,idem)).isZero();
        assertThat(api("POST",path+":validate","{}",Map.of("Cookie",cookie,"If-Match",etag(c),"X-Contract-Reviewer-Key",KEY)).statusCode()).isEqualTo(403);
        var validated=api("POST",path+":validate","{}",Map.of("Cookie",cookie,"If-Match",etag(c),"Idempotency-Key",idem,"X-CSRF-Token",csrf));
        assertThat(validated.statusCode()).withFailMessage(validated.body()).isEqualTo(200);
        assertThat(api("POST",path+":validate","{}",Map.of("Cookie",cookie,"If-Match",etag(c),"Idempotency-Key",idem,"X-CSRF-Token","wrong")).statusCode()).isEqualTo(403);
        var restored=api("GET","/api/v1/reviewer-session",null,Map.of("Cookie",cookie));
        assertThat(json.readTree(restored.body()).at("/data/csrfToken").stringValue()).isEqualTo(csrf);
    }

    @Test void revokesOnlyTheCurrentSignedSessionAndClearsCookieOnIdempotentRetries() throws Exception {
        var issued = api("GET", "/api/v1/reviewer-session", null, Map.of("X-Contract-Reviewer-Key", KEY));
        assertThat(issued.statusCode()).isEqualTo(200);
        var data = json.readTree(issued.body()).path("data");
        String sessionId = data.path("sessionId").stringValue();
        String csrf = data.path("csrfToken").stringValue();
        String cookie = issued.headers().firstValue("Set-Cookie").orElseThrow().split(";", 2)[0];
        String path = "/api/v1/reviewer-session/" + sessionId;
        var second = api("GET", "/api/v1/reviewer-session", null, Map.of("X-Contract-Reviewer-Key", KEY));
        String secondCookie = second.headers().firstValue("Set-Cookie").orElseThrow().split(";", 2)[0];
        String secondId = json.readTree(second.body()).at("/data/sessionId").stringValue();
        assertThat(secondId).isNotEqualTo(sessionId);
        String retryKey = UUID.randomUUID().toString();
        var headers = Map.of("Cookie", cookie, "X-CSRF-Token", csrf, "Idempotency-Key", retryKey);

        assertThat(api("DELETE", path, null, Map.of("Cookie", cookie, "Idempotency-Key", retryKey)).statusCode())
                .isEqualTo(403);
        assertThat(api("DELETE", path, null, Map.of("Cookie", cookie, "X-CSRF-Token", "wrong",
                "Idempotency-Key", retryKey)).statusCode()).isEqualTo(403);
        assertThat(api("DELETE", "/api/v1/reviewer-session/" + UUID.randomUUID(), null, headers).statusCode())
                .isEqualTo(403);
        assertThat(api("DELETE", path, null, Map.of("X-Contract-Reviewer-Key", KEY,
                "Idempotency-Key", retryKey)).statusCode()).isEqualTo(403);
        assertThat(db.queryForObject("select count(*) from reviewer_session_revocations", Integer.class)).isZero();
        assertThat(db.queryForObject("select count(*) from api_idempotency_records where idempotency_key=?",
                Integer.class, retryKey)).isZero();

        var first = api("DELETE", path, null, headers);
        assertThat(first.statusCode()).withFailMessage(first.body()).isEqualTo(204);
        assertThat(first.headers().firstValue("Set-Cookie")).hasValueSatisfying(value ->
                assertThat(value).contains(ContractReviewerCredentials.COOKIE + "=", "Max-Age=0", "HttpOnly",
                        "Secure", "SameSite=Lax", "Path=/"));
        assertThat(db.queryForObject("select count(*) from reviewer_session_revocations", Integer.class)).isEqualTo(1);
        String storedDigest = db.queryForObject("select session_digest from reviewer_session_revocations", String.class);
        assertThat(storedDigest).matches("sha256:[0-9a-f]{64}").doesNotContain(sessionId, csrf, cookie);
        assertThat(api("GET", "/api/v1/reviewer-session", null, Map.of("Cookie", cookie)).statusCode())
                .isEqualTo(403);
        assertThat(api("GET", "/api/v1/contract-versions/" + UUID.randomUUID(), null,
                Map.of("Cookie", cookie)).statusCode()).isEqualTo(403);
        assertThat(api("GET", "/api/v1/contract-versions/" + UUID.randomUUID(), null,
                Map.of("Cookie", cookie, "X-Contract-Reviewer-Key", KEY)).statusCode()).isEqualTo(403);
        assertThat(api("GET", "/api/v1/contract-versions/" + UUID.randomUUID(), null,
                Map.of("Cookie", cookie + "x", "X-Contract-Reviewer-Key", KEY)).statusCode()).isEqualTo(403);
        var stillActive = api("GET", "/api/v1/reviewer-session", null, Map.of("Cookie", secondCookie));
        assertThat(stillActive.statusCode()).isEqualTo(200);
        assertThat(json.readTree(stillActive.body()).at("/data/sessionId").stringValue()).isEqualTo(secondId);

        var replay = api("DELETE", path, null, headers);
        assertThat(replay.statusCode()).isEqualTo(204);
        assertThat(replay.headers().firstValue("Idempotent-Replayed")).contains("true");
        assertThat(replay.headers().firstValue("Set-Cookie")).hasValueSatisfying(value ->
                assertThat(value).contains("Max-Age=0"));
        var newKeyRetry = api("DELETE", path, null, Map.of("Cookie", cookie, "X-CSRF-Token", csrf,
                "Idempotency-Key", UUID.randomUUID().toString()));
        assertThat(newKeyRetry.statusCode()).isEqualTo(204);
        assertThat(newKeyRetry.headers().firstValue("Set-Cookie")).hasValueSatisfying(value ->
                assertThat(value).contains("Max-Age=0"));
        assertThat(db.queryForObject("select count(*) from reviewer_session_revocations", Integer.class)).isEqualTo(1);

        var recovered = api("GET", "/api/v1/reviewer-session", null,
                Map.of("Cookie", cookie, "X-Contract-Reviewer-Key", KEY));
        assertThat(recovered.statusCode()).isEqualTo(200);
        assertThat(json.readTree(recovered.body()).at("/data/sessionId").stringValue()).isNotEqualTo(sessionId);
        assertThat(recovered.headers().firstValue("Set-Cookie")).isPresent();
        assertThat(api("GET", "/api/v1/reviewer-session", null,
                Map.of("Cookie", cookie + "x", "X-Contract-Reviewer-Key", KEY)).statusCode()).isEqualTo(200);
    }

    @Test void proposalRejectionRequiresTrustedReviewerBeforeIdempotencyReservation() throws Exception {
        UUID proposalId=UUID.randomUUID();
        String path="/api/v1/patch-proposals/"+proposalId+":reject";
        String body="{\"comment\":\"review\"}";
        String key=UUID.randomUUID().toString();
        assertThat(post(path,body,key,"wrong",null).statusCode()).isEqualTo(403);
        assertThat(post(path,body,key,KEY,"forged-actor").statusCode()).isEqualTo(403);
        assertThat(post("/api/v1/%70atch-proposals/"+proposalId+":reject",body,key,KEY,null).statusCode()).isEqualTo(400);
        assertThat(post("/api/v1/patch-proposals/"+proposalId+";bad:reject",body,key,KEY,null).statusCode()).isEqualTo(400);
        assertThat(db.queryForObject("select count(*) from api_idempotency_records where idempotency_key=?",Integer.class,key)).isZero();

        var issued=api("GET","/api/v1/reviewer-session",null,Map.of("X-Contract-Reviewer-Key",KEY));
        String cookie=issued.headers().firstValue("Set-Cookie").orElseThrow().split(";",2)[0];
        String csrf=json.readTree(issued.body()).at("/data/csrfToken").stringValue();
        assertThat(api("POST",path,body,Map.of("Cookie",cookie,"Idempotency-Key",key)).statusCode()).isEqualTo(403);
        assertThat(api("POST",path,body,Map.of("Cookie",cookie,"X-CSRF-Token","wrong","Idempotency-Key",key)).statusCode()).isEqualTo(403);
        assertThat(api("POST",path,body,Map.of("Cookie",expiredReviewerCookie(),"X-CSRF-Token",csrf,
                "Idempotency-Key",key)).statusCode()).isEqualTo(403);
        assertThat(db.queryForObject("select count(*) from api_idempotency_records where idempotency_key=?",Integer.class,key)).isZero();
        String sessionId=json.readTree(issued.body()).at("/data/sessionId").stringValue();
        assertThat(api("DELETE","/api/v1/reviewer-session/"+sessionId,null,
                Map.of("Cookie",cookie,"X-CSRF-Token",csrf,"Idempotency-Key",UUID.randomUUID().toString())).statusCode()).isEqualTo(204);
        assertThat(api("POST",path,body,Map.of("Cookie",cookie,"X-CSRF-Token",csrf,"Idempotency-Key",key)).statusCode()).isEqualTo(403);
        assertThat(db.queryForObject("select count(*) from api_idempotency_records where idempotency_key=?",Integer.class,key)).isZero();
    }

    @Test void proposalRejectionReturnsBoundedStateAndReplaysOnlyTheSameAuthorizedRequest() throws Exception {
        UUID proposalId=pendingProposal();
        String path="/api/v1/patch-proposals/"+proposalId+":reject";
        String body="{\"comment\":\"Reviewed patch risk\"}";
        String key=UUID.randomUUID().toString();
        var headers=Map.of("X-Contract-Reviewer-Key",KEY,"Idempotency-Key",key);
        var first=api("POST",path,body,headers);
        assertThat(first.statusCode()).withFailMessage(first.body()).isEqualTo(200);
        var value=json.readTree(first.body()).path("data");
        assertThat(value.properties().stream().map(Map.Entry::getKey).toList())
                .containsExactlyInAnyOrder("id","findingId","baseContractVersionId","state","decidedAt");
        assertThat(value.path("id").stringValue()).isEqualTo(proposalId.toString());
        assertThat(value.path("state").stringValue()).isEqualTo("REJECTED");
        assertThat(first.body()).doesNotContain("Reviewed patch risk","recommendedRule","policyDiff","validation");
        var replay=api("POST",path,body,headers);
        assertThat(replay.statusCode()).isEqualTo(200);
        assertThat(replay.body()).isEqualTo(first.body());
        assertThat(replay.headers().firstValue("Idempotent-Replayed")).contains("true");
        assertThat(db.queryForObject("select count(*) from patch_approvals where patch_proposal_id=?",Integer.class,proposalId)).isEqualTo(1);
        assertThat(api("POST",path,"{\"comment\":\"other\"}",headers).statusCode()).isEqualTo(409);
        assertThat(api("POST",path,body,Map.of("X-Contract-Reviewer-Key",KEY,
                "Idempotency-Key",UUID.randomUUID().toString())).statusCode()).isEqualTo(409);
        assertThat(api("POST","/api/v1/patch-proposals/"+UUID.randomUUID()+":reject",body,
                Map.of("X-Contract-Reviewer-Key",KEY)).statusCode()).isEqualTo(404);
        var missingKey=HttpRequest.newBuilder(URI.create("http://localhost:"+port+path))
                .header("Content-Type","application/json").header("X-Contract-Reviewer-Key",KEY)
                .POST(HttpRequest.BodyPublishers.ofString(body)).build();
        assertThat(HttpClient.newHttpClient().send(missingKey,HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(400);
        for(String invalid:List.of("{}","{\"comment\":\"review\",\"role\":\"AI_SECURITY_REVIEWER\"}",
                "{\"comment\":\"review\",\"workspaceId\":\""+reviewer.workspaceId()+"\"}","{\"comment\":\"  \"}")) {
            assertThat(api("POST",path,invalid,Map.of("X-Contract-Reviewer-Key",KEY)).statusCode()).isEqualTo(400);
        }

        UUID cookieProposal=pendingProposal();
        var issued=api("GET","/api/v1/reviewer-session",null,Map.of("X-Contract-Reviewer-Key",KEY));
        String cookie=issued.headers().firstValue("Set-Cookie").orElseThrow().split(";",2)[0];
        String csrf=json.readTree(issued.body()).at("/data/csrfToken").stringValue();
        var cookieResult=api("POST","/api/v1/patch-proposals/"+cookieProposal+":reject",body,
                Map.of("Cookie",cookie,"X-CSRF-Token",csrf,"Idempotency-Key",UUID.randomUUID().toString()));
        assertThat(cookieResult.statusCode()).withFailMessage(cookieResult.body()).isEqualTo(200);
        assertThat(json.readTree(cookieResult.body()).at("/data/id").stringValue()).isEqualTo(cookieProposal.toString());
    }

    @Test void proposalDetailRouteRequiresReviewerAndHidesCorruptStoredNarrative() throws Exception {
        UUID proposalId=pendingProposal();
        String path="/api/v1/patch-proposals/"+proposalId;
        assertThat(api("GET",path,null,Map.of()).statusCode()).isEqualTo(403);
        assertThat(api("GET",path,null,Map.of("X-Contract-Reviewer-Key","wrong")).statusCode()).isEqualTo(403);
        assertThat(api("GET",path,null,Map.of("X-Contract-Reviewer-Key",KEY,"X-Actor-Id","forged")).statusCode()).isEqualTo(403);
        assertThat(api("GET",path,null,Map.of("Cookie",expiredReviewerCookie())).statusCode()).isEqualTo(403);
        assertThat(api("GET","/api/v1/%70atch-proposals/"+proposalId,null,
                Map.of("X-Contract-Reviewer-Key",KEY)).statusCode()).isEqualTo(400);
        assertThat(api("GET",path+";bad",null,Map.of("X-Contract-Reviewer-Key",KEY)).statusCode()).isEqualTo(400);
        assertThat(api("GET","/api/v1/patch-proposals/not-a-uuid",null,
                Map.of("X-Contract-Reviewer-Key",KEY)).statusCode()).isEqualTo(400);
        assertThat(api("GET","/api/v1/patch-proposals/"+UUID.randomUUID(),null,
                Map.of("X-Contract-Reviewer-Key",KEY)).statusCode()).isEqualTo(404);

        // This #91 fixture intentionally has no accepted C proof; its reviewer-visible failure is fixed.
        var invalid=api("GET",path,null,Map.of("X-Contract-Reviewer-Key",KEY));
        assertThat(invalid.statusCode()).withFailMessage(invalid.body()).isEqualTo(409);
        assertThat(json.readTree(invalid.body()).path("code").stringValue()).isEqualTo("EVIDENCE_INCOMPLETE");
        assertThat(invalid.body()).contains("Patch proposal integrity check failed")
                .doesNotContain("Excessive scope","recommended_rule_json","patch_proposals","select p.");

        var issued=api("GET","/api/v1/reviewer-session",null,Map.of("X-Contract-Reviewer-Key",KEY));
        String cookie=issued.headers().firstValue("Set-Cookie").orElseThrow().split(";",2)[0];
        String csrf=json.readTree(issued.body()).at("/data/csrfToken").stringValue();
        assertThat(api("GET",path,null,Map.of("Cookie",cookie)).statusCode()).isEqualTo(409);
        String sessionId=json.readTree(issued.body()).at("/data/sessionId").stringValue();
        assertThat(api("DELETE","/api/v1/reviewer-session/"+sessionId,null,
                Map.of("Cookie",cookie,"X-CSRF-Token",csrf,"Idempotency-Key",UUID.randomUUID().toString())).statusCode()).isEqualTo(204);
        assertThat(api("GET",path,null,Map.of("Cookie",cookie)).statusCode()).isEqualTo(403);
    }

    private UUID pendingProposal() throws Exception {
        UUID releaseId=release();
        var base=service.create(releaseId,fixture("loan-review-safety-contract.json"),reviewer);
        var release=releases.find(releaseId);
        String hash="sha256:"+"a".repeat(64);
        UUID suite=UUID.randomUUID(),testCase=UUID.randomUUID(),run=UUID.randomUUID();
        UUID caseRun=UUID.randomUUID(),oracle=UUID.randomUUID(),finding=UUID.randomUUID(),proposal=UUID.randomUUID();
        String suffix=UUID.randomUUID().toString().substring(0,8);
        db.update("""
            insert into test_suites(id,workspace_id,suite_key,version,fixture_version,generation_config_json,suite_hash,status)
            values(?,?,?,'1.0','fixture-v1','{}',?,'DRAFT')
            """,suite,reviewer.workspaceId(),"patch-http-"+suffix,hash);
        db.update("""
            insert into test_cases(id,suite_id,case_key,case_type,partition_name,category,severity,delivery_channel,
                target_tool,attack_goal,payload_hash,preconditions_json,expected_invariant,oracle_type,generation_source,
                hidden_from_patch_generator,expected_result_json,trial_policy_json)
            values(?,?,'FA-02','ATTACK','SEED','FA-02','CRITICAL','DOCUMENT','CUSTOMER_DATA_READ','cross customer read',
                ?,'{}','INV-01','CROSS_CUSTOMER','GOLDEN',false,'{}','{}')
            """,testCase,suite,hash);
        db.update("update test_suites set status='READY' where id=?",suite);
        db.update("""
            insert into test_runs(id,release_id,suite_id,mode,status,agent_artifact_fingerprint,release_fingerprint,
                config_json,fixture_version,fixture_digest,model_config_hash,total_cases)
            values(?,?,?,'BASELINE','RUNNING',?,?,'{}','fixture-v1',?,?,1)
            """,run,releaseId,suite,release.agentArtifactFingerprint(),release.releaseFingerprint(),hash,hash);
        db.update("""
            insert into test_case_runs(id,test_run_id,test_case_id,trial_index,status,security_outcome,variant_hash,
                started_at,completed_at,result_json)
            values(?,?,?,0,'FAILED_SECURITY','ATTACK_SUCCESS',?,now(),now(),'{}')
            """,caseRun,run,testCase,hash);
        db.update("""
            insert into oracle_results(id,test_case_run_id,oracle_type,oracle_version,outcome,reason_code,invariant_id,
                evidence_json,evidence_digest,evaluated_at)
            values(?,?,'CROSS_CUSTOMER','1.0','ATTACK_SUCCESS','UNAUTHORIZED_RECORD_RETURNED','INV-01','{}',?,now())
            """,oracle,caseRun,hash);
        db.update("""
            insert into findings(id,release_id,source_oracle_result_id,category,severity,title,status,violated_invariant,
                root_cause_json,first_seen_run_id,latest_seen_run_id)
            values(?,?,?,'FA-02','CRITICAL','Unauthorized customer record returned','OPEN','INV-01','{}',?,?)
            """,finding,releaseId,oracle,run,run);
        db.update("""
            insert into patch_proposals(id,finding_id,base_contract_version_id,state,root_cause,recommended_rule_json,
                policy_diff_json,normal_workflow_impact_json,rollback_json,generation_model_meta_json,validation_json)
            values(?,?,?,'PROPOSED','Excessive scope','{}','[]','{}','{}','{}','{}')
            """,proposal,finding,base.id());
        return proposal;
    }

    private String expiredReviewerCookie() {
        try {
            var payload=json.createObjectNode().put("sessionId",UUID.randomUUID().toString()).put("csrf","expired")
                    .put("expires",java.time.Instant.now().minusSeconds(60).getEpochSecond())
                    .put("actor",reviewer.actorId()).put("workspace",reviewer.workspaceId().toString());
            String encoded=Base64.getUrlEncoder().withoutPadding().encodeToString(json.writeValueAsBytes(payload));
            var mac=javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(KEY.getBytes(java.nio.charset.StandardCharsets.UTF_8),"HmacSHA256"));
            String signature=Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(
                    ("FINSEC_REVIEWER_SESSION_V1:"+encoded).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            return ContractReviewerCredentials.COOKIE+"="+encoded+"."+signature;
        } catch (java.security.GeneralSecurityException exception) {throw new IllegalStateException(exception);}
    }

    private HttpResponse<String> api(String method,String path,String body,Map<String,String> headers) throws Exception {
        var builder=HttpRequest.newBuilder(URI.create("http://localhost:"+port+path));
        headers.forEach(builder::header);
        if(body!=null) {
            builder.header("Content-Type","application/json");
            if(!headers.containsKey("Idempotency-Key")) builder.header("Idempotency-Key",UUID.randomUUID().toString());
        }
        builder.method(method,body==null?HttpRequest.BodyPublishers.noBody():HttpRequest.BodyPublishers.ofString(body));
        return HttpClient.newHttpClient().send(builder.build(),HttpResponse.BodyHandlers.ofString());
    }
    private HttpResponse<String> post(String path,String body,String idem,String token,String actor) throws Exception {
        var b=HttpRequest.newBuilder(URI.create("http://localhost:"+port+path)).header("Content-Type","application/json")
            .header("Idempotency-Key",idem).header("X-Contract-Reviewer-Key",token).POST(HttpRequest.BodyPublishers.ofString(body));
        if(actor!=null)b.header("X-Actor-Id",actor);
        return HttpClient.newHttpClient().send(b.build(),HttpResponse.BodyHandlers.ofString());
    }
}
