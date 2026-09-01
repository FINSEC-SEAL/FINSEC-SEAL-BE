package com.finsecseal.common.api;

import com.finsecseal.agent.AgentService;
import com.finsecseal.audit.AuditService;
import com.finsecseal.common.persistence.UuidV7;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Service
public class IdempotencyRecoveryService {

    private static final int MAX_RECOVERED_RESPONSE_BYTES = 1024 * 1024;

    private final JdbcTemplate jdbcTemplate;
    private final DigestService digestService;
    private final AuditService auditService;
    private final ObjectMapper objectMapper;
    private final CanonicalJsonService canonicalJsonService;
    private final OperatorRecoveryCredentialVerifier credentialVerifier;

    public IdempotencyRecoveryService(
            JdbcTemplate jdbcTemplate,
            DigestService digestService,
            AuditService auditService,
            ObjectMapper objectMapper,
            CanonicalJsonService canonicalJsonService,
            OperatorRecoveryCredentialVerifier credentialVerifier
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.digestService = digestService;
        this.auditService = auditService;
        this.objectMapper = objectMapper;
        this.canonicalJsonService = canonicalJsonService;
        this.credentialVerifier = credentialVerifier;
    }

    @Transactional
    public IdempotencyRecoveryDto.Response recover(
            IdempotencyRecoveryDto.Request request,
            String suppliedRecoveryKey,
            String operatorActorId
    ) {
        String operator = credentialVerifier.verify(suppliedRecoveryKey, operatorActorId);
        StoredRecord stored = lock(request);
        if (!stored.requestDigest().equals(request.requestDigest())) {
            throw new BusinessException(
                    ErrorCode.IDEMPOTENCY_CONFLICT,
                    "Recovery requestDigest does not match the original reservation"
            );
        }
        if (!"RECOVERY_REQUIRED".equals(stored.state()) || stored.executionFinishedAt() == null) {
            throw new BusinessException(
                    ErrorCode.IDEMPOTENCY_IN_PROGRESS,
                    "The original execution has not produced DB-verifiable recovery-ready evidence"
            );
        }

        Completion completion = resolve(request);
        Instant recoveredAt = Instant.now();
        UUID recoveryId = UuidV7.generate();
        jdbcTemplate.update("""
                insert into idempotency_recoveries
                    (id, workspace_id, idempotency_record_id, actor_id, http_method, request_path,
                     idempotency_key, request_digest, resolution, verification_reference,
                     response_digest, recovered_by, original_expires_at, recovered_at)
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                recoveryId,
                AgentService.DEMO_WORKSPACE_ID,
                stored.id(),
                request.actorId(),
                request.httpMethod(),
                request.requestPath(),
                request.idempotencyKey(),
                request.requestDigest(),
                request.resolution().name(),
                request.verificationReference(),
                completion.responseDigest(),
                operator,
                Timestamp.from(stored.expiresAt()),
                Timestamp.from(recoveredAt)
        );
        if (request.resolution() == IdempotencyRecoveryDto.Resolution.COMPLETE) {
            int updated = jdbcTemplate.update("""
                    update api_idempotency_records
                       set state = 'COMPLETED', response_status = ?, response_content_type = ?,
                           response_location = ?, response_trace_id = ?, response_body = ?,
                           completed_at = ?, recovery_reason = null, expires_at = ?
                     where id = ? and state = 'RECOVERY_REQUIRED'
                    """,
                    completion.status(), completion.contentType(), completion.location(),
                    completion.traceId(), completion.body(), Timestamp.from(recoveredAt),
                    Timestamp.from(recoveredAt.plusSeconds(86_400)), stored.id()
            );
            requireSingleTransition(updated);
        } else {
            requireSingleTransition(jdbcTemplate.update(
                    "delete from api_idempotency_records where id = ? and state = 'RECOVERY_REQUIRED'",
                    stored.id()
            ));
        }

        ObjectNode metadata = objectMapper.createObjectNode();
        metadata.put("schemaVersion", "1.0");
        metadata.put("idempotencyRecordId", stored.id().toString());
        metadata.put("originalActorId", request.actorId());
        metadata.put("httpMethod", request.httpMethod());
        metadata.put("requestPath", request.requestPath());
        metadata.put("idempotencyKey", request.idempotencyKey());
        metadata.put("resolution", request.resolution().name());
        metadata.put("verificationReference", request.verificationReference());
        auditService.append(
                AgentService.DEMO_WORKSPACE_ID,
                operator,
                "IDEMPOTENCY_RECOVERED_" + request.resolution().name(),
                "IDEMPOTENCY_RECOVERY",
                recoveryId,
                request.requestDigest(),
                completion.responseDigest(),
                metadata
        );

        return new IdempotencyRecoveryDto.Response(
                recoveryId,
                stored.id(),
                request.resolution(),
                request.resolution() == IdempotencyRecoveryDto.Resolution.RELEASE ? "RELEASED" : "COMPLETED",
                completion.responseDigest(),
                operator,
                recoveredAt
        );
    }

    @Transactional(readOnly = true)
    public List<IdempotencyRecoveryDto.Pending> findPending(
            String suppliedRecoveryKey,
            String operatorActorId,
            int limit
    ) {
        credentialVerifier.verify(suppliedRecoveryKey, operatorActorId);
        if (limit < 1 || limit > 100) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "limit must be between 1 and 100");
        }
        return jdbcTemplate.query("""
                select id, actor_id, http_method, request_path, idempotency_key,
                       request_digest, expires_at, execution_finished_at, recovery_reason, created_at
                  from api_idempotency_records
                 where workspace_id = ? and state = 'RECOVERY_REQUIRED'
                 order by expires_at, created_at, id
                 limit ?
                """, (resultSet, rowNumber) -> new IdempotencyRecoveryDto.Pending(
                        resultSet.getObject("id", UUID.class),
                        resultSet.getString("actor_id"),
                        resultSet.getString("http_method"),
                        resultSet.getString("request_path"),
                        resultSet.getString("idempotency_key"),
                        resultSet.getString("request_digest"),
                        resultSet.getTimestamp("expires_at").toInstant(),
                        resultSet.getTimestamp("execution_finished_at").toInstant(),
                        resultSet.getString("recovery_reason"),
                        resultSet.getTimestamp("created_at").toInstant()
                ), AgentService.DEMO_WORKSPACE_ID, limit);
    }

    private StoredRecord lock(IdempotencyRecoveryDto.Request request) {
        List<StoredRecord> rows = jdbcTemplate.query("""
                select id, request_digest, state, expires_at, execution_finished_at
                  from api_idempotency_records
                 where workspace_id = ? and actor_id = ? and http_method = ?
                   and request_path = ? and idempotency_key = ?
                 for update
                """, (resultSet, rowNumber) -> new StoredRecord(
                        resultSet.getObject("id", UUID.class),
                        resultSet.getString("request_digest"),
                        resultSet.getString("state"),
                        resultSet.getTimestamp("expires_at").toInstant(),
                        resultSet.getTimestamp("execution_finished_at") == null
                                ? null
                                : resultSet.getTimestamp("execution_finished_at").toInstant()
                ),
                AgentService.DEMO_WORKSPACE_ID,
                request.actorId(),
                request.httpMethod(),
                request.requestPath(),
                request.idempotencyKey()
        );
        if (rows.isEmpty()) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "Idempotency reservation was not found");
        }
        return rows.getFirst();
    }

    private Completion resolve(IdempotencyRecoveryDto.Request request) {
        if (request.resolution() == IdempotencyRecoveryDto.Resolution.RELEASE) {
            if (request.completedResponse() != null) {
                throw new BusinessException(
                        ErrorCode.VALIDATION_ERROR,
                        "completedResponse is only allowed for COMPLETE recovery"
                );
            }
            return new Completion(null, null, null, null, null, null);
        }
        if (request.completedResponse() == null) {
            throw new BusinessException(
                    ErrorCode.VALIDATION_ERROR,
                    "COMPLETE recovery requires the independently verified original response"
            );
        }
        byte[] body;
        try {
            body = Base64.getDecoder().decode(request.completedResponse().bodyBase64());
        } catch (IllegalArgumentException exception) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "bodyBase64 is not valid Base64");
        }
        if (body.length > MAX_RECOVERED_RESPONSE_BYTES) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "Recovered response body exceeds 1 MiB");
        }
        String bodyDigest = digestService.sha256(body);
        ObjectNode envelope = objectMapper.createObjectNode();
        envelope.put("status", request.completedResponse().status());
        envelope.put("contentType", normalizeNullable(request.completedResponse().contentType()));
        envelope.put("location", normalizeNullable(request.completedResponse().location()));
        envelope.put("traceId", request.completedResponse().traceId().toString());
        envelope.put("bodyDigest", bodyDigest);
        return new Completion(
                request.completedResponse().status(),
                request.completedResponse().contentType(),
                request.completedResponse().location(),
                request.completedResponse().traceId(),
                body,
                digestService.sha256(canonicalJsonService.canonicalize(envelope))
        );
    }

    private String normalizeNullable(String value) {
        return value == null ? "" : value.trim();
    }

    private void requireSingleTransition(int updated) {
        if (updated != 1) {
            throw new BusinessException(ErrorCode.IDEMPOTENCY_CONFLICT, "Idempotency recovery lost its row lock");
        }
    }

    private record StoredRecord(
            UUID id,
            String requestDigest,
            String state,
            Instant expiresAt,
            Instant executionFinishedAt
    ) {
    }

    private record Completion(
            Integer status,
            String contentType,
            String location,
            UUID traceId,
            byte[] body,
            String responseDigest
    ) {
    }
}
