package com.finsecseal.common.api;

import com.finsecseal.agent.AgentService;
import com.finsecseal.common.persistence.UuidV7;
import com.finsecseal.release.DigestService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class IdempotencyFilter extends OncePerRequestFilter {

    private static final Set<String> MUTATION_METHODS = Set.of("POST", "PUT", "PATCH", "DELETE");
    private static final Pattern KEY = Pattern.compile("^[A-Za-z0-9._:-]{1,128}$");
    private static final int MAX_REQUEST_BYTES = 2 * 1024 * 1024;

    private final JdbcTemplate jdbcTemplate;
    private final DigestService digestService;
    private final ObjectMapper objectMapper;
    private final IdempotencyInstanceLease instanceLease;
    private final Duration ttl;

    public IdempotencyFilter(
            JdbcTemplate jdbcTemplate,
            DigestService digestService,
            ObjectMapper objectMapper,
            IdempotencyInstanceLease instanceLease,
            @Value("${finsec.idempotency.ttl:24h}") Duration ttl
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.digestService = digestService;
        this.objectMapper = objectMapper;
        this.instanceLease = instanceLease;
        this.ttl = ttl;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/v1/")
                || !MUTATION_METHODS.contains(request.getMethod());
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        String key = request.getHeader("Idempotency-Key");
        if (key == null || !KEY.matcher(key).matches()) {
            writeProblem(
                    response,
                    ErrorCode.VALIDATION_ERROR,
                    "Idempotency-Key is required and must contain 1 to 128 safe characters"
            );
            return;
        }
        String actor = request.getHeader("X-Actor-Id");
        if (actor == null || actor.isBlank()) {
            actor = "demo-user";
        }
        if (actor.length() > 120) {
            writeProblem(response, ErrorCode.VALIDATION_ERROR, "X-Actor-Id must not exceed 120 characters");
            return;
        }
        byte[] body = request.getInputStream().readNBytes(MAX_REQUEST_BYTES + 1);
        if (body.length > MAX_REQUEST_BYTES) {
            writeProblem(response, ErrorCode.MANIFEST_INVALID, "Request body exceeds the 2 MB platform limit");
            return;
        }

        String path = request.getRequestURI()
                + (request.getQueryString() == null ? "" : "?" + request.getQueryString());
        String requestDigest = requestDigest(
                body,
                request.getContentType(),
                request.getHeader(HttpHeaders.IF_MATCH)
        );
        deleteExpiredCompleted(actor, request.getMethod(), path, key);
        boolean reserved = reserve(actor, request.getMethod(), path, key, requestDigest);
        if (!reserved) {
            StoredResponse stored = find(actor, request.getMethod(), path, key);
            if (stored == null) {
                writeProblem(response, ErrorCode.IDEMPOTENCY_IN_PROGRESS, "Idempotency reservation is being created");
                return;
            }
            if (!stored.requestDigest().equals(requestDigest)) {
                writeProblem(
                        response,
                        ErrorCode.IDEMPOTENCY_CONFLICT,
                        "Idempotency-Key was already used with a semantically different request"
                );
                return;
            }
            if (!"COMPLETED".equals(stored.state())) {
                writeProblem(
                        response,
                        ErrorCode.IDEMPOTENCY_IN_PROGRESS,
                        "The original request is still processing or requires operator recovery"
                );
                return;
            }
            replay(response, stored);
            return;
        }

        CachedBodyRequest cachedRequest = new CachedBodyRequest(request, body);
        ContentCachingResponseWrapper cachedResponse = new ContentCachingResponseWrapper(response);
        try {
            filterChain.doFilter(cachedRequest, cachedResponse);
        } catch (ServletException | IOException | RuntimeException | Error exception) {
            markRecoveryRequired(
                    actor, request.getMethod(), path, key, requestDigest, "REQUEST_CHAIN_FAILED"
            );
            throw exception;
        }
        byte[] responseBody = cachedResponse.getContentAsByteArray();
        if (cachedResponse.getStatus() < 500) {
            store(
                    actor,
                    request.getMethod(),
                    path,
                    key,
                    requestDigest,
                    cachedResponse.getStatus(),
                    cachedResponse.getContentType(),
                    cachedResponse.getHeader(HttpHeaders.LOCATION),
                    cachedResponse.getHeader("X-Trace-Id"),
                    responseBody
            );
        } else {
            markRecoveryRequired(
                    actor, request.getMethod(), path, key, requestDigest, "HTTP_5XX_RESPONSE"
            );
        }
        cachedResponse.copyBodyToResponse();
    }

    private StoredResponse find(String actor, String method, String path, String key) {
        return jdbcTemplate.query("""
                select request_digest, state, response_status, response_content_type, response_location,
                       response_trace_id, response_body
                  from api_idempotency_records
                 where workspace_id = ? and actor_id = ? and http_method = ?
                   and request_path = ? and idempotency_key = ?
                """, resultSet -> resultSet.next()
                        ? new StoredResponse(
                                resultSet.getString("request_digest"),
                                resultSet.getString("state"),
                                resultSet.getInt("response_status"),
                                resultSet.getString("response_content_type"),
                                resultSet.getString("response_location"),
                                resultSet.getString("response_trace_id"),
                                resultSet.getBytes("response_body")
                        )
                        : null,
                AgentService.DEMO_WORKSPACE_ID, actor, method, path, key);
    }

    private boolean reserve(String actor, String method, String path, String key, String requestDigest) {
        Instant now = Instant.now();
        return jdbcTemplate.update("""
                insert into api_idempotency_records
                    (id, workspace_id, actor_id, http_method, request_path, idempotency_key,
                     request_digest, state, expires_at, owner_instance_id)
                values (?, ?, ?, ?, ?, ?, ?, 'PROCESSING', ?, ?)
                on conflict (workspace_id, actor_id, http_method, request_path, idempotency_key)
                do nothing
                """,
                UuidV7.generate(),
                AgentService.DEMO_WORKSPACE_ID,
                actor,
                method,
                path,
                key,
                requestDigest,
                Timestamp.from(now.plus(ttl)),
                instanceLease.instanceId()
        ) == 1;
    }

    private void deleteExpiredCompleted(String actor, String method, String path, String key) {
        jdbcTemplate.update("""
                delete from api_idempotency_records
                 where workspace_id = ? and actor_id = ? and http_method = ?
                   and request_path = ? and idempotency_key = ?
                   and state = 'COMPLETED' and expires_at <= now()
                """, AgentService.DEMO_WORKSPACE_ID, actor, method, path, key);
    }

    private void store(
            String actor,
            String method,
            String path,
            String key,
            String requestDigest,
            int status,
            String contentType,
            String location,
            String traceId,
            byte[] body
    ) {
        Instant now = Instant.now();
        int updated = jdbcTemplate.update("""
                with transition_proof as (
                    select set_config('finsec.idempotency_transition_secret', ?, true)
                )
                update api_idempotency_records
                   set state = 'COMPLETED', response_status = ?, response_content_type = ?,
                       response_location = ?, response_trace_id = ?::uuid, response_body = ?,
                       completed_at = ?, execution_finished_at = ?, recovery_reason = null,
                       expires_at = ?
                 where workspace_id = ? and actor_id = ? and http_method = ? and request_path = ?
                   and idempotency_key = ? and request_digest = ? and state = 'PROCESSING'
                   and (select count(*) from transition_proof) = 1
                """,
                instanceLease.transitionSecret(),
                status,
                contentType,
                location,
                traceId,
                body,
                Timestamp.from(now),
                Timestamp.from(now),
                Timestamp.from(now.plus(ttl)),
                AgentService.DEMO_WORKSPACE_ID,
                actor,
                method,
                path,
                key,
                requestDigest
        );
        if (updated != 1) {
            throw new IllegalStateException("Idempotency reservation was not completed exactly once");
        }
    }

    private void markRecoveryRequired(
            String actor,
            String method,
            String path,
            String key,
            String requestDigest,
            String reason
    ) {
        Instant now = Instant.now();
        int updated = jdbcTemplate.update("""
                with transition_proof as (
                    select set_config('finsec.idempotency_transition_secret', ?, true)
                )
                update api_idempotency_records
                   set state = 'RECOVERY_REQUIRED', execution_finished_at = ?, recovery_reason = ?
                 where workspace_id = ? and actor_id = ? and http_method = ? and request_path = ?
                   and idempotency_key = ? and request_digest = ? and state = 'PROCESSING'
                   and owner_instance_id = ?
                   and (select count(*) from transition_proof) = 1
                """,
                instanceLease.transitionSecret(),
                Timestamp.from(now),
                reason,
                AgentService.DEMO_WORKSPACE_ID,
                actor,
                method,
                path,
                key,
                requestDigest,
                instanceLease.instanceId()
        );
        if (updated != 1) {
            throw new IllegalStateException("Idempotency execution completion was not recorded exactly once");
        }
    }

    private void replay(HttpServletResponse response, StoredResponse stored) throws IOException {
        response.setStatus(stored.status());
        if (stored.contentType() != null) {
            response.setContentType(stored.contentType());
        }
        if (stored.location() != null) {
            response.setHeader(HttpHeaders.LOCATION, stored.location());
        }
        response.setHeader("X-Trace-Id", stored.traceId());
        response.setHeader("Idempotent-Replayed", "true");
        response.getOutputStream().write(stored.body());
    }

    private void writeProblem(HttpServletResponse response, ErrorCode code, String detail) throws IOException {
        response.setStatus(code.status().value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        ObjectNode problem = objectMapper.createObjectNode();
        problem.put("type", "https://finsec-seal.local/problems/" + code.name().toLowerCase());
        problem.put("title", code.status().getReasonPhrase());
        problem.put("status", code.status().value());
        problem.put("detail", detail);
        problem.put("code", code.name());
        problem.put("traceId", TraceIdFilter.currentTraceId());
        problem.put("retryable", code.retryable());
        ArrayNode errors = problem.putArray("errors");
        response.getOutputStream().write(objectMapper.writeValueAsBytes(problem));
    }

    private String requestDigest(byte[] body, String contentType, String ifMatch) {
        String normalizedContentType = contentType == null ? "" : contentType.trim().toLowerCase(java.util.Locale.ROOT);
        String normalizedIfMatch = ifMatch == null ? "" : ifMatch.trim();
        byte[] metadata = ("\ncontent-type:" + normalizedContentType + "\nif-match:" + normalizedIfMatch)
                .getBytes(StandardCharsets.UTF_8);
        byte[] semanticRequest = java.util.Arrays.copyOf(body, body.length + metadata.length);
        System.arraycopy(metadata, 0, semanticRequest, body.length, metadata.length);
        return digestService.sha256(semanticRequest);
    }

    private record StoredResponse(
            String requestDigest,
            String state,
            int status,
            String contentType,
            String location,
            String traceId,
            byte[] body
    ) {
    }

    private static final class CachedBodyRequest extends HttpServletRequestWrapper {

        private final byte[] body;

        private CachedBodyRequest(HttpServletRequest request, byte[] body) {
            super(request);
            this.body = body;
        }

        @Override
        public ServletInputStream getInputStream() {
            ByteArrayInputStream input = new ByteArrayInputStream(body);
            return new ServletInputStream() {
                @Override
                public boolean isFinished() {
                    return input.available() == 0;
                }

                @Override
                public boolean isReady() {
                    return true;
                }

                @Override
                public void setReadListener(ReadListener readListener) {
                    throw new UnsupportedOperationException("Async request body reads are not supported");
                }

                @Override
                public int read() {
                    return input.read();
                }
            };
        }
    }
}
