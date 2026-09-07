package com.finsecseal.platform.contract;

import com.finsecseal.common.api.ApiResponse;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.api.TraceIdFilter;
import jakarta.servlet.http.HttpServletRequest;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tools.jackson.databind.JsonNode;

/** Public routes from docs/predev/10_API_SPECIFICATION.md. */
@RestController
@RequestMapping("/api/v1")
public class ContractSpecificationController {
    private final ContractPersistenceService service;

    public ContractSpecificationController(ContractPersistenceService service) {
        this.service = service;
    }

    @GetMapping("/contract-versions/{id}")
    ResponseEntity<?> find(@PathVariable UUID id, HttpServletRequest request) {
        var version = service.find(id, ContractController.reviewer(request));
        return response(service.detail(version, ContractController.reviewer(request)), version.resourceHash());
    }

    @GetMapping("/contracts/{id}/versions")
    ApiResponse<?> history(@PathVariable UUID id, @RequestParam(defaultValue = "25") int limit,
            @RequestParam(required = false) String cursor, HttpServletRequest request) {
        return ApiResponse.success(service.history(id, limit, cursor, ContractController.reviewer(request)),
                TraceIdFilter.currentTraceId());
    }

    @PostMapping("/contract-versions/{id}:validate")
    ResponseEntity<?> validate(@PathVariable UUID id, @RequestHeader("If-Match") String match,
            @RequestBody JsonNode body, HttpServletRequest request) {
        if (!body.isObject() || !body.isEmpty()) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "Validation body must be an empty object");
        }
        var version = service.validate(id, match, ContractController.reviewer(request));
        return response(service.validationResult(version), version.resourceHash());
    }

    @PostMapping("/contract-versions/{id}:approve")
    ResponseEntity<?> approve(@PathVariable UUID id, @RequestHeader("If-Match") String match,
            @RequestBody JsonNode body, HttpServletRequest request) {
        var review = review(body, true);
        var version = service.approve(id, match, review.comment(), review.patchProposalId(), ContractController.reviewer(request));
        return response(service.detail(version, ContractController.reviewer(request)), version.resourceHash());
    }

    @PostMapping("/contract-versions/{id}:reject")
    ResponseEntity<?> reject(@PathVariable UUID id, @RequestHeader("If-Match") String match,
            @RequestBody JsonNode body, HttpServletRequest request) {
        var review = review(body, false);
        var version = service.reject(id, match, review.comment(), ContractController.reviewer(request));
        return response(service.detail(version, ContractController.reviewer(request)), version.resourceHash());
    }

    @GetMapping("/contract-versions/{id}/approved")
    ApiResponse<?> approved(@PathVariable UUID id, @RequestParam UUID releaseId, HttpServletRequest request) {
        return ApiResponse.success(service.approved(releaseId, id, ContractController.reviewer(request)), TraceIdFilter.currentTraceId());
    }

    private record Review(String comment, UUID patchProposalId) {}

    private Review review(JsonNode body, boolean approval) {
        if (!body.isObject() || !body.path("comment").isString()
                || body.properties().stream().anyMatch(e -> !e.getKey().equals("comment")
                    && !(approval && e.getKey().equals("patchProposalId")))) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "Expected comment and optional patchProposalId only");
        }
        UUID proposal = null;
        if (body.hasNonNull("patchProposalId")) {
            try { proposal = UUID.fromString(body.path("patchProposalId").stringValue()); }
            catch (RuntimeException exception) {
                throw new BusinessException(ErrorCode.VALIDATION_ERROR, "patchProposalId must be a UUID");
            }
        }
        return new Review(body.path("comment").stringValue(), proposal);
    }

    private ResponseEntity<?> response(Object value, String hash) {
        return ResponseEntity.ok().eTag('"' + hash + '"')
                .body(ApiResponse.success(value, TraceIdFilter.currentTraceId()));
    }
}
