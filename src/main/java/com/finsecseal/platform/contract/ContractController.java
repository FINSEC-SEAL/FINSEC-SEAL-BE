package com.finsecseal.platform.contract;

import com.finsecseal.common.api.ApiResponse;
import com.finsecseal.common.api.TraceIdFilter;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tools.jackson.databind.JsonNode;

@RestController
@RequestMapping("/api/v1/platform/contracts")
public class ContractController {
    private final ContractPersistenceService service;
    public ContractController(ContractPersistenceService service) {this.service=service;}
    public record Create(UUID releaseId,JsonNode policy) {}
    public record Review(String comment, UUID patchProposalId) {}
    @PostMapping
    ResponseEntity<?> create(@RequestBody Create body,HttpServletRequest request) {
        return response(service.create(body.releaseId(),body.policy(),reviewer(request)),201);
    }
    @GetMapping
    ApiResponse<List<ContractPersistenceService.Version>> list(@RequestParam UUID releaseId,HttpServletRequest r) {
        return ApiResponse.success(service.list(releaseId,reviewer(r)),TraceIdFilter.currentTraceId());
    }
    @GetMapping("/{id}")
    ResponseEntity<?> find(@PathVariable UUID id,HttpServletRequest r) {return response(service.find(id,reviewer(r)),200);}
    @PostMapping("/{id}:validate")
    ResponseEntity<?> validate(@PathVariable UUID id,@RequestHeader("If-Match") String match,HttpServletRequest r) {
        return response(service.validate(id,match,reviewer(r)),200);
    }
    @PostMapping("/{id}:approve")
    ResponseEntity<?> approve(@PathVariable UUID id,@RequestHeader("If-Match") String match,@RequestBody Review body,HttpServletRequest r) {
        return response(service.approve(id,match,body.comment(),body.patchProposalId(),reviewer(r)),200);
    }
    @PostMapping("/{id}:reject")
    ResponseEntity<?> reject(@PathVariable UUID id,@RequestHeader("If-Match") String match,@RequestBody Review body,HttpServletRequest r) {
        return response(service.reject(id,match,body.comment(),reviewer(r)),200);
    }
    @GetMapping("/{id}/approved")
    ApiResponse<ContractPersistenceService.ApprovedContract> approved(@PathVariable UUID id,@RequestParam UUID releaseId,HttpServletRequest r) {
        return ApiResponse.success(service.approved(releaseId,id,reviewer(r)),TraceIdFilter.currentTraceId());
    }
    private ResponseEntity<?> response(ContractPersistenceService.Version v,int status) {
        return ResponseEntity.status(status).eTag('"'+v.resourceHash()+'"')
                .body(ApiResponse.success(v,TraceIdFilter.currentTraceId()));
    }
    static ReviewerContext reviewer(HttpServletRequest r) {return (ReviewerContext)r.getAttribute(ContractAccessFilter.CONTEXT);}
}
