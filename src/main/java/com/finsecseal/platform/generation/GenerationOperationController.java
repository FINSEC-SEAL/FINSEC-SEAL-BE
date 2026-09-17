package com.finsecseal.platform.generation;

import com.finsecseal.common.api.*;
import com.finsecseal.contract.LoanReviewFinancialTemplate;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.platform.contract.ContractAccessFilter;
import com.finsecseal.platform.generation.GenerationContract.*;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tools.jackson.databind.JsonNode;

@RestController
@RequestMapping("/api/v1")
public class GenerationOperationController {
    private final GenerationOperationService service;
    public GenerationOperationController(GenerationOperationService service) {this.service=service;}

    @PostMapping("/releases/{id}/contracts:generate")
    ResponseEntity<?> initial(@PathVariable UUID id,@RequestBody JsonNode body,HttpServletRequest request) {
        if(!body.isObject() || body.size()!=1 || !body.path("templateKey").isString()) invalid();
        return accepted(service.submit(Kind.CONTRACT,id,null,body.path("templateKey").stringValue(),reviewer(request),(IdempotencyFilter.Admission)request.getAttribute(IdempotencyFilter.ADMISSION)));
    }
    @PostMapping("/findings/{id}/patch-proposals")
    ResponseEntity<?> patch(@PathVariable UUID id,@RequestBody JsonNode body,HttpServletRequest request) {
        if(!body.isObject() || body.size()!=1 || !body.path("baseContractVersionId").isString()) invalid();
        UUID base;
        try {base=UUID.fromString(body.path("baseContractVersionId").stringValue());}
        catch(RuntimeException exception) {throw new BusinessException(ErrorCode.VALIDATION_ERROR,"baseContractVersionId must be a UUID");}
        return accepted(service.submit(Kind.PATCH,id,base,LoanReviewFinancialTemplate.KEY,reviewer(request),(IdempotencyFilter.Admission)request.getAttribute(IdempotencyFilter.ADMISSION)));
    }
    @GetMapping("/operations/{id}")
    ApiResponse<Operation> find(@PathVariable UUID id,HttpServletRequest request) {
        return ApiResponse.success(service.find(id,reviewer(request)),TraceIdFilter.currentTraceId());
    }
    private ResponseEntity<?> accepted(Operation op) {
        return ResponseEntity.accepted().location(URI.create(op.statusUrl()))
                .body(ApiResponse.success(op,TraceIdFilter.currentTraceId()));
    }
    private ReviewerContext reviewer(HttpServletRequest request) {return (ReviewerContext)request.getAttribute(ContractAccessFilter.CONTEXT);}
    private void invalid() {throw new BusinessException(ErrorCode.VALIDATION_ERROR,"Unexpected generation request fields");}
}
