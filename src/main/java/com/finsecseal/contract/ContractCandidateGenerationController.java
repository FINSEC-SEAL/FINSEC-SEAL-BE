package com.finsecseal.contract;

import com.finsecseal.common.api.ApiResponse;
import com.finsecseal.common.api.TraceIdFilter;
import com.finsecseal.contract.ContractCandidateGenerationService.CandidateGenerationResult;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@ConditionalOnProperty(name = "finsec.ai.enabled", havingValue = "true")
@RequestMapping("/api/v1/releases/{releaseId}")
public class ContractCandidateGenerationController {

    private final ContractCandidateGenerationService service;

    public ContractCandidateGenerationController(ContractCandidateGenerationService service) {
        this.service = service;
    }

    @PostMapping("/contracts:generate")
    ApiResponse<CandidateGenerationResult> generate(
            @PathVariable UUID releaseId,
            @RequestBody GenerateRequest request,
            @RequestHeader(value = "X-Actor-Id", required = false) String actorId
    ) {
        CandidateGenerationResult result = service.generate(
                releaseId,
                request.templateKey(),
                request.contractKey(),
                actorId
        );
        return ApiResponse.success(result, TraceIdFilter.currentTraceId());
    }

    public record GenerateRequest(String templateKey, String contractKey) {
    }
}
