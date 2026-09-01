package com.finsecseal.evidence;

import com.finsecseal.common.api.ApiResponse;
import com.finsecseal.common.api.TraceIdFilter;
import jakarta.validation.Valid;
import java.net.URI;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/evidence-references")
public class EvidenceReferenceController {

    private final EvidenceReferenceService evidenceReferenceService;

    public EvidenceReferenceController(EvidenceReferenceService evidenceReferenceService) {
        this.evidenceReferenceService = evidenceReferenceService;
    }

    @PostMapping
    ResponseEntity<ApiResponse<EvidenceReferenceDto.Reference>> append(
            @Valid @RequestBody EvidenceReferenceDto.AppendRequest request,
            @RequestHeader(value = "X-Actor-Id", required = false) String actorId
    ) {
        EvidenceReferenceDto.Reference reference = evidenceReferenceService.append(request, actorId);
        return ResponseEntity.created(URI.create("/api/v1/evidence-references/" + reference.id()))
                .body(ApiResponse.success(reference, TraceIdFilter.currentTraceId()));
    }

    @GetMapping
    ApiResponse<EvidenceReferenceDto.ListResponse> find(
            @RequestParam String ownerType,
            @RequestParam UUID ownerId
    ) {
        return ApiResponse.success(
                evidenceReferenceService.find(ownerType, ownerId),
                TraceIdFilter.currentTraceId()
        );
    }
}
