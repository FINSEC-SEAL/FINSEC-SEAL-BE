package com.finsecseal.attestation;

import com.finsecseal.common.api.ApiResponse;
import com.finsecseal.common.api.TraceIdFilter;
import java.util.UUID;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/releases/{releaseId}")
public class AttestationController {

    private final AttestationService attestationService;

    public AttestationController(AttestationService attestationService) {
        this.attestationService = attestationService;
    }

    @GetMapping("/attestation")
    ApiResponse<AttestationDto.View> find(
            @PathVariable UUID releaseId,
            @RequestHeader(value = "X-Actor-Id", required = false) String actorId
    ) {
        return ApiResponse.success(
                attestationService.findOrCreate(releaseId, actorId),
                TraceIdFilter.currentTraceId()
        );
    }

    @GetMapping("/evidence-export")
    ResponseEntity<byte[]> export(
            @PathVariable UUID releaseId,
            @RequestParam(defaultValue = "json") String format,
            @RequestHeader(value = "X-Actor-Id", required = false) String actorId
    ) {
        AttestationDto.Export export = attestationService.export(releaseId, format, actorId);
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + export.fileName() + "\"")
                .header("X-Attestation-Hash", export.documentHash())
                .header("X-Attestation-Stale", Boolean.toString(export.stale()))
                .header(HttpHeaders.CONTENT_TYPE, export.contentType())
                .body(export.content());
    }
}
