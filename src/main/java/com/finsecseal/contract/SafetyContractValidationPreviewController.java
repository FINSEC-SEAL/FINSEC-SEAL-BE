package com.finsecseal.contract;

import com.finsecseal.common.api.ApiResponse;
import com.finsecseal.common.api.TraceIdFilter;
import com.finsecseal.contract.ReleaseToolCatalogContractAdapter.CatalogAdapterException;
import com.finsecseal.contract.SafetyContractValidationPreviewService.PreviewProcessingException;
import com.finsecseal.contract.SafetyContractValidationPreviewService.PreviewResult;
import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import tools.jackson.databind.JsonNode;

@RestController
@Profile("local")
@ConditionalOnProperty(name = "finsec.contract-preview.enabled", havingValue = "true")
@RequestMapping(SafetyContractValidationPreviewAccessFilter.PATH)
public final class SafetyContractValidationPreviewController {

    private final SafetyContractValidationPreviewService service;

    public SafetyContractValidationPreviewController(SafetyContractValidationPreviewService service) {
        this.service = service;
    }

    @PostMapping("/{releaseId}")
    public ApiResponse<PreviewResult> preview(
            @PathVariable UUID releaseId,
            @RequestBody JsonNode candidate,
            @RequestHeader(value = "X-Actor-Id", required = false) String actorId
    ) {
        return ApiResponse.success(service.preview(releaseId, candidate, actorId),
                TraceIdFilter.currentTraceId());
    }

    @ExceptionHandler({HttpMessageNotReadableException.class, MethodArgumentTypeMismatchException.class})
    ProblemDetail malformedRequest(Exception ignored) {
        return problem(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR",
                "A valid release UUID and JSON request body are required", List.of());
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    ProblemDetail unsupportedMediaType(HttpMediaTypeNotSupportedException ignored) {
        return problem(HttpStatus.UNSUPPORTED_MEDIA_TYPE, "UNSUPPORTED_MEDIA_TYPE",
                "Contract validation preview requires application/json", List.of());
    }

    @ExceptionHandler(CatalogAdapterException.class)
    ProblemDetail unavailableSource(CatalogAdapterException exception) {
        return problem(HttpStatus.SERVICE_UNAVAILABLE, "CONTRACT_PREVIEW_SOURCE_UNAVAILABLE",
                "The release catalog could not be verified", List.of(exception.code().name()));
    }

    @ExceptionHandler(PreviewProcessingException.class)
    ProblemDetail processingFailure(PreviewProcessingException ignored) {
        return problem(HttpStatus.INTERNAL_SERVER_ERROR, "CONTRACT_PREVIEW_PROCESSING_FAILED",
                "Contract validation preview could not be completed", List.of());
    }

    private ProblemDetail problem(HttpStatus status, String code, String detail, List<String> errors) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setType(URI.create("https://finsec-seal.local/problems/" + code.toLowerCase(Locale.ROOT)));
        problem.setTitle(status.getReasonPhrase());
        problem.setProperty("code", code);
        problem.setProperty("traceId", TraceIdFilter.currentTraceId());
        problem.setProperty("retryable", false);
        problem.setProperty("errors", errors);
        return problem;
    }
}
