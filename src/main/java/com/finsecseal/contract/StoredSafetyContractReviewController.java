package com.finsecseal.contract;

import com.finsecseal.common.api.ApiResponse;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.TraceIdFilter;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionIdentity;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionState;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationResult;
import com.finsecseal.contract.StoredSafetyContractReviewService.Baseline;
import com.finsecseal.contract.StoredSafetyContractReviewService.ChangeView;
import com.finsecseal.contract.StoredSafetyContractReviewService.ReviewException;
import com.finsecseal.contract.StoredSafetyContractReviewService.ReviewMetadata;
import com.finsecseal.contract.StoredSafetyContractReviewService.ReviewView;
import com.finsecseal.platform.contract.ContractAccessFilter;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

/** Protected additive integration route; the original contract-versions/session route remains separate. */
@RestController
@RequestMapping("/api/v1/platform/contracts")
public class StoredSafetyContractReviewController {
    private final StoredSafetyContractReviewService service;

    public StoredSafetyContractReviewController(StoredSafetyContractReviewService service) {
        this.service = service;
    }

    @GetMapping("/{id}/review")
    public ResponseEntity<ApiResponse<ReviewResponse>> review(@PathVariable("id") UUID id,
            HttpServletRequest request) {
        Object context = request.getAttribute(ContractAccessFilter.CONTEXT);
        ReviewerContext reviewer = context instanceof ReviewerContext trusted ? trusted : null;
        ReviewView view = service.review(id, reviewer);
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(ApiResponse.success(ReviewResponse.from(view), TraceIdFilter.currentTraceId()));
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    ResponseEntity<ProblemDetail> invalidIdentifier() {
        return problem(HttpStatus.BAD_REQUEST, "CONTRACT_REVIEW_INVALID_REQUEST",
                "Contract version identifier must be a UUID", false);
    }

    @ExceptionHandler(ReviewException.class)
    ResponseEntity<ProblemDetail> reviewFailure(ReviewException exception) {
        String code = "CONTRACT_REVIEW_" + exception.code().name();
        return switch (exception.code()) {
            case INVALID_REQUEST -> invalidIdentifier();
            case UNSAFE_TRANSACTION -> problem(HttpStatus.SERVICE_UNAVAILABLE, code,
                    "A consistent stored contract review is unavailable", false);
            case STORED_VERSION_INVALID -> problem(HttpStatus.CONFLICT, code,
                    "Stored contract version cannot be reviewed", false);
            case BASELINE_UNAVAILABLE -> problem(HttpStatus.CONFLICT, code,
                    "Recorded contract comparison baseline is unavailable", false);
            case REVIEW_UNAVAILABLE -> unavailable();
        };
    }

    @ExceptionHandler(BusinessException.class)
    ResponseEntity<ProblemDetail> persistenceFailure(BusinessException exception) {
        var code = exception.errorCode();
        String detail = switch (code) {
            case OPERATOR_AUTH_REQUIRED -> "Workspace reviewer authorization is required";
            case RESOURCE_NOT_FOUND -> "Stored contract version was not found";
            case EVIDENCE_INCOMPLETE -> "Stored contract integrity verification failed";
            default -> "Stored contract review request was rejected";
        };
        return problem(code.status(), code.name(), detail, code.retryable());
    }

    @ExceptionHandler(RuntimeException.class)
    ResponseEntity<ProblemDetail> unavailable() {
        // Also covers transaction opening/completion outside the service method's safe boundary.
        return problem(HttpStatus.SERVICE_UNAVAILABLE, "CONTRACT_REVIEW_UNAVAILABLE",
                "Stored contract review is temporarily unavailable", true);
    }

    private ResponseEntity<ProblemDetail> problem(HttpStatus status, String code, String detail, boolean retryable) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setType(URI.create("https://finsec-seal.local/problems/" + code.toLowerCase(Locale.ROOT)));
        // Prevent automatic request-path insertion from reflecting a malformed identifier.
        problem.setInstance(URI.create("/api/v1/platform/contracts"));
        problem.setProperty("code", code);
        problem.setProperty("traceId", TraceIdFilter.currentTraceId());
        problem.setProperty("retryable", retryable);
        problem.setProperty("errors", List.of());
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore()).body(problem);
    }

    /** Explicit wire projection: absent evidence is null; policy/diff values remain JSON text. */
    public record ReviewResponse(VersionIdentity identity, VersionState state, String policyHash, String resourceHash,
            String storedPolicyJson, String canonicalPolicyJson, Baseline baseline, ValidationResult validation,
            ReviewMetadata review, List<ChangeView> changes) {
        public ReviewResponse {
            changes = List.copyOf(changes);
        }

        private static ReviewResponse from(ReviewView view) {
            return new ReviewResponse(view.identity(), view.state(), view.policyHash(), view.resourceHash(),
                    view.storedPolicyJson(), view.canonicalPolicyJson(), view.baseline().orElse(null),
                    view.validation().orElse(null), view.review().orElse(null), view.changes());
        }
    }
}
