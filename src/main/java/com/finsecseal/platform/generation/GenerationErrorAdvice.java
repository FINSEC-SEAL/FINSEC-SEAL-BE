package com.finsecseal.platform.generation;

import com.finsecseal.common.api.TraceIdFilter;
import com.finsecseal.contract.SafetyContractGenerationSourceService.GenerationSourceException;
import org.springframework.core.annotation.Order;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.*;

@RestControllerAdvice(assignableTypes=GenerationOperationController.class)
@Order(-20)
public class GenerationErrorAdvice {
    @ExceptionHandler(GenerationOperationService.GenerationUnavailableException.class)
    ProblemDetail unavailable() {return problem(503,"GENERATION_DISABLED");}
    @ExceptionHandler(GenerationSourceException.class)
    ProblemDetail source(GenerationSourceException exception) {return problem(422,exception.code().name());}
    private ProblemDetail problem(int status,String code) {
        var problem=ProblemDetail.forStatus(status);problem.setDetail("Generation request could not be accepted");
        problem.setProperty("code",code);problem.setProperty("retryable",false);problem.setProperty("traceId",TraceIdFilter.currentTraceId());
        return problem;
    }
}
