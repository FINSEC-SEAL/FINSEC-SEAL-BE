package com.finsecseal.platform.contract;

import com.finsecseal.contract.SafetyContractCanonicalizer.InvalidSafetyContractException;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.LifecyclePolicyException;
import com.finsecseal.common.api.TraceIdFilter;
import org.springframework.core.annotation.Order;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.*;

@RestControllerAdvice(assignableTypes = ContractController.class)
@Order(-10)
public class ContractErrorAdvice {
    @ExceptionHandler(LifecyclePolicyException.class)
    ProblemDetail lifecycle(LifecyclePolicyException e) {
        String code=e.code().name();
        int status=code.startsWith("REVIEWER_")||code.startsWith("INVALID_REVIEWER")?403:
                code.equals("STALE_RESOURCE")||code.equals("INVALID_STATE_TRANSITION")||code.equals("VALIDATION_SOURCE_CHANGED")?409:422;
        return problem(status,code,e.getMessage());
    }
    @ExceptionHandler(InvalidSafetyContractException.class)
    ProblemDetail schema(InvalidSafetyContractException e) {return problem(422,"CONTRACT_SCHEMA_INVALID","Contract schema validation failed");}
    private ProblemDetail problem(int status,String code,String message) {
        var p=ProblemDetail.forStatus(status);p.setDetail(message);p.setProperty("code",code);
        p.setProperty("traceId",TraceIdFilter.currentTraceId());return p;
    }
}
