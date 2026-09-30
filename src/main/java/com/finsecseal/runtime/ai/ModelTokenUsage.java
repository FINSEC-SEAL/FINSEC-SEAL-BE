package com.finsecseal.runtime.ai;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;

public record ModelTokenUsage(long promptTokens, long completionTokens, long totalTokens) {

    public static final ModelTokenUsage ZERO = new ModelTokenUsage(0L, 0L, 0L);

    public ModelTokenUsage {
        if (promptTokens < 0 || completionTokens < 0 || totalTokens < 0) {
            throw invalid();
        }
        long expectedTotal;
        try {
            expectedTotal = Math.addExact(promptTokens, completionTokens);
        } catch (ArithmeticException exception) {
            throw invalid();
        }
        if (totalTokens != expectedTotal) {
            throw invalid();
        }
    }

    public ModelTokenUsage plus(ModelTokenUsage other) {
        if (other == null) {
            throw invalid();
        }
        try {
            long prompt = Math.addExact(promptTokens, other.promptTokens);
            long completion = Math.addExact(completionTokens, other.completionTokens);
            return new ModelTokenUsage(prompt, completion, Math.addExact(prompt, completion));
        } catch (ArithmeticException exception) {
            throw invalid();
        }
    }

    private static BusinessException invalid() {
        return new BusinessException(
                ErrorCode.EVIDENCE_INCOMPLETE,
                "Model token usage is missing, negative, inconsistent, or too large"
        );
    }
}
