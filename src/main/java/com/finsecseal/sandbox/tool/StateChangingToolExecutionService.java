package com.finsecseal.sandbox.tool;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.runtime.ToolInvocation;
import com.finsecseal.sandbox.SandboxExecutionContext;

public final class StateChangingToolExecutionService {

    public Execution execute(
            SandboxExecutionContext context,
            ToolInvocation invocation,
            ToolAdapter adapter,
            String actorId
    ) {
        if (context == null
                || invocation == null
                || adapter == null
                || actorId == null
                || actorId.isBlank()) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "State-changing Tool execution requires complete invocation context"
            );
        }

        if (adapter.effect() != ToolEffect.STATE_CHANGING) {
            throw new BusinessException(
                    ErrorCode.VALIDATION_ERROR,
                    "State-changing Tool executor requires a STATE_CHANGING adapter"
            );
        }

        ToolAdapter.ToolExecutionResult result =
                adapter.execute(
                        context,
                        invocation.proposal().arguments()
                );

        return new Execution(
                null,
                null,
                null,
                result,
                false
        );
    }

    public record Execution(
            ExecutionEventDto.Event requestEvent,
            ExecutionEventDto.Event responseEvent,
            ExecutionEventDto.Event stateEvent,
            ToolAdapter.ToolExecutionResult result,
            boolean replayed
    ) {
    }
}
