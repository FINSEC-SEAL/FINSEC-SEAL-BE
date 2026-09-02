package com.finsecseal.sandbox.tool;

import com.finsecseal.sandbox.SandboxExecutionContext;
import tools.jackson.databind.JsonNode;

public interface ToolAdapter {

    String toolName();

    ToolExecutionResult execute(SandboxExecutionContext context, JsonNode arguments);

    record ToolExecutionResult(JsonNode output, boolean stateChanged) {
    }
}
