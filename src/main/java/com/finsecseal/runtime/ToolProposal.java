package com.finsecseal.runtime;

import tools.jackson.databind.JsonNode;

public record ToolProposal(String toolName, JsonNode arguments) {
}
