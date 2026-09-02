package com.finsecseal.runtime;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.sandbox.tool.ToolAdapter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

@Component
public class ToolProposalValidator {

    private static final int MAX_ARGUMENT_BYTES = 32 * 1024;
    private static final int MAX_TOOL_NAME_LENGTH = 80;

    private final ObjectMapper objectMapper;
    private final Map<String, ToolAdapter> adapters;

    public ToolProposalValidator(ObjectMapper objectMapper, List<ToolAdapter> adapters) {
        this.objectMapper = objectMapper;
        this.adapters = indexAdapters(adapters);
    }

    public ToolProposal validate(ToolProposal proposal) {
        if (proposal == null || proposal.toolName() == null || proposal.arguments() == null) {
            throw new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, "AI client returned an invalid Tool Proposal");
        }
        if (proposal.toolName().isBlank()
                || proposal.toolName().length() > MAX_TOOL_NAME_LENGTH
                || !proposal.toolName().matches("[A-Z0-9_:-]+")) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "Tool Proposal contains an invalid tool name");
        }
        if (!proposal.arguments().isObject()) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "Tool Proposal arguments must be a JSON object");
        }
        try {
            if (objectMapper.writeValueAsBytes(proposal.arguments()).length > MAX_ARGUMENT_BYTES) {
                throw new BusinessException(ErrorCode.VALIDATION_ERROR, "Tool Proposal arguments exceed 32 KiB");
            }
        } catch (BusinessException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "Tool Proposal arguments cannot be serialized");
        }

        ToolAdapter adapter = adapters.get(proposal.toolName());
        if (adapter == null) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "Unknown tool proposal: " + proposal.toolName());
        }
        adapter.validateArguments(proposal.arguments());
        return proposal;
    }

    private Map<String, ToolAdapter> indexAdapters(List<ToolAdapter> adapters) {
        Map<String, ToolAdapter> indexed = new HashMap<>();
        for (ToolAdapter adapter : adapters) {
            ToolAdapter previous = indexed.put(adapter.toolName(), adapter);
            if (previous != null) {
                throw new IllegalStateException("Duplicate ToolAdapter for " + adapter.toolName());
            }
        }
        return Map.copyOf(indexed);
    }
}
