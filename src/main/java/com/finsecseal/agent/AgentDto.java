package com.finsecseal.agent;

import com.finsecseal.common.domain.AgentStatus;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.UUID;

public final class AgentDto {

    private AgentDto() {
    }

    public record CreateRequest(
            @NotBlank @Pattern(regexp = "^[a-z0-9][a-z0-9-]{2,79}$") String agentKey,
            @NotBlank @Size(max = 100) String name,
            @NotBlank @Size(max = 500) String purposeSummary
    ) {
    }

    public record UpdateRequest(
            @NotBlank @Size(max = 100) String name,
            @NotBlank @Size(max = 500) String purposeSummary
    ) {
    }

    public record Response(
            UUID id,
            String agentKey,
            String name,
            String purposeSummary,
            AgentStatus status,
            Instant createdAt,
            Instant updatedAt
    ) {
        public static Response from(AgentEntity entity) {
            return new Response(
                    entity.getId(),
                    entity.getAgentKey(),
                    entity.getName(),
                    entity.getPurposeSummary(),
                    entity.getStatus(),
                    entity.getCreatedAt(),
                    entity.getUpdatedAt()
            );
        }
    }
}
