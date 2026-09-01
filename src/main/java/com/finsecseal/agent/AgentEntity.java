package com.finsecseal.agent;

import com.finsecseal.common.domain.AgentStatus;
import com.finsecseal.common.persistence.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import java.util.UUID;

@Entity
@Table(name = "agents")
public class AgentEntity extends BaseEntity {

    @Column(name = "workspace_id", nullable = false, updatable = false)
    private UUID workspaceId;

    @Column(name = "agent_key", nullable = false, length = 80)
    private String agentKey;

    @Column(nullable = false, length = 100)
    private String name;

    @Column(name = "purpose_summary", nullable = false, length = 500)
    private String purposeSummary;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private AgentStatus status;

    protected AgentEntity() {
    }

    public AgentEntity(UUID workspaceId, String agentKey, String name, String purposeSummary) {
        this.workspaceId = workspaceId;
        this.agentKey = agentKey;
        this.name = name;
        this.purposeSummary = purposeSummary;
        this.status = AgentStatus.ACTIVE;
    }

    public void update(String name, String purposeSummary) {
        this.name = name;
        this.purposeSummary = purposeSummary;
    }

    public void archive() {
        this.status = AgentStatus.ARCHIVED;
    }

    public UUID getWorkspaceId() {
        return workspaceId;
    }

    public String getAgentKey() {
        return agentKey;
    }

    public String getName() {
        return name;
    }

    public String getPurposeSummary() {
        return purposeSummary;
    }

    public AgentStatus getStatus() {
        return status;
    }
}
