package com.finsecseal.agent;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AgentRepository extends JpaRepository<AgentEntity, UUID> {

    List<AgentEntity> findAllByWorkspaceIdOrderByCreatedAtDesc(UUID workspaceId);

    Optional<AgentEntity> findByWorkspaceIdAndAgentKey(UUID workspaceId, String agentKey);
}
