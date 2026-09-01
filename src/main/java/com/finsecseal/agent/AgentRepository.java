package com.finsecseal.agent;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import jakarta.persistence.LockModeType;

public interface AgentRepository extends JpaRepository<AgentEntity, UUID> {

    List<AgentEntity> findAllByWorkspaceIdOrderByCreatedAtDesc(UUID workspaceId);

    Optional<AgentEntity> findByWorkspaceIdAndAgentKey(UUID workspaceId, String agentKey);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select agent from AgentEntity agent where agent.id = :id")
    Optional<AgentEntity> findByIdForUpdate(@Param("id") UUID id);
}
