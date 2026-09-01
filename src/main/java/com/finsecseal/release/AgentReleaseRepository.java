package com.finsecseal.release;

import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AgentReleaseRepository extends JpaRepository<AgentReleaseEntity, UUID> {

    List<AgentReleaseEntity> findAllByAgentIdOrderByCreatedAtDesc(UUID agentId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select release from AgentReleaseEntity release where release.id = :id")
    Optional<AgentReleaseEntity> findByIdForUpdate(@Param("id") UUID id);
}
