package com.finsecseal.agent;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.AgentStatus;
import java.util.List;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class AgentService {

    public static final UUID DEMO_WORKSPACE_ID = UUID.fromString("0198f1e2-0000-7000-8000-000000000001");

    private final AgentRepository agentRepository;

    public AgentService(AgentRepository agentRepository) {
        this.agentRepository = agentRepository;
    }

    @Transactional
    public AgentDto.Response create(AgentDto.CreateRequest request) {
        AgentEntity entity = new AgentEntity(
                DEMO_WORKSPACE_ID,
                request.agentKey(),
                request.name(),
                request.purposeSummary()
        );
        try {
            return AgentDto.Response.from(agentRepository.saveAndFlush(entity));
        } catch (DataIntegrityViolationException exception) {
            throw new BusinessException(ErrorCode.RESOURCE_CONFLICT, "agentKey already exists");
        }
    }

    public List<AgentDto.Response> findAll() {
        return agentRepository.findAllByWorkspaceIdOrderByCreatedAtDesc(DEMO_WORKSPACE_ID).stream()
                .map(AgentDto.Response::from)
                .toList();
    }

    public AgentEntity getRequired(UUID id) {
        return agentRepository.findById(id)
                .orElseThrow(() -> new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "Agent not found"));
    }

    public AgentDto.Response find(UUID id) {
        return AgentDto.Response.from(getRequired(id));
    }

    @Transactional
    public AgentDto.Response update(UUID id, AgentDto.UpdateRequest request) {
        AgentEntity agent = getRequired(id);
        agent.update(request.name(), request.purposeSummary());
        return AgentDto.Response.from(agent);
    }

    @Transactional
    public AgentDto.Response archive(UUID id) {
        AgentEntity agent = getRequired(id);
        agent.archive();
        return AgentDto.Response.from(agent);
    }

    public void requireActive(AgentEntity agent) {
        if (agent.getStatus() != AgentStatus.ACTIVE) {
            throw new BusinessException(ErrorCode.INVALID_STATE_TRANSITION, "Archived Agent cannot create a Release");
        }
    }
}
