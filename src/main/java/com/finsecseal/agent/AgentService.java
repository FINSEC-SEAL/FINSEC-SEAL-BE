package com.finsecseal.agent;

import com.finsecseal.audit.AuditService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.AgentStatus;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import java.util.List;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Service
@Transactional(readOnly = true)
public class AgentService {

    public static final UUID DEMO_WORKSPACE_ID = UUID.fromString("0198f1e2-0000-7000-8000-000000000001");

    private final AgentRepository agentRepository;
    private final AuditService auditService;
    private final ObjectMapper objectMapper;
    private final CanonicalJsonService canonicalJsonService;
    private final DigestService digestService;

    public AgentService(
            AgentRepository agentRepository,
            AuditService auditService,
            ObjectMapper objectMapper,
            CanonicalJsonService canonicalJsonService,
            DigestService digestService
    ) {
        this.agentRepository = agentRepository;
        this.auditService = auditService;
        this.objectMapper = objectMapper;
        this.canonicalJsonService = canonicalJsonService;
        this.digestService = digestService;
    }

    @Transactional
    public AgentDto.Response create(AgentDto.CreateRequest request) {
        return create(request, "demo-user");
    }

    @Transactional
    public AgentDto.Response create(AgentDto.CreateRequest request, String actorId) {
        AgentEntity entity = new AgentEntity(
                DEMO_WORKSPACE_ID,
                request.agentKey(),
                request.name(),
                request.purposeSummary()
        );
        try {
            AgentDto.Response response = AgentDto.Response.from(agentRepository.saveAndFlush(entity));
            ObjectNode state = stateDocument(response);
            auditService.append(
                    DEMO_WORKSPACE_ID, normalizeActor(actorId), "AGENT_CREATED", "AGENT", response.id(),
                    null, digest(state), state
            );
            return response;
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
        return update(id, request, "demo-user");
    }

    @Transactional
    public AgentDto.Response update(UUID id, AgentDto.UpdateRequest request, String actorId) {
        AgentEntity agent = getRequiredForUpdate(id);
        String beforeDigest = digest(stateDocument(AgentDto.Response.from(agent)));
        agent.update(request.name(), request.purposeSummary());
        AgentDto.Response response = AgentDto.Response.from(agent);
        ObjectNode state = stateDocument(response);
        auditService.append(
                agent.getWorkspaceId(), normalizeActor(actorId), "AGENT_UPDATED", "AGENT", id,
                beforeDigest, digest(state), state
        );
        return response;
    }

    @Transactional
    public AgentDto.Response archive(UUID id) {
        return archive(id, "demo-user");
    }

    @Transactional
    public AgentDto.Response archive(UUID id, String actorId) {
        AgentEntity agent = getRequiredForUpdate(id);
        String beforeDigest = digest(stateDocument(AgentDto.Response.from(agent)));
        agent.archive();
        AgentDto.Response response = AgentDto.Response.from(agent);
        ObjectNode state = stateDocument(response);
        auditService.append(
                agent.getWorkspaceId(), normalizeActor(actorId), "AGENT_ARCHIVED", "AGENT", id,
                beforeDigest, digest(state), state
        );
        return response;
    }

    public void requireActive(AgentEntity agent) {
        if (agent.getStatus() != AgentStatus.ACTIVE) {
            throw new BusinessException(ErrorCode.INVALID_STATE_TRANSITION, "Archived Agent cannot create a Release");
        }
    }

    public AgentEntity getRequiredForUpdate(UUID id) {
        return agentRepository.findByIdForUpdate(id)
                .orElseThrow(() -> new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "Agent not found"));
    }

    private ObjectNode stateDocument(AgentDto.Response response) {
        ObjectNode state = objectMapper.createObjectNode();
        state.put("schemaVersion", "1.0");
        state.put("agentKey", response.agentKey());
        state.put("name", response.name());
        state.put("purposeSummary", response.purposeSummary());
        state.put("status", response.status().name());
        return state;
    }

    private String digest(ObjectNode state) {
        return digestService.sha256(canonicalJsonService.canonicalize(state));
    }

    private String normalizeActor(String actorId) {
        if (actorId == null || actorId.isBlank()) {
            return "demo-user";
        }
        if (actorId.length() > 120) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "X-Actor-Id exceeds 120 characters");
        }
        return actorId;
    }
}
