package com.finsecseal.oracle.application;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.finding.FindingDto;
import com.finsecseal.finding.FindingService;
import com.finsecseal.oracle.domain.OracleOutcome;
import com.finsecseal.oracle.domain.OracleResult;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

/** Persists one deterministic evaluation and its causally ordered evidence events. */
@Service
public class OracleAssessmentService {

    private final OracleResultService oracleResultService;
    private final FindingService findingService;
    private final ExecutionEventService eventService;
    private final ObjectMapper objectMapper;

    public OracleAssessmentService(
            OracleResultService oracleResultService,
            FindingService findingService,
            ExecutionEventService eventService,
            ObjectMapper objectMapper
    ) {
        this.oracleResultService = oracleResultService;
        this.findingService = findingService;
        this.eventService = eventService;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public Assessment record(
            UUID runId,
            UUID testCaseRunId,
            UUID traceId,
            UUID sourceEventId,
            OracleResult result,
            String actorId
    ) {
        if (runId == null || testCaseRunId == null || traceId == null || result == null) {
            throw new BusinessException(
                    ErrorCode.VALIDATION_ERROR,
                    "Run, TestCaseRun, trace, and OracleResult are required"
            );
        }

        OracleResultService.Stored stored = oracleResultService.persist(
                testCaseRunId, sourceEventId, result, actorId
        );
        if (!stored.context().runId().equals(runId)) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "TestCaseRun does not belong to TestRun");
        }
        if (!stored.created()) {
            return new Assessment(stored.result(), findExistingFinding(stored.result()), false);
        }

        appendOracleEvent(runId, testCaseRunId, traceId, stored.result(), actorId);

        FindingDto.View finding = null;
        if (result.outcome() == OracleOutcome.ATTACK_SUCCESS) {
            FindingService.Stored storedFinding = findingService.createFromAttackSuccess(
                    stored.result(),
                    new FindingService.Context(
                            stored.context().workspaceId(),
                            stored.context().runId(),
                            stored.context().releaseId(),
                            stored.context().category(),
                            stored.context().severity()
                    ),
                    actorId
            );
            finding = storedFinding.finding();
            if (storedFinding.created()) {
                appendFindingEvent(runId, testCaseRunId, traceId, finding, actorId);
            }
        }
        return new Assessment(stored.result(), finding, true);
    }

    private FindingDto.View findExistingFinding(OracleResultDto.View result) {
        if (result.outcome() != OracleOutcome.ATTACK_SUCCESS) {
            return null;
        }
        return findingService.findByRun(result.runId()).items().stream()
                .filter(finding -> finding.sourceOracleResultId().equals(result.id()))
                .findFirst()
                .orElseThrow(() -> new BusinessException(
                        ErrorCode.EVIDENCE_INCOMPLETE,
                        "ATTACK_SUCCESS OracleResult is missing its Finding"
                ));
    }

    private void appendOracleEvent(
            UUID runId,
            UUID testCaseRunId,
            UUID traceId,
            OracleResultDto.View result,
            String actorId
    ) {
        ObjectNode metadata = objectMapper.createObjectNode();
        metadata.put("schemaVersion", "1.0");
        metadata.put("oracleResultId", result.id().toString());
        metadata.put("oracleType", result.oracleType().name());
        metadata.put("oracleVersion", result.oracleVersion());
        metadata.put("outcome", result.outcome().name());
        metadata.put("invariantId", result.invariantId());
        metadata.put("evidenceDigest", result.evidenceDigest());
        eventService.append(
                runId,
                new ExecutionEventDto.AppendRequest(
                        testCaseRunId,
                        traceId,
                        ExecutionEventType.ORACLE_EVALUATED,
                        null,
                        null,
                        null,
                        null,
                        result.reasonCode().name(),
                        metadata
                ),
                actorId
        );
    }

    private void appendFindingEvent(
            UUID runId,
            UUID testCaseRunId,
            UUID traceId,
            FindingDto.View finding,
            String actorId
    ) {
        ObjectNode metadata = objectMapper.createObjectNode();
        metadata.put("schemaVersion", "1.0");
        metadata.put("findingId", finding.id().toString());
        metadata.put("category", finding.category());
        metadata.put("severity", finding.severity());
        metadata.put("oracleResultId", finding.sourceOracleResultId().toString());
        eventService.append(
                runId,
                new ExecutionEventDto.AppendRequest(
                        testCaseRunId,
                        traceId,
                        ExecutionEventType.FINDING_CREATED,
                        null,
                        null,
                        null,
                        null,
                        "FINDING_CREATED",
                        metadata
                ),
                actorId
        );
    }

    public record Assessment(
            OracleResultDto.View oracleResult,
            FindingDto.View finding,
            boolean created
    ) {
    }
}
