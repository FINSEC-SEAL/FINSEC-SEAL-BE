package com.finsecseal.execution;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.release.AgentReleaseEntity;
import com.finsecseal.release.AgentReleaseRepository;
import com.finsecseal.release.FingerprintService;
import com.finsecseal.sandbox.SandboxFixtureService;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Executor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class TestRunStartService {

    private final AgentReleaseRepository releaseRepository;
    private final FingerprintService fingerprintService;
    private final SandboxFixtureService fixtureService;
    private final TestRunPersistenceService persistenceService;
    private final ExecutionDispatchService dispatchService;
    private final JdbcTemplate jdbcTemplate;
    private final Executor executor;

    public TestRunStartService(
            AgentReleaseRepository releaseRepository,
            FingerprintService fingerprintService,
            SandboxFixtureService fixtureService,
            TestRunPersistenceService persistenceService,
            ExecutionDispatchService dispatchService,
            JdbcTemplate jdbcTemplate,
            @Qualifier("testRunExecutor") Executor executor
    ) {
        this.releaseRepository = releaseRepository;
        this.fingerprintService = fingerprintService;
        this.fixtureService = fixtureService;
        this.persistenceService = persistenceService;
        this.dispatchService = dispatchService;
        this.jdbcTemplate = jdbcTemplate;
        this.executor = executor;
    }

    public TestRunPersistenceDto.Registered start(Request request, String actorId) {
        if (request == null
                || request.releaseId() == null
                || request.suiteId() == null
                || request.mode() == null) {
            throw new BusinessException(
                    ErrorCode.VALIDATION_ERROR,
                    "releaseId, suiteId and mode are required"
            );
        }

        List<UUID> caseIds = request.caseIds();
        if (caseIds == null || caseIds.isEmpty()) {
            caseIds = jdbcTemplate.queryForList(
                    "select id from test_cases where suite_id = ? order by case_key",
                    UUID.class,
                    request.suiteId()
            );
        }
        if (caseIds.isEmpty()) {
            throw new BusinessException(
                    ErrorCode.VALIDATION_ERROR,
                    "Test suite has no executable cases"
            );
        }

        AgentReleaseEntity release = releaseRepository.findById(request.releaseId())
                .orElseThrow(() -> new BusinessException(
                        ErrorCode.RESOURCE_NOT_FOUND,
                        "Release not found"
                ));

        String fixtureDigest = fixtureService.fixtureDigest();
        String modelConfigHash = fingerprintService.hash(
                release.getManifestJson().path("model")
        );

        TestRunPersistenceDto.Registered registered = persistenceService.register(
                new TestRunPersistenceDto.RegisterRequest(
                        request.releaseId(),
                        request.suiteId(),
                        request.contractVersionId(),
                        request.mode(),
                        null,
                        null,
                        fixtureDigest,
                        modelConfigHash,
                        request.randomSeed(),
                        caseIds.size()
                ),
                actorId
        );

        List<UUID> executionCaseIds = List.copyOf(caseIds);
        executor.execute(() -> {
            for (UUID caseId : executionCaseIds) {
                dispatchService.execute(registered.runId(), caseId, actorId);
            }
        });

        return registered;
    }

    public record Request(
            UUID releaseId,
            UUID suiteId,
            TestRunMode mode,
            UUID contractVersionId,
            List<UUID> caseIds,
            Long randomSeed
    ) {
    }
}
