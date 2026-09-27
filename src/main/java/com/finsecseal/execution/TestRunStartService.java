package com.finsecseal.execution;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.evidence.AuthenticatedTestRunRegistrationService;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.release.AgentReleaseEntity;
import com.finsecseal.release.AgentReleaseRepository;
import com.finsecseal.release.FingerprintService;
import com.finsecseal.sandbox.SandboxFixtureService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Service
public class TestRunStartService {

    private static final int MAX_CASES = 10_000;
    private static final String SUITE_SQL = """
            select suite.fixture_version, suite.status
              from agent_releases release
              join agents agent on agent.id = release.agent_id
              join test_suites suite on suite.id = ?
             where release.id = ? and suite.workspace_id = agent.workspace_id
            """;
    private static final String EXPLICIT_CASES_SQL = """
            select id, partition_name, hidden_from_patch_generator
              from test_cases
             where suite_id = ? and id = any(?::uuid[])
            """;

    private final AgentReleaseRepository releaseRepository;
    private final FingerprintService fingerprintService;
    private final SandboxFixtureService fixtureService;
    private final AuthenticatedTestRunRegistrationService admissionService;
    private final ExecutionDispatchService dispatchService;
    private final RunExecutionLifecycleService lifecycleService;
    private final JdbcTemplate jdbcTemplate;
    private final Executor executor;

    public TestRunStartService(
            AgentReleaseRepository releaseRepository,
            FingerprintService fingerprintService,
            SandboxFixtureService fixtureService,
            AuthenticatedTestRunRegistrationService admissionService,
            ExecutionDispatchService dispatchService,
            RunExecutionLifecycleService lifecycleService,
            JdbcTemplate jdbcTemplate,
            @Qualifier("testRunExecutor") Executor executor
    ) {
        this.releaseRepository = releaseRepository;
        this.fingerprintService = fingerprintService;
        this.fixtureService = fixtureService;
        this.admissionService = admissionService;
        this.dispatchService = dispatchService;
        this.lifecycleService = lifecycleService;
        this.jdbcTemplate = jdbcTemplate;
        this.executor = executor;
    }

    @Transactional
    public TestRunPersistenceDto.Registered start(Request request, HttpServletRequest httpRequest) {
        if (request == null
                || request.releaseId() == null
                || request.suiteId() == null
                || request.mode() == null) {
            throw new BusinessException(
                    ErrorCode.VALIDATION_ERROR,
                    "releaseId, suiteId and mode are required"
            );
        }

        List<UUID> requestedCaseIds = request.caseIds() == null
                ? List.of() : new ArrayList<>(request.caseIds());
        validateRequestedCases(request.mode(), requestedCaseIds);

        AgentReleaseEntity release = releaseRepository.findById(request.releaseId())
                .orElseThrow(() -> new BusinessException(
                        ErrorCode.RESOURCE_NOT_FOUND,
                        "Release not found"
                ));

        SuiteSnapshot suite = requireReadySuite(request.releaseId(), request.suiteId());
        List<UUID> caseIds = selectCaseIds(request.suiteId(), request.mode(), requestedCaseIds);
        String fixtureDigest = fixtureService.fixtureDigest(suite.fixtureVersion());
        String modelConfigHash = fingerprintService.hash(
                release.getManifestJson().path("model")
        );

        AuthenticatedTestRunRegistrationService.Admission admission = admissionService.register(
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
                httpRequest
        );
        if (admission == null || admission.run() == null || admission.run().runId() == null
                || admission.run().status() != TestRunStatus.QUEUED
                || admission.actorId() == null || admission.actorId().isBlank()
                || admission.actorId().length() > 120
                || !admission.actorId().equals(admission.actorId().strip())) {
            throw new BusinessException(ErrorCode.INTERNAL_ERROR,
                    "Authenticated TestRun admission was incomplete");
        }
        TestRunPersistenceDto.Registered registered = admission.run();
        UUID admittedRunId = registered.runId();
        String admittedActorId = admission.actorId();

        if (!caseIds.equals(selectCaseIds(request.suiteId(), request.mode(), requestedCaseIds))) {
            throw new BusinessException(ErrorCode.RESOURCE_CONFLICT,
                    "Test case selection changed during Run registration");
        }
        if (!TransactionSynchronizationManager.isSynchronizationActive()
                || !TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new IllegalStateException("TestRun start requires an active transaction");
        }
        List<UUID> executionCaseIds = List.copyOf(caseIds);
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                try {
                    executor.execute(() -> {
                        for (UUID caseId : executionCaseIds) {
                            dispatchService.execute(admittedRunId, caseId, admittedActorId);
                        }
                    });
                } catch (RejectedExecutionException rejected) {
                    lifecycleService.rejectScheduling(admittedRunId, UUID.randomUUID(), admittedActorId);
                    throw new BusinessException(ErrorCode.INTERNAL_ERROR,
                            "TestRun scheduling was rejected");
                }
            }
        });

        return registered;
    }

    private SuiteSnapshot requireReadySuite(UUID releaseId, UUID suiteId) {
        List<SuiteSnapshot> suites = jdbcTemplate.query(SUITE_SQL,
                (resultSet, rowNumber) -> new SuiteSnapshot(
                        resultSet.getString("fixture_version"), resultSet.getString("status")),
                suiteId, releaseId);
        if (suites.size() != 1) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "TestSuite not found");
        }
        SuiteSnapshot suite = suites.getFirst();
        if (!"READY".equals(suite.status())) {
            throw new BusinessException(ErrorCode.INVALID_STATE_TRANSITION,
                    "TestSuite must be READY");
        }
        return suite;
    }

    private void validateRequestedCases(TestRunMode mode, List<UUID> requestedCaseIds) {
        if (mode == TestRunMode.HELD_OUT && !requestedCaseIds.isEmpty()) {
            throw invalidSelection();
        }
        if (requestedCaseIds.size() > MAX_CASES || requestedCaseIds.stream().anyMatch(id -> id == null)
                || new HashSet<>(requestedCaseIds).size() != requestedCaseIds.size()) {
            throw invalidSelection();
        }
    }

    private List<UUID> selectCaseIds(UUID suiteId, TestRunMode mode, List<UUID> requestedCaseIds) {
        List<CaseCandidate> candidates;
        if (requestedCaseIds.isEmpty()) {
            candidates = jdbcTemplate.query("""
                    select id, partition_name, hidden_from_patch_generator
                      from test_cases
                     where suite_id = ? and %s
                     order by case_key, id
                     limit 10001
                    """.formatted(eligibleSql(mode)), (resultSet, rowNumber) -> new CaseCandidate(
                    resultSet.getObject("id", UUID.class),
                    resultSet.getString("partition_name"),
                    resultSet.getBoolean("hidden_from_patch_generator")), suiteId);
            if (candidates.isEmpty() || candidates.size() > MAX_CASES) {
                throw invalidSelection();
            }
            return candidates.stream().map(CaseCandidate::id).toList();
        }

        candidates = jdbcTemplate.query(EXPLICIT_CASES_SQL, (resultSet, rowNumber) -> new CaseCandidate(
                resultSet.getObject("id", UUID.class),
                resultSet.getString("partition_name"),
                resultSet.getBoolean("hidden_from_patch_generator")),
                suiteId, (Object) requestedCaseIds.toArray(UUID[]::new));
        if (candidates.size() != requestedCaseIds.size()) {
            throw invalidSelection();
        }
        Set<UUID> eligibleIds = new HashSet<>();
        for (CaseCandidate candidate : candidates) {
            if (!eligible(mode, candidate) || !eligibleIds.add(candidate.id())) {
                throw invalidSelection();
            }
        }
        if (!eligibleIds.containsAll(requestedCaseIds)) {
            throw invalidSelection();
        }
        return List.copyOf(requestedCaseIds);
    }

    private String eligibleSql(TestRunMode mode) {
        return switch (mode) {
            case BASELINE -> "partition_name in ('SEED','MUTATION','NORMAL') and not hidden_from_patch_generator";
            case SEAL_REPLAY -> "partition_name in ('SEED','MUTATION') and not hidden_from_patch_generator";
            case HELD_OUT -> "partition_name = 'HELD_OUT' and hidden_from_patch_generator";
            case REGRESSION -> "partition_name = 'NORMAL' and not hidden_from_patch_generator";
        };
    }

    private boolean eligible(TestRunMode mode, CaseCandidate candidate) {
        if (candidate.hidden()) {
            return mode == TestRunMode.HELD_OUT && "HELD_OUT".equals(candidate.partition());
        }
        return switch (mode) {
            case BASELINE -> Set.of("SEED", "MUTATION", "NORMAL").contains(candidate.partition());
            case SEAL_REPLAY -> Set.of("SEED", "MUTATION").contains(candidate.partition());
            case HELD_OUT -> false;
            case REGRESSION -> "NORMAL".equals(candidate.partition());
        };
    }

    private BusinessException invalidSelection() {
        return new BusinessException(ErrorCode.VALIDATION_ERROR,
                "Test case selection is invalid for this Run");
    }

    private record SuiteSnapshot(String fixtureVersion, String status) {
    }

    private record CaseCandidate(UUID id, String partition, boolean hidden) {
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
