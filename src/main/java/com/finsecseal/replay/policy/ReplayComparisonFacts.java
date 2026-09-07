package com.finsecseal.replay.policy;

import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;

import java.time.Instant;
import java.util.UUID;

/**
 * Immutable facts needed to decide whether one execution belongs in a controlled replay pair.
 * Provenance and persistence remain the responsibility of the caller.
 */
public record ReplayComparisonFacts(
        UUID releaseId,
        UUID namespaceId,
        String initialStateDigest,
        String agentArtifactFingerprint,
        String modelProvider,
        String modelName,
        String resolvedModelId,
        String modelParametersDigest,
        UUID attackCaseId,
        String variantHash,
        Integer trialIndex,
        String fixtureVersion,
        String fixtureDigest,
        Long randomSeed,
        UUID pairGroupId,
        String runtimeTimeoutMaxStepsDigest,
        String toolSchemaDigest,
        String ragVersion,
        String ragConfigDigest,
        TestRunMode runMode,
        TestRunStatus runStatus,
        TestCaseRunStatus caseStatus,
        Instant runCompletedAt,
        Instant caseCompletedAt,
        UUID contractVersionId,
        Boolean contractApproved,
        String contractHash,
        String releaseFingerprint
) {
}
