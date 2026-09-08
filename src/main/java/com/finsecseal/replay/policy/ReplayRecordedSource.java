package com.finsecseal.replay.policy;

import java.time.Instant;
import java.util.UUID;

/**
 * Required owner read of immutable controls recorded for the same historical case/trial.
 * Current configuration, current sandbox state and caller assertions are not substitutes.
 * No default implementation or production registration is supplied by C.
 */
public interface ReplayRecordedSource {
    RecordedCaseControls caseControls(UUID runId, UUID testCaseRunId);

    /** Missing controls remain null; a missing record is a source failure. */
    record RecordedCaseControls(
            UUID runId,
            UUID testCaseRunId,
            UUID pairGroupId,
            Long randomSeed,
            Instant caseCompletedAt,
            UUID namespaceId,
            String initialStateDigest,
            String resolvedModelId,
            String modelParametersDigest,
            String runtimeTimeoutMaxStepsDigest,
            String toolSchemaDigest,
            String ragVersion,
            String ragConfigDigest
    ) {
        @Override
        public String toString() { return "RecordedCaseControls[historical controls]"; }
    }
}
