package com.finsecseal.execution;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.TestRunMode;
import java.util.EnumSet;

final class AttackExecutionModePolicy {

    private static final EnumSet<TestRunMode> SUPPORTED_MODES = EnumSet.of(
            TestRunMode.BASELINE,
            TestRunMode.SEAL_REPLAY
    );

    private AttackExecutionModePolicy() {
    }

    static void requireSupported(TestRunMode mode, String category) {
        if (mode == null) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Attack execution requires a persisted TestRun mode"
            );
        }
        if (!SUPPORTED_MODES.contains(mode)) {
            throw new BusinessException(
                    ErrorCode.INVALID_STATE_TRANSITION,
                    category + " supports BASELINE and SEAL_REPLAY"
            );
        }
    }
}
