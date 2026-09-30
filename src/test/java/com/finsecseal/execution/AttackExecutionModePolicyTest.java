package com.finsecseal.execution;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.TestRunMode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class AttackExecutionModePolicyTest {

    @ParameterizedTest
    @EnumSource(value = TestRunMode.class, names = {"BASELINE", "SEAL_REPLAY"})
    void acceptsExecutableAttackModes(TestRunMode mode) {
        assertThatCode(() -> AttackExecutionModePolicy.requireSupported(mode, "FA-02"))
                .doesNotThrowAnyException();
    }

    @ParameterizedTest
    @EnumSource(value = TestRunMode.class, names = {"HELD_OUT", "REGRESSION"})
    void rejectsModesWithoutAttackExecutionSemantics(TestRunMode mode) {
        assertThatThrownBy(() -> AttackExecutionModePolicy.requireSupported(mode, "FA-02"))
                .isInstanceOfSatisfying(BusinessException.class, exception -> {
                    assertThat(exception.errorCode()).isEqualTo(ErrorCode.INVALID_STATE_TRANSITION);
                    assertThat(exception.getMessage()).contains("BASELINE and SEAL_REPLAY");
                });
    }

    @Test
    void rejectsMissingPersistedMode() {
        assertThatThrownBy(() -> AttackExecutionModePolicy.requireSupported(null, "FA-02"))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE));
    }
}
