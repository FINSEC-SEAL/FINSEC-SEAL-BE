package com.finsecseal.release;

import static org.assertj.core.api.Assertions.assertThat;

import com.finsecseal.common.domain.ReleaseLifecycleState;
import org.junit.jupiter.api.Test;

class ReleaseLifecycleStateTest {

    @Test
    void permitsOnlyDocumentedTransitions() {
        assertThat(ReleaseLifecycleState.DRAFT.canTransitionTo(ReleaseLifecycleState.ANALYZED)).isTrue();
        assertThat(ReleaseLifecycleState.ANALYZED.canTransitionTo(ReleaseLifecycleState.PASS)).isFalse();
        assertThat(ReleaseLifecycleState.REMEDIATION.canTransitionTo(ReleaseLifecycleState.VERIFYING)).isTrue();
        assertThat(ReleaseLifecycleState.PASS.canTransitionTo(ReleaseLifecycleState.NEEDS_REVALIDATION)).isTrue();
    }
}
