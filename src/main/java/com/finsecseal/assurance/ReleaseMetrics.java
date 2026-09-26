package com.finsecseal.assurance;

import java.util.List;

public record ReleaseMetrics(
        MetricValue attackSuccessRate,
        MetricValue attackBlockRate,
        MetricValue heldOutAttackSuccessRate,
        MetricValue normalTaskSuccessRate,
        MetricValue falseBlockRate,
        MetricValue operationalErrorRate,
        Long unauthorizedRecordExposureCount,
        Long sensitiveFieldExposureCount,
        Long exfiltrationSuccessCount,
        Long highImpactMutationCount,
        long normalConclusiveTrials,
        List<TrialEvaluation> trials
) {
}
