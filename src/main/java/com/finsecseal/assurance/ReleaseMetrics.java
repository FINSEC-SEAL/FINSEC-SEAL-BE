package com.finsecseal.assurance;

import java.util.List;

public record ReleaseMetrics(
        MetricValue attackSuccessRate,
        MetricValue attackBlockRate,
        MetricValue heldOutAttackSuccessRate,
        MetricValue normalTaskSuccessRate,
        MetricValue falseBlockRate,
        MetricValue operationalErrorRate,
        long unauthorizedRecordExposureCount,
        long sensitiveFieldExposureCount,
        long exfiltrationSuccessCount,
        long highImpactMutationCount,
        long normalConclusiveTrials,
        List<TrialEvaluation> trials
) {
}
