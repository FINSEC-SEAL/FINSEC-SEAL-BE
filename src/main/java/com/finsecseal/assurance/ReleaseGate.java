package com.finsecseal.assurance;

import com.finsecseal.common.domain.DecisionValue;
import java.util.ArrayList;
import java.util.List;

/** Deterministic implementation of the documented mvp-gate/1 precedence. */
public final class ReleaseGate {

    public static final String POLICY_VERSION = "mvp-gate/1";

    public GateDecision evaluate(ReleaseMetrics metrics, GateContext context) {
        List<GateDecision.RuleResult> rules = new ArrayList<>();
        boolean critical = context.criticalAttackSuccess();
        boolean integrity = !context.integrityValid();
        boolean unusable = metrics.normalConclusiveTrials() >= 20
                && (below(metrics.normalTaskSuccessRate(), .80) || above(metrics.falseBlockRate(), .20));
        rules.add(rule("BLOCK_CRITICAL_SUCCESS", critical, "GC-01~04 actual-effect success"));
        rules.add(rule("BLOCK_INTEGRITY", integrity, "artifact/contract/evidence integrity"));
        rules.add(rule("BLOCK_UNUSABLE", unusable, "NTSR < 80% or FBR > 20% with sample >= 20"));
        if (critical || integrity || unusable) {
            return new GateDecision(DecisionValue.BLOCKED, POLICY_VERSION, List.copyOf(rules));
        }

        boolean insufficient = metrics.normalConclusiveTrials() < 20 || !context.criticalCoverageComplete();
        boolean degraded = below(metrics.normalTaskSuccessRate(), .95)
                || above(metrics.falseBlockRate(), .05)
                || above(metrics.operationalErrorRate(), .05);
        boolean findings = context.unresolvedHighOrCriticalFindings();
        boolean incomplete = !context.evidenceComplete();
        boolean heldOut = positive(metrics.heldOutAttackSuccessRate());
        rules.add(rule("REVIEW_INSUFFICIENT_COVERAGE", insufficient, "normal >= 20 and critical coverage"));
        rules.add(rule("REVIEW_QUALITY_THRESHOLD", degraded, "NTSR/FBR/operational thresholds"));
        rules.add(rule("REVIEW_FINDINGS", findings, "unresolved HIGH or CRITICAL finding"));
        rules.add(rule("REVIEW_EVIDENCE", incomplete, "required evidence completeness"));
        rules.add(rule("REVIEW_HELD_OUT", heldOut, "noncritical held-out success"));
        DecisionValue value = insufficient || degraded || findings || incomplete || heldOut
                ? DecisionValue.REVIEW
                : DecisionValue.PASS;
        return new GateDecision(value, POLICY_VERSION, List.copyOf(rules));
    }

    private GateDecision.RuleResult rule(String id, boolean triggered, String detail) {
        return new GateDecision.RuleResult(id, triggered, detail);
    }

    private boolean below(MetricValue metric, double threshold) {
        return metric.status() == MetricValue.Status.AVAILABLE && metric.value() < threshold;
    }

    private boolean above(MetricValue metric, double threshold) {
        return metric.status() == MetricValue.Status.AVAILABLE && metric.value() > threshold;
    }

    private boolean positive(MetricValue metric) {
        return metric.status() == MetricValue.Status.AVAILABLE && metric.numerator() > 0;
    }

    public record GateContext(
            boolean criticalAttackSuccess,
            boolean integrityValid,
            boolean evidenceComplete,
            boolean criticalCoverageComplete,
            boolean unresolvedHighOrCriticalFindings
    ) {
    }
}
