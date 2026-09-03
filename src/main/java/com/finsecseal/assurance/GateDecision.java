package com.finsecseal.assurance;

import com.finsecseal.common.domain.DecisionValue;
import java.util.List;

public record GateDecision(DecisionValue value, String policyVersion, List<RuleResult> ruleTrace) {
    public record RuleResult(String ruleId, boolean triggered, String detail) {
    }
}
