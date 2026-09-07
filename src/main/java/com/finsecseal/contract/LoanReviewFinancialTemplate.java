package com.finsecseal.contract;

import java.util.Objects;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/** Fixed policy rules from Safety Contract Specification sections 2 and 6. */
@Component
public final class LoanReviewFinancialTemplate {

    public static final String KEY = "loan-review/1";
    public static final String PURPOSE = "LOAN_DOCUMENT_COMPLETENESS_REVIEW";

    private final JsonNode rules;

    public LoanReviewFinancialTemplate(ObjectMapper objectMapper) {
        rules = Objects.requireNonNull(objectMapper, "objectMapper must not be null")
                .readTree("""
                        {
                          "schemaVersion": "1.0",
                          "purpose": "LOAN_DOCUMENT_COMPLETENESS_REVIEW",
                          "allowedTools": [
                            "CASE_CONTEXT_READ", "DOCUMENT_READER", "CUSTOMER_DATA_READ",
                            "LOAN_POLICY_SEARCH", "REVIEW_NOTE_WRITE"
                          ],
                          "resourcePolicies": {
                            "DOCUMENT_READER": {
                              "caseScope": "CURRENT_CASE_ONLY",
                              "documentScope": "ALLOWED_DOCUMENTS_ONLY"
                            },
                            "REVIEW_NOTE_WRITE": {"caseScope": "CURRENT_CASE_ONLY"}
                          },
                          "customerScope": {"type": "CURRENT_APPLICANT_ONLY"},
                          "fieldPolicy": {
                            "CUSTOMER_DATA_READ": {
                              "allowed": ["incomeBand", "employmentStatus"], "denyUnknown": true
                            }
                          },
                          "cardinality": {
                            "CUSTOMER_DATA_READ": {"maxRequestedRecords": 1, "maxReturnedRecords": 1}
                          },
                          "externalEgress": {"allowed": false, "allowedDestinations": []},
                          "workflow": {"allowedStages": ["DOCUMENT_REVIEW"]},
                          "highImpactActions": {"LOAN_DECISION_UPDATE": "HUMAN_ONLY"},
                          "toolTrust": {
                            "requireTrustedTool": true, "allowedTrustLevels": ["TRUSTED_INTERNAL"]
                          },
                          "outputPolicy": {
                            "reviewStatusAllowed": ["READY_FOR_HUMAN_REVIEW", "NEEDS_MORE_DOCUMENTS"]
                          },
                          "metadata": {"templateVersion": "loan-review/1", "validatorVersion": "1.0"}
                        }
                        """);
    }

    /** Returns independent rules without allocating a persisted identity or applying approval. */
    public JsonNode policyRules() {
        return rules.deepCopy();
    }
}
