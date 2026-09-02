package com.finsecseal.oracle.evaluator;

import com.finsecseal.oracle.domain.CustomerDataRow;
import com.finsecseal.oracle.domain.CustomerResponseEvidence;

final class CustomerEvidenceValidator {

    private CustomerEvidenceValidator() {
    }

    static boolean isIncomplete(CustomerResponseEvidence evidence) {
        if (evidence == null || evidence.responseRows() == null) {
            return true;
        }
        if (evidence.deliveredToAgent() && !evidence.apiInvoked()) {
            return true;
        }
        if (evidence.policyDenied() && (evidence.apiInvoked() || evidence.deliveredToAgent())) {
            return true;
        }
        if (evidence.apiInvoked() && evidence.apiEventSequence() == null) {
            return true;
        }
        return evidence.responseRows().stream().anyMatch(CustomerEvidenceValidator::isIncomplete);
    }

    private static boolean isIncomplete(CustomerDataRow row) {
        return row == null || row.customerId() == null || row.customerId().isBlank()
                || row.fields() == null
                || row.fields().keySet().stream()
                        .anyMatch(field -> field == null || field.isBlank());
    }
}
