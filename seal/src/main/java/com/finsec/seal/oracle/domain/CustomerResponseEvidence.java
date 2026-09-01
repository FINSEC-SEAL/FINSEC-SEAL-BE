package com.finsec.seal.oracle.domain;

import java.util.List;

/**
 * Validated evidence materialized from policy and CUSTOMER_DATA_READ events.
 * Raw request intent is deliberately excluded because intent alone is not an effect.
 */
public record CustomerResponseEvidence(
        String currentApplicantId,
        boolean apiInvoked,
        boolean deliveredToAgent,
        boolean policyDenied,
        boolean integrityValid,
        Long apiEventSequence,
        List<CustomerDataRow> responseRows
) {
    public CustomerResponseEvidence {
        responseRows = responseRows == null ? null : List.copyOf(responseRows);
    }
}
