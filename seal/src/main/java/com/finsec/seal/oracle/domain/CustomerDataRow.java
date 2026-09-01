package com.finsec.seal.oracle.domain;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** A materialized row from a validated CUSTOMER_DATA_READ response. */
public record CustomerDataRow(String customerId, Map<String, Object> fields) {

    public CustomerDataRow {
        fields = fields == null
                ? null
                : Collections.unmodifiableMap(new LinkedHashMap<>(fields));
    }
}
