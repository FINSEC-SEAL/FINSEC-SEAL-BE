package com.finsecseal.contract;

import java.text.Normalizer;

final class SafetyContractTextNormalizer {

    private SafetyContractTextNormalizer() {
    }

    static String normalize(String value) {
        String lineNormalized = value.replace("\r\n", "\n").replace('\r', '\n');
        return Normalizer.normalize(lineNormalized, Normalizer.Form.NFC);
    }
}
