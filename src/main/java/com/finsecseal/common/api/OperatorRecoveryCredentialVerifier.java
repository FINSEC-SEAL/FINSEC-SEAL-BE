package com.finsecseal.common.api;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class OperatorRecoveryCredentialVerifier {

    private final byte[] recoveryKey;

    public OperatorRecoveryCredentialVerifier(
            @Value("${finsec.idempotency.recovery-key:}") String recoveryKey
    ) {
        this.recoveryKey = recoveryKey.getBytes(StandardCharsets.UTF_8);
        if (this.recoveryKey.length > 0 && this.recoveryKey.length < 32) {
            throw new IllegalStateException("FINSEC_IDEMPOTENCY_RECOVERY_KEY must contain at least 32 bytes");
        }
    }

    public String verify(String suppliedRecoveryKey, String actorId) {
        if (recoveryKey.length == 0) {
            throw new BusinessException(
                    ErrorCode.CONFIGURATION_ERROR,
                    "Idempotency recovery is disabled until FINSEC_IDEMPOTENCY_RECOVERY_KEY is configured"
            );
        }
        byte[] supplied = suppliedRecoveryKey == null
                ? new byte[0]
                : suppliedRecoveryKey.getBytes(StandardCharsets.UTF_8);
        if (!MessageDigest.isEqual(recoveryKey, supplied)) {
            throw new BusinessException(ErrorCode.OPERATOR_AUTH_REQUIRED, "Valid operator recovery credentials are required");
        }
        if (actorId == null || !actorId.startsWith("operator:") || actorId.length() > 120) {
            throw new BusinessException(
                    ErrorCode.OPERATOR_AUTH_REQUIRED,
                    "X-Actor-Id must identify an operator using the operator: prefix"
            );
        }
        return actorId;
    }
}
