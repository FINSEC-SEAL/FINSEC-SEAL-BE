package com.finsecseal.release;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class EncryptionService {

    private static final String PREFIX = "aesgcm:v1:";
    private static final byte[] AAD = "finsec-seal/release-artifact/v1".getBytes(StandardCharsets.UTF_8);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final String configuredKey;

    public EncryptionService(@Value("${finsec.crypto.key-base64:}") String configuredKey) {
        this.configuredKey = configuredKey;
    }

    public String encrypt(String plaintext) {
        try {
            byte[] iv = new byte[12];
            RANDOM.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key(), new GCMParameterSpec(128, iv));
            cipher.updateAAD(AAD);
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return PREFIX + Base64.getEncoder().encodeToString(
                    ByteBuffer.allocate(iv.length + ciphertext.length).put(iv).put(ciphertext).array()
            );
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Artifact encryption failed", exception);
        }
    }

    public String decrypt(String encrypted) {
        if (encrypted == null || !encrypted.startsWith(PREFIX)) {
            throw new IllegalArgumentException("Unsupported encrypted artifact format");
        }
        try {
            byte[] envelope = Base64.getDecoder().decode(encrypted.substring(PREFIX.length()));
            if (envelope.length < 29) {
                throw new IllegalArgumentException("Encrypted artifact is truncated");
            }
            byte[] iv = java.util.Arrays.copyOfRange(envelope, 0, 12);
            byte[] ciphertext = java.util.Arrays.copyOfRange(envelope, 12, envelope.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, iv));
            cipher.updateAAD(AAD);
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new IllegalStateException("Artifact decryption failed", exception);
        }
    }

    private SecretKeySpec key() {
        if (configuredKey == null || configuredKey.isBlank()) {
            throw new BusinessException(
                    ErrorCode.CONFIGURATION_ERROR,
                    "FINSEC_DATA_ENCRYPTION_KEY_BASE64 must contain a 32-byte base64 key"
            );
        }
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(configuredKey);
        } catch (IllegalArgumentException exception) {
            throw new BusinessException(ErrorCode.CONFIGURATION_ERROR, "Encryption key is not valid base64");
        }
        if (decoded.length != 32) {
            throw new BusinessException(ErrorCode.CONFIGURATION_ERROR, "Encryption key must be exactly 32 bytes");
        }
        return new SecretKeySpec(decoded, "AES");
    }
}
