package com.finsecseal.release;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Base64;
import org.junit.jupiter.api.Test;

class EncryptionServiceTest {

    @Test
    void encryptsWithRandomNonceAndAuthenticatesCiphertext() {
        String key = Base64.getEncoder().encodeToString(new byte[32]);
        EncryptionService service = new EncryptionService(key);

        String first = service.encrypt("synthetic secret");
        String second = service.encrypt("synthetic secret");

        assertThat(first).isNotEqualTo(second);
        assertThat(service.decrypt(first)).isEqualTo("synthetic secret");
        String tampered = first.substring(0, first.length() - 2) + "AA";
        assertThatThrownBy(() -> service.decrypt(tampered))
                .isInstanceOf(IllegalStateException.class);
    }
}
