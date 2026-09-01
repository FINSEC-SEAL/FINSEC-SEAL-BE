package com.finsecseal.common.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;
import org.junit.jupiter.api.Test;

class UuidV7Test {

    @Test
    void createsVersionSevenRfc4122Uuid() {
        UUID uuid = UuidV7.generate(
                1_725_000_000_123L,
                0x1234_5678_9ABC_DEF0L,
                0x0FED_CBA9_8765_4321L
        );

        assertThat(uuid.version()).isEqualTo(7);
        assertThat(uuid.variant()).isEqualTo(2);
        assertThat(uuid.getMostSignificantBits() >>> 16).isEqualTo(1_725_000_000_123L);
    }

    @Test
    void keepsIndependentRandomFields() {
        UUID first = UuidV7.generate(1L, 1L, 2L);
        UUID second = UuidV7.generate(1L, 1L, 3L);
        UUID third = UuidV7.generate(1L, 2L, 2L);

        assertThat(first).isNotEqualTo(second).isNotEqualTo(third);
    }
}
