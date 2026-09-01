package com.finsecseal.common.persistence;

import java.security.SecureRandom;
import java.time.Clock;
import java.util.UUID;

public final class UuidV7 {

    private static final SecureRandom RANDOM = new SecureRandom();

    private UuidV7() {
    }

    public static UUID generate() {
        return generate(Clock.systemUTC().millis(), RANDOM.nextLong(), RANDOM.nextLong());
    }

    static UUID generate(long unixMillis, long randomA, long randomB) {
        if (unixMillis < 0 || unixMillis > 0xFFFFFFFFFFFFL) {
            throw new IllegalArgumentException("unixMillis must fit in 48 bits");
        }
        long mostSignificantBits = (unixMillis << 16) | 0x7000L | (randomA & 0x0FFFL);
        long leastSignificantBits = 0x8000000000000000L | (randomB & 0x3FFFFFFFFFFFFFFFL);
        return new UUID(mostSignificantBits, leastSignificantBits);
    }
}
