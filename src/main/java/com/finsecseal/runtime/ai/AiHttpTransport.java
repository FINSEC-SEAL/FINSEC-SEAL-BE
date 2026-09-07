package com.finsecseal.runtime.ai;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;

final class AiHttpTransport {

    private static final Set<Integer> RETRYABLE_STATUSES = Set.of(408, 429, 502, 503, 504);

    private final HttpClient httpClient;
    private final int maxAttempts;
    private final long retryBaseDelayMs;

    AiHttpTransport(HttpClient httpClient, int maxAttempts, long retryBaseDelayMs) {
        this.httpClient = httpClient;
        this.maxAttempts = maxAttempts;
        this.retryBaseDelayMs = retryBaseDelayMs;
    }

    byte[] postJson(
            URI endpoint,
            Duration timeout,
            byte[] requestBody,
            String apiKey,
            int maxResponseBytes,
            String operationName
    ) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(endpoint)
                .timeout(timeout)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(requestBody));

        if (apiKey != null && !apiKey.isBlank()) {
            builder.header("Authorization", "Bearer " + apiKey);
        }

        HttpRequest request = builder.build();

        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                HttpResponse<InputStream> response = httpClient.send(
                        request,
                        HttpResponse.BodyHandlers.ofInputStream()
                );
                int statusCode = response.statusCode();

                if (RETRYABLE_STATUSES.contains(statusCode)) {
                    closeQuietly(response.body());
                    if (attempt == maxAttempts) {
                        throw internalFailure(
                                operationName + " failed with retryable HTTP " + statusCode
                                        + " after " + maxAttempts + " attempts",
                                null
                        );
                    }
                    sleepBeforeRetry(attempt, operationName);
                    continue;
                }

                if (statusCode >= 500) {
                    closeQuietly(response.body());
                    throw internalFailure(operationName + " failed with HTTP " + statusCode, null);
                }

                if (statusCode < 200 || statusCode >= 300) {
                    closeQuietly(response.body());
                    throw new BusinessException(
                            ErrorCode.EVIDENCE_INCOMPLETE,
                            operationName + " was rejected with HTTP " + statusCode
                    );
                }

                try {
                    return readBoundedResponse(response.body(), maxResponseBytes, operationName);
                } finally {
                    closeQuietly(response.body());
                }
            } catch (java.net.http.HttpTimeoutException exception) {
                if (attempt == maxAttempts) {
                    throw internalFailure(
                            operationName + " timed out after " + maxAttempts + " attempts",
                            exception
                    );
                }
                sleepBeforeRetry(attempt, operationName);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                throw internalFailure(operationName + " was interrupted", exception);
            } catch (IOException exception) {
                if (attempt == maxAttempts) {
                    throw internalFailure(
                            operationName + " failed after " + maxAttempts + " attempts",
                            exception
                    );
                }
                sleepBeforeRetry(attempt, operationName);
            }
        }

        throw internalFailure(operationName + " exhausted retry attempts", null);
    }

    private byte[] readBoundedResponse(InputStream body, int maxResponseBytes, String operationName)
            throws IOException {
        if (body == null) {
            return new byte[0];
        }

        byte[] bytes = body.readNBytes(maxResponseBytes + 1);
        if (bytes.length > maxResponseBytes) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    operationName + " response exceeds " + maxResponseBytes + " bytes"
            );
        }
        return bytes;
    }

    private void sleepBeforeRetry(int failedAttempt, String operationName) {
        long baseDelay = retryBaseDelayMs * (1L << (failedAttempt - 1));
        long jitterBound = Math.max(1L, baseDelay / 3L);
        long delayMs = baseDelay + ThreadLocalRandom.current().nextLong(jitterBound);

        try {
            Thread.sleep(delayMs);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw internalFailure(operationName + " retry backoff was interrupted", exception);
        }
    }

    private void closeQuietly(InputStream body) {
        if (body == null) {
            return;
        }

        try {
            body.close();
        } catch (IOException ignored) {
            // Response stream is already discarded.
        }
    }

    private BusinessException internalFailure(String message, Exception cause) {
        if (cause == null) {
            return new BusinessException(ErrorCode.INTERNAL_ERROR, message);
        }
        return new BusinessException(
                ErrorCode.INTERNAL_ERROR,
                message + ": " + cause.getClass().getSimpleName()
        );
    }
}
