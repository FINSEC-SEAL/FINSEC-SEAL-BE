package com.finsecseal.policy;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Immutable server-side registry, release-binding, and policy facts for Tool Trust.
 *
 * <p>Inconsistencies that can be observed for the requested Tool are intentionally retained so
 * the evaluator can return a structured operational integrity failure. Unrelated malformed
 * configuration is rejected while constructing the snapshot.</p>
 */
public record PolicyToolTrustFacts(
        String requestedTool,
        String expectedReleaseFingerprint,
        String observedReleaseFingerprint,
        List<ToolRegistryEntry> registryEntries,
        List<ReleaseToolBinding> releaseBindings,
        ToolTrustPolicy trustPolicy
) {

    private static final Pattern SHA_256 = Pattern.compile("^sha256:[0-9a-f]{64}$");

    public PolicyToolTrustFacts {
        requestedTool = requireNonBlank(requestedTool, "requestedTool");
        expectedReleaseFingerprint = requireDigest(
                expectedReleaseFingerprint,
                "expectedReleaseFingerprint"
        );
        observedReleaseFingerprint = requireDigest(
                observedReleaseFingerprint,
                "observedReleaseFingerprint"
        );
        registryEntries = copyUniqueRegistryEntries(registryEntries);
        releaseBindings = copyUniqueReleaseBindings(releaseBindings);
        if (trustPolicy == null) {
            throw new IllegalArgumentException("trustPolicy must not be null");
        }
        validateUnrelatedBindingReferences(requestedTool, registryEntries, releaseBindings);
    }

    public List<ReleaseToolBinding> requestedReleaseBindings() {
        return releaseBindings.stream()
                .filter(binding -> binding.toolName().equals(requestedTool))
                .toList();
    }

    public Optional<ToolRegistryEntry> registryEntryFor(ReleaseToolBinding binding) {
        if (binding == null) {
            throw new IllegalArgumentException("binding must not be null");
        }
        ToolIdentity identity = binding.identity();
        return registryEntries.stream()
                .filter(entry -> entry.identity().equals(identity))
                .findFirst();
    }

    public boolean releaseFingerprintMatches() {
        return expectedReleaseFingerprint.equals(observedReleaseFingerprint);
    }

    private static List<ToolRegistryEntry> copyUniqueRegistryEntries(
            List<ToolRegistryEntry> values
    ) {
        if (values == null) {
            throw new IllegalArgumentException("registryEntries must not be null");
        }

        List<ToolRegistryEntry> snapshot = new ArrayList<>(values);
        Set<ToolIdentity> identities = new HashSet<>();
        for (ToolRegistryEntry entry : snapshot) {
            if (entry == null) {
                throw new IllegalArgumentException(
                        "registryEntries must not contain null entries"
                );
            }
            if (!identities.add(entry.identity())) {
                throw new IllegalArgumentException(
                        "registryEntries must not contain duplicate Tool identities"
                );
            }
        }
        return List.copyOf(snapshot);
    }

    private static List<ReleaseToolBinding> copyUniqueReleaseBindings(
            List<ReleaseToolBinding> values
    ) {
        if (values == null) {
            throw new IllegalArgumentException("releaseBindings must not be null");
        }

        List<ReleaseToolBinding> snapshot = new ArrayList<>(values);
        Set<ToolIdentity> identities = new HashSet<>();
        for (ReleaseToolBinding binding : snapshot) {
            if (binding == null) {
                throw new IllegalArgumentException(
                        "releaseBindings must not contain null entries"
                );
            }
            if (!identities.add(binding.identity())) {
                throw new IllegalArgumentException(
                        "releaseBindings must not contain duplicate Tool identities"
                );
            }
        }
        return List.copyOf(snapshot);
    }

    private static void validateUnrelatedBindingReferences(
            String requestedTool,
            List<ToolRegistryEntry> registryEntries,
            List<ReleaseToolBinding> releaseBindings
    ) {
        Set<ToolIdentity> registryIdentities = new HashSet<>();
        for (ToolRegistryEntry entry : registryEntries) {
            registryIdentities.add(entry.identity());
        }

        for (ReleaseToolBinding binding : releaseBindings) {
            if (!binding.toolName().equals(requestedTool)
                    && !registryIdentities.contains(binding.identity())) {
                throw new IllegalArgumentException(
                        "releaseBindings must reference registry Tool identities"
                );
            }
        }
    }

    private static List<TrustLevel> copyUniqueTrustLevels(List<TrustLevel> values) {
        if (values == null) {
            throw new IllegalArgumentException("allowedTrustLevels must not be null");
        }

        List<TrustLevel> snapshot = new ArrayList<>(values);
        Set<TrustLevel> unique = new HashSet<>();
        for (TrustLevel trustLevel : snapshot) {
            if (trustLevel == null) {
                throw new IllegalArgumentException(
                        "allowedTrustLevels must not contain null entries"
                );
            }
            if (!unique.add(trustLevel)) {
                throw new IllegalArgumentException(
                        "allowedTrustLevels must not contain duplicates"
                );
            }
        }
        return List.copyOf(snapshot);
    }

    private static String requireNonBlank(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value;
    }

    private static String requireDigest(String value, String field) {
        if (value == null || !SHA_256.matcher(value).matches()) {
            throw new IllegalArgumentException(field + " must be a lowercase sha256 digest");
        }
        return value;
    }

    public record ToolRegistryEntry(
            String toolName,
            String version,
            TrustLevel trustLevel,
            String schemaDigest,
            String descriptionDigest
    ) {

        public ToolRegistryEntry {
            toolName = requireNonBlank(toolName, "registry toolName");
            version = requireNonBlank(version, "registry version");
            if (trustLevel == null) {
                throw new IllegalArgumentException("registry trustLevel must not be null");
            }
            schemaDigest = requireDigest(schemaDigest, "registry schemaDigest");
            descriptionDigest = requireDigest(
                    descriptionDigest,
                    "registry descriptionDigest"
            );
        }

        private ToolIdentity identity() {
            return new ToolIdentity(toolName, version);
        }
    }

    public record ReleaseToolBinding(
            String toolName,
            String version,
            boolean enabled,
            String schemaDigest,
            String descriptionDigest
    ) {

        public ReleaseToolBinding {
            toolName = requireNonBlank(toolName, "release binding toolName");
            version = requireNonBlank(version, "release binding version");
            schemaDigest = requireDigest(schemaDigest, "release binding schemaDigest");
            descriptionDigest = requireDigest(
                    descriptionDigest,
                    "release binding descriptionDigest"
            );
        }

        private ToolIdentity identity() {
            return new ToolIdentity(toolName, version);
        }
    }

    public record ToolTrustPolicy(
            boolean requireTrustedTool,
            List<TrustLevel> allowedTrustLevels
    ) {

        public ToolTrustPolicy {
            allowedTrustLevels = copyUniqueTrustLevels(allowedTrustLevels);
            if (requireTrustedTool && allowedTrustLevels.isEmpty()) {
                throw new IllegalArgumentException(
                        "required Tool trust policy must allow at least one trust level"
                );
            }
        }

        public boolean allows(TrustLevel trustLevel) {
            return allowedTrustLevels.contains(trustLevel);
        }
    }

    public enum TrustLevel {
        TRUSTED_INTERNAL,
        MIXED,
        SANDBOXED
    }

    private record ToolIdentity(String toolName, String version) {
    }
}
