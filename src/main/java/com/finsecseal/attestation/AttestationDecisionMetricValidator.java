package com.finsecseal.attestation;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.databind.JsonNode;

/** Validates frozen report structure/provenance; it never recalculates D evidence or a Gate. */
final class AttestationDecisionMetricValidator {
    static final List<String> FIELDS = List.of(
            "policyLatency", "completionRate", "trialSuccessDistribution", "attackRateBreakdown");
    private final JdbcTemplate jdbc;

    AttestationDecisionMetricValidator(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    void validate(UUID releaseId, JsonNode snapshot) {
        Context context = new Context(releaseId, snapshot);
        if (snapshot.has("policyLatency")) latency(context, snapshot.path("policyLatency"));
        if (snapshot.has("completionRate")) completion(context, snapshot.path("completionRate"));
        if (snapshot.has("trialSuccessDistribution")) distribution(context, snapshot.path("trialSuccessDistribution"));
        if (snapshot.has("attackRateBreakdown")) breakdown(context, snapshot.path("attackRateBreakdown"));
    }

    private void latency(Context context, JsonNode report) {
        String path = "policyLatency";
        boolean available = available(report, path);
        long observed = count(report.path("observedEventCount"), path);
        long invalid = count(report.path("invalidEventCount"), path);
        Set<UUID> events = ids(report.path("sourceEventIds"), path);
        Set<UUID> runs = runs(context, report.path("sourceRunIds"), path, true);
        if (invalid > observed || observed != events.size()
                || (available && (observed == 0 || invalid != 0))
                || (!available && observed > 0 && invalid == 0)) incomplete(path);
        for (String field : List.of("averageMs", "p50Ms", "p95Ms", "p99Ms")) {
            if (available) number(report.path(field), path);
            else requireNull(report.path(field), path);
        }
        if (available && (report.path("p50Ms").decimalValue().compareTo(report.path("p95Ms").decimalValue()) > 0
                || report.path("p95Ms").decimalValue().compareTo(report.path("p99Ms").decimalValue()) > 0)) {
            incomplete(path);
        }
        Set<UUID> eventRuns = new HashSet<>();
        if (!events.isEmpty()) {
            List<UUID> selected = jdbc.query("""
                    select run_id from execution_events
                     where id = any(?::uuid[]) and event_type = 'POLICY_EVALUATED'
                    """, (row, index) -> row.getObject("run_id", UUID.class),
                    (Object) events.toArray(UUID[]::new));
            if (selected.size() != events.size()) incomplete(path);
            eventRuns.addAll(selected);
        }
        if (!eventRuns.equals(runs)) incomplete(path);
    }

    private void completion(Context context, JsonNode report) {
        String path = "completionRate";
        boolean available = available(report, path);
        Set<UUID> sources = runs(context, report.path("sourceRunIds"), path, false);
        if (!available) {
            for (String field : List.of("numerator", "denominator", "value", "cancelledTrials", "unmaterializedTrials")) {
                requireNull(report.path(field), path);
            }
            return;
        }
        long numerator = fraction(report, path);
        long denominator = count(report.path("denominator"), path);
        long cancelled = count(report.path("cancelledTrials"), path);
        long unmaterialized = count(report.path("unmaterializedTrials"), path);
        if (sources.isEmpty() || cancelled > denominator - numerator
                || unmaterialized > denominator - numerator - cancelled) incomplete(path);
        // No live Run counts/status progress are compared to the frozen fraction.
    }

    private void distribution(Context context, JsonNode report) {
        String path = "trialSuccessDistribution";
        boolean available = available(report, path);
        Set<UUID> sources = runs(context, report.path("sourceRunIds"), path, true);
        JsonNode cases = array(report.path("cases"), path);
        JsonNode categories = array(report.path("categories"), path);
        Set<String> caseKeys = new HashSet<>();
        Set<UUID> caseRuns = new HashSet<>();
        Set<UUID> observedRuns = new HashSet<>();
        boolean anyAvailable = false;
        for (JsonNode item : cases) {
            boolean conclusive = available(item, path);
            anyAvailable |= conclusive;
            UUID run = uuid(item.path("runId"), path);
            UUID testCase = uuid(item.path("testCaseId"), path);
            if (!sources.contains(run) || !caseKeys.add(run + "/" + testCase)) incomplete(path);
            observedRuns.add(run);
            for (String field : List.of("mode", "caseKey", "caseType", "category", "partition")) text(item.path(field), path);
            JsonNode trials = array(item.path("orderedTrials"), path);
            if (trials.isEmpty()) incomplete(path);
            long previousIndex = -1;
            for (JsonNode trial : trials) {
                UUID caseRun = uuid(trial.path("caseRunId"), path);
                long index = count(trial.path("trialIndex"), path);
                if (!run.equals(uuid(trial.path("runId"), path))
                        || !testCase.equals(uuid(trial.path("testCaseId"), path))
                        || !caseRuns.add(caseRun) || index <= previousIndex) incomplete(path);
                previousIndex = index;
                List<String> statuses = jdbc.query("""
                        select trial.status from test_case_runs trial
                        join test_runs run on run.id = trial.test_run_id
                        join test_cases test_case on test_case.id = trial.test_case_id
                         where trial.id = ? and trial.test_run_id = ? and trial.test_case_id = ?
                           and trial.trial_index = ? and test_case.suite_id = run.suite_id
                           and run.mode = ? and test_case.case_key = ? and test_case.case_type = ?
                           and test_case.category = ? and test_case.partition_name = ?
                        """, (row, rowIndex) -> row.getString("status"), caseRun, run, testCase, index,
                        item.path("mode").asString(), item.path("caseKey").asString(),
                        item.path("caseType").asString(), item.path("category").asString(),
                        item.path("partition").asString());
                if (statuses.size() != 1) incomplete(path);
                sealedTrial(trial, statuses.get(0), path);
            }
            trialCounts(item, path);
        }
        if (available != anyAvailable || (!cases.isEmpty() && !sources.equals(observedRuns))) incomplete(path);
        Set<String> categoryKeys = new HashSet<>();
        Set<UUID> categorized = new HashSet<>();
        for (JsonNode category : categories) {
            available(category, path);
            String key = categoryKey(category, path);
            if (!categoryKeys.add(key)) incomplete(path);
            List<JsonNode> expected = new ArrayList<>();
            for (JsonNode item : cases) {
                if (categoryKey(item, path).equals(key)) item.path("orderedTrials").forEach(expected::add);
            }
            JsonNode ordered = array(category.path("orderedTrials"), path);
            if (expected.isEmpty() || ordered.size() != expected.size()) incomplete(path);
            Set<UUID> categoryRuns = new HashSet<>();
            for (int index = 0; index < ordered.size(); index++) {
                JsonNode trial = ordered.get(index);
                if (!trial.equals(expected.get(index)) || !categorized.add(uuid(trial.path("caseRunId"), path))) incomplete(path);
                categoryRuns.add(uuid(trial.path("runId"), path));
            }
            if (!runs(context, category.path("sourceRunIds"), path, true).equals(categoryRuns)) incomplete(path);
            trialCounts(category, path);
        }
        if (!categorized.equals(caseRuns)) incomplete(path);
    }

    private void trialCounts(JsonNode item, String path) {
        boolean available = available(item, path);
        JsonNode ordered = array(item.path("orderedTrials"), path);
        JsonNode bits = array(item.path("successBits"), path);
        if (bits.size() != ordered.size()) incomplete(path);
        long trials = 0;
        long successes = 0;
        for (int index = 0; index < ordered.size(); index++) {
            JsonNode trial = ordered.get(index);
            if (!trial.isObject() || !trial.path("secondaryInconclusive").isBoolean()
                    || !bits.get(index).equals(trial.path("successBit"))) incomplete(path);
            JsonNode bit = trial.path("successBit");
            if (bit.isNull()) {
                String reason = text(trial.path("exclusionReason"), path);
                boolean inconclusive = trial.path("secondaryInconclusive").asBoolean();
                if (("INCONCLUSIVE_ORACLE".equals(reason) && !inconclusive)
                        || ("MISSING_REQUIRED_ORACLE".equals(reason) && inconclusive)
                        || ("REPLAY_NOT_COMPARABLE".equals(reason)
                            && !"SEAL_REPLAY".equals(item.path("mode").asString()))) incomplete(path);
            }
            else {
                // Validate the exact integer before narrowing (2^64 + 1 is not a bit).
                long bitValue = count(bit, path);
                if (bitValue != 0 && bitValue != 1) incomplete(path);
                // D retains an observed ATTACK success despite a secondary inconclusive Oracle;
                // every other inconclusive trial must remain excluded from the rate.
                if (trial.path("secondaryInconclusive").asBoolean()
                        && (!"ATTACK".equals(item.path("caseType").asString()) || bitValue != 1)) incomplete(path);
                requireNull(trial.path("exclusionReason"), path);
                trials++;
                successes += bitValue;
            }
        }
        if (available != (trials > 0) || count(item.path("excludedTrials"), path) != ordered.size() - trials) incomplete(path);
        if (available) {
            if (count(item.path("successCount"), path) != successes || count(item.path("trials"), path) != trials) incomplete(path);
        } else {
            requireNull(item.path("successCount"), path);
            requireNull(item.path("trials"), path);
        }
    }

    private void sealedTrial(JsonNode trial, String status, String path) {
        String reason = trial.path("exclusionReason").isString() ? trial.path("exclusionReason").asString() : null;
        // Read only the immutable CaseRun result, never live Oracle/comparability evidence.
        if (("ERROR".equals(status)
                && (!trial.path("successBit").isNull() || !"OPERATIONAL_ERROR".equals(reason)))
                || ("CANCELLED".equals(status)
                    && (!trial.path("successBit").isNull() || !"CANCELLED".equals(reason)))
                || ("CANCELLED".equals(reason) && !"CANCELLED".equals(status))
                || ("NON_TERMINAL_CASE".equals(reason)
                    && Set.of("PASSED", "FAILED_SECURITY", "FAILED_FUNCTIONAL", "ERROR", "CANCELLED")
                            .contains(status))) incomplete(path);
    }

    private void breakdown(Context context, JsonNode report) {
        String path = "attackRateBreakdown";
        boolean available = available(report, path);
        Set<UUID> sources = runs(context, report.path("sourceRunIds"), path, true);
        JsonNode groups = array(report.path("groups"), path);
        if (!groups.isEmpty() && attackWitnesses(sources, null, false) != sources.size()) incomplete(path);
        Set<String> dimensions = new HashSet<>();
        boolean anyAvailable = false;
        for (JsonNode group : groups) {
            boolean conclusive = available(group, path);
            anyAvailable |= conclusive;
            String key = dimension(group, path);
            if (!dimensions.add(key)) incomplete(path);
            count(group.path("excludedTrials"), path);
            Set<UUID> groupRuns = runs(context, group.path("sourceRunIds"), path, true);
            if (!sources.containsAll(groupRuns)) incomplete(path);
            // Observed excluded-only sources witness an N_A dimension; its conclusive sources stay empty.
            if (attackWitnesses(sources, group, false) == 0
                    || attackWitnesses(groupRuns, group, conclusive) != groupRuns.size()) incomplete(path);
            if (conclusive) {
                long numerator = fraction(group, path);
                if (groupRuns.isEmpty() || !group.path("anySuccess").isBoolean()
                        || group.path("anySuccess").asBoolean() != (numerator > 0)) incomplete(path);
            } else {
                for (String field : List.of("numerator", "denominator", "value", "anySuccess")) requireNull(group.path(field), path);
                if (!groupRuns.isEmpty()) incomplete(path);
            }
        }
        if (available != anyAvailable) incomplete(path);
        if (!context.snapshot().has("trialSuccessDistribution")) return;
        // Cross-check declarations against the already validated report, never
        // against live Oracle values or a replacement D calculation.
        Set<String> observedDimensions = new HashSet<>();
        Set<UUID> observedRuns = new HashSet<>();
        for (JsonNode item : context.snapshot().at("/trialSuccessDistribution/cases")) {
            if (!"ATTACK".equals(item.path("caseType").asString())) continue;
            observedDimensions.add(dimension(item, path));
            observedRuns.add(uuid(item.path("runId"), path));
        }
        if (!dimensions.equals(observedDimensions) || !sources.equals(observedRuns)) incomplete(path);
        for (JsonNode group : groups) {
            Set<UUID> conclusiveRuns = new HashSet<>();
            long numerator = 0;
            long denominator = 0;
            long excluded = 0;
            for (JsonNode item : context.snapshot().at("/trialSuccessDistribution/cases")) {
                if ("ATTACK".equals(item.path("caseType").asString())
                        && dimension(item, path).equals(dimension(group, path))) {
                    for (JsonNode trial : item.path("orderedTrials")) {
                        if (trial.path("successBit").isNull()) excluded++;
                        else {
                            denominator++;
                            numerator += count(trial.path("successBit"), path);
                            conclusiveRuns.add(uuid(item.path("runId"), path));
                        }
                    }
                }
            }
            if (!ids(group.path("sourceRunIds"), path).equals(conclusiveRuns)
                    || count(group.path("excludedTrials"), path) != excluded
                    || "AVAILABLE".equals(group.path("status").asString()) != (denominator > 0)) incomplete(path);
            if (denominator > 0 && (count(group.path("numerator"), path) != numerator
                    || count(group.path("denominator"), path) != denominator)) incomplete(path);
        }
    }

    private int attackWitnesses(Set<UUID> sources, JsonNode dimension, boolean conclusiveOnly) {
        if (sources.isEmpty()) return 0;
        String filter = dimension == null ? "" :
                " and run.mode = ? and test_case.category = ? and test_case.partition_name = ?";
        List<Object> arguments = new ArrayList<>();
        arguments.add(sources.toArray(UUID[]::new));
        if (dimension != null) {
            arguments.add(dimension.path("mode").asString());
            arguments.add(dimension.path("category").asString());
            arguments.add(dimension.path("partition").asString());
        }
        Integer matches = jdbc.queryForObject("""
                select count(*) from test_runs run where run.id = any(?::uuid[])
                  and exists (select 1 from test_case_runs trial
                    join test_cases test_case on test_case.id = trial.test_case_id
                    where trial.test_run_id = run.id and test_case.suite_id = run.suite_id
                      and test_case.case_type = 'ATTACK'
                """ + filter
                + (conclusiveOnly ? " and trial.status in ('PASSED','FAILED_SECURITY','FAILED_FUNCTIONAL')" : "")
                + ")", Integer.class, arguments.toArray());
        return matches == null ? 0 : matches;
    }

    private String categoryKey(JsonNode item, String path) {
        return text(item.path("mode"), path) + "/" + text(item.path("caseType"), path)
                + "/" + text(item.path("category"), path);
    }

    private String dimension(JsonNode item, String path) {
        return text(item.path("mode"), path) + "/" + text(item.path("category"), path)
                + "/" + text(item.path("partition"), path);
    }

    private Set<UUID> runs(Context context, JsonNode values, String path, boolean terminal) {
        Set<UUID> sources = ids(values, path);
        if (sources.isEmpty()) return sources;
        String status = terminal ? " and run.status in ('COMPLETED', 'FAILED')" : "";
        Integer matches = jdbc.queryForObject("""
                select count(*) from test_runs run
                 where run.id = any(?::uuid[]) and run.release_id = ? and run.suite_id = ?
                   and run.fixture_version = ? and run.fixture_digest = ?
                   and run.agent_artifact_fingerprint = ? and run.release_fingerprint = ?
                """ + status, Integer.class, (Object) sources.toArray(UUID[]::new), context.releaseId(),
                UUID.fromString(context.snapshot().at("/testSuite/id").asString()),
                context.snapshot().at("/sandbox/fixtureVersion").asString(),
                context.snapshot().at("/sandbox/fixtureDigest").asString(),
                context.snapshot().at("/release/agentArtifactFingerprint").asString(),
                context.snapshot().at("/release/fingerprint").asString());
        if (matches == null || matches != sources.size()) incomplete(path);
        return sources;
    }

    private Set<UUID> ids(JsonNode values, String path) {
        Set<UUID> result = new LinkedHashSet<>();
        for (JsonNode value : array(values, path)) {
            if (!result.add(uuid(value, path))) incomplete(path);
        }
        return result;
    }

    private UUID uuid(JsonNode value, String path) {
        String text = text(value, path);
        try {
            UUID result = UUID.fromString(text);
            if (!result.toString().equalsIgnoreCase(text)) incomplete(path);
            return result;
        } catch (IllegalArgumentException invalid) {
            throw new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, path + " has invalid provenance");
        }
    }

    private boolean available(JsonNode value, String path) {
        if (!value.isObject()) incomplete(path);
        String status = text(value.path("status"), path);
        if ("AVAILABLE".equals(status)) {
            requireNull(value.path("reason"), path);
            return true;
        }
        if (!"N_A".equals(status)) incomplete(path);
        text(value.path("reason"), path);
        return false;
    }

    private long fraction(JsonNode value, String path) {
        long numerator = count(value.path("numerator"), path);
        long denominator = count(value.path("denominator"), path);
        number(value.path("value"), path);
        if (denominator == 0 || numerator > denominator) incomplete(path);
        // D serializes a Double quotient. Compare its shortest decimal without narrowing the declared value.
        BigDecimal expected = BigDecimal.valueOf((double) numerator / denominator);
        if (value.path("value").decimalValue().compareTo(expected) != 0) incomplete(path);
        return numerator;
    }

    private long count(JsonNode value, String path) {
        if (!value.isIntegralNumber() || value.bigIntegerValue().signum() < 0
                || value.bigIntegerValue().bitLength() > 63) incomplete(path);
        return value.longValue();
    }

    private void number(JsonNode value, String path) {
        if (!value.isNumber()) incomplete(path);
        Number number = value.numberValue();
        // D latency uses finite BigDecimal quantities, without a binary-double range limit.
        if ((number instanceof Double floatingDouble && !Double.isFinite(floatingDouble))
                || (number instanceof Float floatingFloat && !Float.isFinite(floatingFloat))
                || value.decimalValue().signum() < 0) incomplete(path);
    }

    private JsonNode array(JsonNode value, String path) {
        if (!value.isArray()) incomplete(path);
        return value;
    }

    private String text(JsonNode value, String path) {
        if (!value.isString() || value.asString().isBlank()) incomplete(path);
        return value.asString();
    }

    private void requireNull(JsonNode value, String path) {
        if (!value.isNull()) incomplete(path);
    }

    private void incomplete(String path) {
        throw new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, path + " has inconsistent report evidence");
    }

    private record Context(UUID releaseId, JsonNode snapshot) { }
}
