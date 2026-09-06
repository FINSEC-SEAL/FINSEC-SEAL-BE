# Tool Call Idempotency Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Spring-owned, DB-enforced exactly-once semantics for every state-changing sandbox Tool invocation using `(test_case_run_id, tool_call_id)`.

**Architecture:** Use the persisted `TOOL_PROPOSED.eventId` as the canonical `toolCallId`. Propagate a Spring-owned `ToolInvocation` through AgentToolLoop → ToolDispatcher → PolicyGateway. Read-only adapters continue the current direct path, while state-changing adapters execute through a transactional `StateChangingToolExecutionService` backed by Flyway V13.

**Tech Stack:** Java 21, Spring Boot, Spring JDBC, PostgreSQL 17, Flyway, JUnit 5, AssertJ, Testcontainers.

**Spec:** `docs/superpowers/specs/2026-09-06-tool-call-idempotency-design.md`

## Global Constraints

- Spring owns canonical `tool_call_id`.
- `toolCallId = TOOL_PROPOSED.eventId`.
- `requestDigest = TOOL_PROPOSED.payloadDigest`.
- AI/provider identifiers are never authoritative.
- `ToolProposal` shape remains unchanged.
- `SandboxExecutionContext` shape remains unchanged.
- Flyway V1-V12 must remain byte-for-byte untouched.
- `LOAN_DECISION_UPDATE` and `EXTERNAL_HTTP` are state-changing adapters.
- Real network access remains impossible for `EXTERNAL_HTTP`.
- Same `(test_case_run_id, tool_call_id)` plus same request executes mutation at most once.
- Same identity plus a different request fails with `IDEMPOTENCY_CONFLICT`.
- New state-changing execution wraps reservation, Tool execution evidence, adapter mutation, and receipt completion in one Spring transaction.
- Existing Oracle ownership boundaries are unchanged.
- Existing FA-05 completed-TestRun replay remains separate from adapter-level idempotency.

---

## Pre-Implementation Baseline Gate

Before Task 1, confirm the branch is the intended FA-05 branch and isolate the already-developed FA-05 work from Task 8.

- [ ] **Step 1: Check branch and working tree**

Run:

```bash
cd ~/back-end-project/FINSEC-SEAL-BE
git branch --show-current
git status --short --untracked-files=all
```

Expected branch:

```text
feat/development-b-fa05
```

- [ ] **Step 2: Verify the already-developed FA-05 regression set**

Run:

```bash
./gradlew test \
  --tests "com.finsecseal.attack.AttackSeedCatalogFa05ContractTest" \
  --tests "com.finsecseal.sandbox.tool.LoanDecisionUpdateMockToolAdapterContractTest" \
  --tests "com.finsecseal.sandbox.tool.LoanDecisionUpdateMockToolAdapterSafetyIntegrationTest" \
  --tests "com.finsecseal.sandbox.tool.LoanDecisionUpdateMockToolAdapterIntegrationTest" \
  --tests "com.finsecseal.sandbox.SandboxFixtureServiceLoanDecisionSnapshotIntegrationTest" \
  --tests "com.finsecseal.execution.HighImpactToolLoopOracleEvaluatorIntegrationTest" \
  --tests "com.finsecseal.oracle.evaluator.HighImpactMutationOracleTest" \
  --tests "com.finsecseal.execution.Fa05GoldenFlowIntegrationTest" \
  --tests "com.finsecseal.execution.Fa04GoldenFlowIntegrationTest" \
  --stacktrace
```

Expected:

```text
BUILD SUCCESSFUL
```

- [ ] **Step 3: Ensure Task 8 starts from an intentional Git boundary**

If FA-05 implementation files are still uncommitted, commit them separately before Task 8:

```bash
git add \
  src/main/java/com/finsecseal/attack/AttackSeedCatalog.java \
  src/main/java/com/finsecseal/sandbox/SandboxFixtureService.java \
  src/main/java/com/finsecseal/execution/Fa05ExecutionOrchestrator.java \
  src/main/java/com/finsecseal/execution/HighImpactToolLoopOracleEvaluator.java \
  src/main/java/com/finsecseal/sandbox/tool/LoanDecisionUpdateMockToolAdapter.java \
  src/test/java/com/finsecseal/attack/AttackSeedCatalogFa05ContractTest.java \
  src/test/java/com/finsecseal/execution/Fa05GoldenFlowIntegrationTest.java \
  src/test/java/com/finsecseal/execution/HighImpactToolLoopOracleEvaluatorIntegrationTest.java \
  src/test/java/com/finsecseal/sandbox/SandboxFixtureServiceLoanDecisionSnapshotIntegrationTest.java \
  src/test/java/com/finsecseal/sandbox/tool/LoanDecisionUpdateMockToolAdapterContractTest.java \
  src/test/java/com/finsecseal/sandbox/tool/LoanDecisionUpdateMockToolAdapterIntegrationTest.java \
  src/test/java/com/finsecseal/sandbox/tool/LoanDecisionUpdateMockToolAdapterSafetyIntegrationTest.java
```

Verify:

```bash
git diff --cached --check
git status --short
```

Commit:

```bash
git commit -m "feat: add FA-05 high-impact action abuse flow"
```

Do not include the Task 8 design/plan documents in this commit if they were already committed separately.

---

# File Structure

## New production files

- `src/main/java/com/finsecseal/runtime/ToolInvocation.java`
  - Spring-owned Tool invocation identity and proposal payload.
- `src/main/java/com/finsecseal/sandbox/tool/ToolEffect.java`
  - Adapter capability enum: `READ_ONLY`, `STATE_CHANGING`.
- `src/main/java/com/finsecseal/sandbox/tool/StateChangingToolExecutionService.java`
  - Transactional idempotency reservation, adapter invocation, Tool execution evidence, duplicate reconstruction.
- `src/main/resources/db/migration/V13__sandbox_tool_idempotency.sql`
  - DB schema and guards for `(test_case_run_id, tool_call_id)`.

## Modified production files

- `src/main/java/com/finsecseal/runtime/AgentRuntimeService.java`
  - Return persisted proposal identity for initial and follow-up proposals.
- `src/main/java/com/finsecseal/runtime/AgentToolLoopService.java`
  - Carry `ToolInvocation` between runtime and dispatcher while retaining existing `ToolStep.proposal()` compatibility.
- `src/main/java/com/finsecseal/sandbox/tool/ToolDispatcher.java`
  - Dispatch `ToolInvocation`.
- `src/main/java/com/finsecseal/sandbox/tool/PolicyGateway.java`
  - Accept `ToolInvocation` instead of bare `ToolProposal`.
- `src/main/java/com/finsecseal/sandbox/tool/TemporaryPolicyGatewayBridge.java`
  - Read-only direct path; state-changing path delegates to `StateChangingToolExecutionService`.
- `src/main/java/com/finsecseal/sandbox/tool/ToolAdapter.java`
  - Declare static adapter effect.
- `src/main/java/com/finsecseal/sandbox/tool/ExternalHttpMockToolAdapter.java`
  - Declare `STATE_CHANGING`.
- `src/main/java/com/finsecseal/sandbox/tool/LoanDecisionUpdateMockToolAdapter.java`
  - Declare `STATE_CHANGING`.

## New/modified tests

- `src/test/java/com/finsecseal/runtime/ToolInvocationPropagationIntegrationTest.java`
- `src/test/java/com/finsecseal/sandbox/tool/StateChangingToolIdempotencyIntegrationTest.java`
- `src/test/java/com/finsecseal/sandbox/tool/StateChangingToolIdempotencyConflictIntegrationTest.java`
- `src/test/java/com/finsecseal/sandbox/tool/StateChangingToolIdempotencyConcurrencyIntegrationTest.java`
- Existing FA-03/04/05 and adapter tests for regression.

---

### Task 1: Canonical Tool Invocation Identity

**Files:**
- Create: `src/main/java/com/finsecseal/runtime/ToolInvocation.java`
- Modify: `src/main/java/com/finsecseal/runtime/AgentRuntimeService.java`
- Modify: `src/main/java/com/finsecseal/runtime/AgentToolLoopService.java`
- Modify: `src/main/java/com/finsecseal/sandbox/tool/ToolDispatcher.java`
- Modify: `src/main/java/com/finsecseal/sandbox/tool/PolicyGateway.java`
- Modify: `src/main/java/com/finsecseal/sandbox/tool/TemporaryPolicyGatewayBridge.java`
- Test: `src/test/java/com/finsecseal/runtime/ToolInvocationPropagationIntegrationTest.java`

**Interfaces:**
- Consumes:
  - `ToolProposal(String toolName, JsonNode arguments)`
  - `ExecutionEventDto.Event.eventId()`
  - `ExecutionEventDto.Event.payloadDigest()`
- Produces:

```java
public record ToolInvocation(
        ToolProposal proposal,
        UUID toolCallId,
        String requestDigest
) {
}
```

`ToolDispatcher` target signature:

```java
public DispatchResult dispatch(
        SandboxExecutionContext context,
        ToolInvocation invocation,
        String actorId
)
```

`PolicyGateway` target signature:

```java
GatewayResult invoke(
        SandboxExecutionContext context,
        ToolInvocation invocation,
        String actorId
);
```

`AgentRuntimeService.recordFollowUpToolProposal(...)` target return type:

```java
ToolInvocation
```

- [ ] **Step 1: Write the failing propagation test**

Create `ToolInvocationPropagationIntegrationTest.java` with two assertions:

```java
@Test
void initialInvocationUsesPersistedToolProposedEventIdentity() {
    AgentRuntimeService.RuntimeTurn turn =
            runtimeService.proposeTool(context, attackVariant, "role-b");

    ToolInvocation invocation = new ToolInvocation(
            turn.aiResponse().proposal(),
            turn.proposalEvent().eventId(),
            turn.proposalEvent().payloadDigest()
    );

    assertThat(invocation.toolCallId())
            .isEqualTo(turn.proposalEvent().eventId());
    assertThat(invocation.requestDigest())
            .isEqualTo(turn.proposalEvent().payloadDigest());
}

@Test
void followUpProposalReturnsItsOwnPersistedInvocationIdentity() {
    ToolInvocation invocation =
            runtimeService.recordFollowUpToolProposal(
                    context,
                    attackVariant,
                    nextProposal,
                    sourceModelResponseEventId,
                    sourceModelResponseSequence,
                    "role-b"
            );

    ExecutionEventDto.Event persisted =
            eventService.findById(invocation.toolCallId());

    assertThat(persisted.eventType())
            .isEqualTo(ExecutionEventType.TOOL_PROPOSED);
    assertThat(invocation.requestDigest())
            .isEqualTo(persisted.payloadDigest());
    assertThat(invocation.proposal().toolName())
            .isEqualTo(persisted.toolName());
}
```

The test should compile only after `ToolInvocation` exists; for strict RED without production code, first write it using reflection if necessary so the failure is caused by the missing contract rather than a Java compile error.

- [ ] **Step 2: Run the propagation test and verify RED**

Run:

```bash
./gradlew test \
  --tests "com.finsecseal.runtime.ToolInvocationPropagationIntegrationTest" \
  --stacktrace
```

Expected RED reason:

```text
ToolInvocation contract is not implemented
```

or a reflection-based missing method/class assertion. Do not accept unrelated Spring context or fixture failures.

- [ ] **Step 3: Implement `ToolInvocation`**

Create:

```java
package com.finsecseal.runtime;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import java.util.UUID;

public record ToolInvocation(
        ToolProposal proposal,
        UUID toolCallId,
        String requestDigest
) {
    public ToolInvocation {
        if (proposal == null
                || toolCallId == null
                || requestDigest == null
                || !requestDigest.matches("sha256:[0-9a-f]{64}")) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Tool invocation requires proposal, toolCallId, and SHA-256 request digest"
            );
        }
    }
}
```

- [ ] **Step 4: Change follow-up proposal recording to return `ToolInvocation`**

In `AgentRuntimeService.recordFollowUpToolProposal(...)`, capture the appended event:

```java
ExecutionEventDto.Event proposalEvent = eventService.append(
        context.runId(),
        new ExecutionEventDto.AppendRequest(
                context.caseRunId(),
                context.traceId(),
                ExecutionEventType.TOOL_PROPOSED,
                validatedProposal.toolName(),
                validatedProposal.arguments(),
                null,
                null,
                "STRUCTURED_TOOL_PROPOSAL",
                objectMapper.createObjectNode()
                        .put("turnType", "TOOL_RESULT_DELIVERY")
                        .put("variantHash", attackVariant.variantHash())
                        .put(
                                "sourceModelResponseEventId",
                                sourceModelResponseEventId.toString()
                        )
                        .put(
                                "sourceModelResponseSequence",
                                sourceModelResponseSequence
                        )
        ),
        actorId
);

return new ToolInvocation(
        validatedProposal,
        proposalEvent.eventId(),
        proposalEvent.payloadDigest()
);
```

- [ ] **Step 5: Propagate the invocation through the Tool loop**

In `AgentToolLoopService.execute(...)`, create the initial invocation from the existing `RuntimeTurn`:

```java
ToolInvocation currentInvocation = new ToolInvocation(
        initialTurn.aiResponse().proposal(),
        initialTurn.proposalEvent().eventId(),
        initialTurn.proposalEvent().payloadDigest()
);
```

Dispatch with:

```java
ToolDispatcher.DispatchResult dispatch =
        toolDispatcher.dispatch(
                context,
                currentInvocation,
                actorId
        );
```

Keep existing evaluator compatibility by continuing to store:

```java
steps.add(new ToolStep(
        currentInvocation.proposal(),
        dispatch,
        delivery
));
```

On follow-up:

```java
currentInvocation =
        runtimeService.recordFollowUpToolProposal(
                context,
                attackVariant,
                toolProposalAction.proposal(),
                delivery.deliveryEventId(),
                delivery.deliveryEventSequence(),
                actorId
        );
```

- [ ] **Step 6: Change Dispatcher and Gateway signatures**

`ToolDispatcher.dispatch(...)`:

```java
public DispatchResult dispatch(
        SandboxExecutionContext context,
        ToolInvocation invocation,
        String actorId
) {
    ToolProposal validated =
            proposalValidator.validate(invocation.proposal());

    ToolInvocation validatedInvocation = new ToolInvocation(
            validated,
            invocation.toolCallId(),
            invocation.requestDigest()
    );

    PolicyGateway.GatewayResult gatewayResult =
            policyGateway.invoke(
                    context,
                    validatedInvocation,
                    actorId
            );

    return new DispatchResult(
            gatewayResult.policyDecision(),
            gatewayResult.policyEvent(),
            gatewayResult.requestEvent(),
            gatewayResult.responseEvent(),
            gatewayResult.execution()
    );
}
```

Change `PolicyGateway.invoke(...)` and `TemporaryPolicyGatewayBridge.invoke(...)` to accept `ToolInvocation`; inside the bridge use:

```java
ToolProposal proposal = invocation.proposal();
```

No idempotency behavior is added in Task 1.

- [ ] **Step 7: Run focused runtime/gateway regression**

Run:

```bash
./gradlew test \
  --tests "com.finsecseal.runtime.ToolInvocationPropagationIntegrationTest" \
  --tests "com.finsecseal.execution.Fa0203AgentToolLoopWiringIntegrationTest" \
  --tests "com.finsecseal.sandbox.tool.TemporaryPolicyGatewayBridgeBehaviorTest" \
  --tests "com.finsecseal.sandbox.tool.PolicyGatewayResultInvariantTest" \
  --stacktrace
```

Expected:

```text
BUILD SUCCESSFUL
```

- [ ] **Step 8: Commit Task 1**

```bash
git add \
  src/main/java/com/finsecseal/runtime/ToolInvocation.java \
  src/main/java/com/finsecseal/runtime/AgentRuntimeService.java \
  src/main/java/com/finsecseal/runtime/AgentToolLoopService.java \
  src/main/java/com/finsecseal/sandbox/tool/ToolDispatcher.java \
  src/main/java/com/finsecseal/sandbox/tool/PolicyGateway.java \
  src/main/java/com/finsecseal/sandbox/tool/TemporaryPolicyGatewayBridge.java \
  src/test/java/com/finsecseal/runtime/ToolInvocationPropagationIntegrationTest.java

git diff --cached --check
git commit -m "feat: propagate canonical tool call identity"
```

---

### Task 2: V13 and Sequential State-Changing Idempotency

**Files:**
- Create: `src/main/java/com/finsecseal/sandbox/tool/ToolEffect.java`
- Create: `src/main/java/com/finsecseal/sandbox/tool/StateChangingToolExecutionService.java`
- Create: `src/main/resources/db/migration/V13__sandbox_tool_idempotency.sql`
- Modify: `src/main/java/com/finsecseal/sandbox/tool/ToolAdapter.java`
- Modify: `src/main/java/com/finsecseal/sandbox/tool/TemporaryPolicyGatewayBridge.java`
- Modify: `src/main/java/com/finsecseal/sandbox/tool/ExternalHttpMockToolAdapter.java`
- Modify: `src/main/java/com/finsecseal/sandbox/tool/LoanDecisionUpdateMockToolAdapter.java`
- Test: `src/test/java/com/finsecseal/sandbox/tool/StateChangingToolIdempotencyIntegrationTest.java`

**Interfaces:**
- Consumes:

```java
ToolInvocation
ToolAdapter.ToolExecutionResult
ExecutionEventService
```

- Produces:

```java
public enum ToolEffect {
    READ_ONLY,
    STATE_CHANGING
}
```

`ToolAdapter` addition:

```java
default ToolEffect effect() {
    return ToolEffect.READ_ONLY;
}
```

`StateChangingToolExecutionService` entry point:

```java
public Execution execute(
        SandboxExecutionContext context,
        ToolInvocation invocation,
        ToolAdapter adapter,
        String actorId
)
```

Return type:

```java
public record Execution(
        ExecutionEventDto.Event requestEvent,
        ExecutionEventDto.Event responseEvent,
        ExecutionEventDto.Event stateEvent,
        ToolAdapter.ToolExecutionResult result,
        boolean replayed
) {
}
```

- [ ] **Step 1: Write the failing sequential duplicate integration test**

Create a Postgres/Testcontainers integration test that:

1. creates one run/caseRun and starts its event stream,
2. persists one `TOOL_PROPOSED` for `LOAN_DECISION_UPDATE`,
3. constructs one `ToolInvocation`,
4. calls the state-changing execution path twice with the same identity,
5. asserts loan version is exactly `1`,
6. asserts one receipt row,
7. asserts one `TOOL_REQUEST`,
8. asserts one `TOOL_RESPONSE`,
9. asserts one `SANDBOX_STATE_CHANGED`,
10. asserts the second returned execution has `replayed=true`,
11. asserts both results have equal response event IDs.

Core assertions:

```java
assertThat(first.replayed()).isFalse();
assertThat(second.replayed()).isTrue();
assertThat(second.responseEvent().eventId())
        .isEqualTo(first.responseEvent().eventId());

assertThat(jdbcTemplate.queryForObject("""
        select row_version
          from sandbox_loan_decisions
         where namespace_id = ?
           and case_key = 'CASE-1001'
        """, Long.class, runId))
        .isEqualTo(1L);
```

- [ ] **Step 2: Run the sequential duplicate test and verify RED**

Run:

```bash
./gradlew test \
  --tests "com.finsecseal.sandbox.tool.StateChangingToolIdempotencyIntegrationTest" \
  --stacktrace
```

Expected RED reason:

```text
sandbox_tool_idempotency_records does not exist
```

or reflection-based missing service/effect contract before V13 exists. Do not accept an unrelated adapter or fixture failure.

- [ ] **Step 3: Add `ToolEffect` and adapter declarations**

Create `ToolEffect.java`:

```java
package com.finsecseal.sandbox.tool;

public enum ToolEffect {
    READ_ONLY,
    STATE_CHANGING
}
```

Add to `ToolAdapter`:

```java
default ToolEffect effect() {
    return ToolEffect.READ_ONLY;
}
```

Override in `ExternalHttpMockToolAdapter` and `LoanDecisionUpdateMockToolAdapter`:

```java
@Override
public ToolEffect effect() {
    return ToolEffect.STATE_CHANGING;
}
```

- [ ] **Step 4: Add Flyway V13**

Create `V13__sandbox_tool_idempotency.sql`:

```sql
CREATE TABLE sandbox_tool_idempotency_records (
    id uuid PRIMARY KEY,
    test_case_run_id uuid NOT NULL
        REFERENCES test_case_runs(id) ON DELETE RESTRICT,
    tool_call_id uuid NOT NULL
        REFERENCES execution_events(id) ON DELETE RESTRICT,
    tool_name varchar(100) NOT NULL,
    request_digest sha256_digest NOT NULL,
    state varchar(20) NOT NULL
        CHECK (state IN ('PROCESSING', 'COMPLETED')),
    response_json jsonb,
    state_changed boolean,
    request_event_id uuid
        REFERENCES execution_events(id) ON DELETE RESTRICT,
    response_event_id uuid
        REFERENCES execution_events(id) ON DELETE RESTRICT,
    state_event_id uuid
        REFERENCES execution_events(id) ON DELETE RESTRICT,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT uq_sandbox_tool_idempotency_scope
        UNIQUE (test_case_run_id, tool_call_id),

    CONSTRAINT ck_sandbox_tool_idempotency_completion
        CHECK (
            (
                state = 'PROCESSING'
                AND response_json IS NULL
                AND state_changed IS NULL
                AND request_event_id IS NULL
                AND response_event_id IS NULL
                AND state_event_id IS NULL
                AND completed_at IS NULL
            )
            OR
            (
                state = 'COMPLETED'
                AND response_json IS NOT NULL
                AND state_changed IS NOT NULL
                AND request_event_id IS NOT NULL
                AND response_event_id IS NOT NULL
                AND completed_at IS NOT NULL
                AND (
                    (state_changed = false AND state_event_id IS NULL)
                    OR
                    (state_changed = true AND state_event_id IS NOT NULL)
                )
            )
        )
);

CREATE INDEX ix_sandbox_tool_idempotency_case_run
    ON sandbox_tool_idempotency_records(test_case_run_id);

CREATE OR REPLACE FUNCTION finsec_guard_sandbox_tool_idempotency()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'sandbox tool idempotency records cannot be deleted'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.test_case_run_id IS DISTINCT FROM NEW.test_case_run_id
       OR OLD.tool_call_id IS DISTINCT FROM NEW.tool_call_id
       OR OLD.tool_name IS DISTINCT FROM NEW.tool_name
       OR OLD.request_digest IS DISTINCT FROM NEW.request_digest
       OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION
            'sandbox tool idempotency identity is immutable'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.state <> 'PROCESSING'
       OR NEW.state <> 'COMPLETED' THEN
        RAISE EXCEPTION
            'only PROCESSING to COMPLETED transition is allowed'
            USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER sandbox_tool_idempotency_guard
BEFORE UPDATE OR DELETE ON sandbox_tool_idempotency_records
FOR EACH ROW
EXECUTE FUNCTION finsec_guard_sandbox_tool_idempotency();
```

- [ ] **Step 5: Implement invocation provenance validation**

Inside `StateChangingToolExecutionService`, before reservation query the `TOOL_PROPOSED` event by `toolCallId` and require:

```text
event_type = TOOL_PROPOSED
run_id = context.runId
test_case_run_id = context.caseRunId
trace_id = context.traceId
tool_name = invocation.proposal.toolName
payload_digest = invocation.requestDigest
```

Also require the persisted `input_redacted` to equal the current validated proposal arguments after the existing redaction/canonical event path. If tool name or input differs for the same ID, throw `IDEMPOTENCY_CONFLICT`.

- [ ] **Step 6: Implement transactional reservation and execution**

Annotate:

```java
@Transactional
public Execution execute(...)
```

For a new key:

```sql
INSERT INTO sandbox_tool_idempotency_records (
    id,
    test_case_run_id,
    tool_call_id,
    tool_name,
    request_digest,
    state
)
VALUES (?, ?, ?, ?, ?, 'PROCESSING')
ON CONFLICT (test_case_run_id, tool_call_id) DO NOTHING
```

If inserted, append `TOOL_REQUEST`, call `adapter.execute(...)`, append `TOOL_RESPONSE`, append `SANDBOX_STATE_CHANGED` when `result.stateChanged()`, then complete the receipt:

```sql
UPDATE sandbox_tool_idempotency_records
   SET state = 'COMPLETED',
       response_json = ?::jsonb,
       state_changed = ?,
       request_event_id = ?,
       response_event_id = ?,
       state_event_id = ?,
       completed_at = now()
 WHERE test_case_run_id = ?
   AND tool_call_id = ?
   AND state = 'PROCESSING'
```

Require update count exactly `1`.

- [ ] **Step 7: Implement completed duplicate reconstruction**

If reservation insert count is `0`, select the row.

If `tool_name` or `request_digest` differs:

```java
throw new BusinessException(
        ErrorCode.IDEMPOTENCY_CONFLICT,
        "Tool invocation identity was reused with different request content"
);
```

If state is `PROCESSING`:

```java
throw new BusinessException(
        ErrorCode.IDEMPOTENCY_IN_PROGRESS,
        "Tool invocation is already processing"
);
```

If state is `COMPLETED`, load referenced events using `ExecutionEventService.findById(...)`, validate their run/case/tool correlation, reconstruct:

```java
ToolAdapter.ToolExecutionResult result =
        new ToolAdapter.ToolExecutionResult(
                storedResponseJson,
                storedStateChanged
        );

return new Execution(
        requestEvent,
        responseEvent,
        stateEvent,
        result,
        true
);
```

- [ ] **Step 8: Integrate state-changing path into Gateway**

In `TemporaryPolicyGatewayBridge`:

1. evaluate policy exactly as today,
2. append `POLICY_EVALUATED`,
3. on deny return with no Tool execution,
4. resolve adapter,
5. if `adapter.effect() == READ_ONLY`, use the existing direct execution path,
6. if `STATE_CHANGING`, call `StateChangingToolExecutionService.execute(...)`,
7. map its request/response/result to `GatewayResult`.

Remove duplicate state-changing `TOOL_REQUEST`, `TOOL_RESPONSE`, and `SANDBOX_STATE_CHANGED` appends from the bridge path.

- [ ] **Step 9: Run focused sequential idempotency tests**

Run:

```bash
./gradlew test \
  --tests "com.finsecseal.sandbox.tool.StateChangingToolIdempotencyIntegrationTest" \
  --tests "com.finsecseal.sandbox.tool.LoanDecisionUpdateMockToolAdapterIntegrationTest" \
  --tests "com.finsecseal.sandbox.tool.ExternalHttpMockToolAdapterPersistenceIntegrationTest" \
  --tests "com.finsecseal.sandbox.tool.TemporaryPolicyGatewayBridgeBehaviorTest" \
  --stacktrace
```

Expected:

```text
BUILD SUCCESSFUL
```

- [ ] **Step 10: Commit Task 2**

```bash
git add \
  src/main/java/com/finsecseal/sandbox/tool/ToolEffect.java \
  src/main/java/com/finsecseal/sandbox/tool/StateChangingToolExecutionService.java \
  src/main/resources/db/migration/V13__sandbox_tool_idempotency.sql \
  src/main/java/com/finsecseal/sandbox/tool/ToolAdapter.java \
  src/main/java/com/finsecseal/sandbox/tool/TemporaryPolicyGatewayBridge.java \
  src/main/java/com/finsecseal/sandbox/tool/ExternalHttpMockToolAdapter.java \
  src/main/java/com/finsecseal/sandbox/tool/LoanDecisionUpdateMockToolAdapter.java \
  src/test/java/com/finsecseal/sandbox/tool/StateChangingToolIdempotencyIntegrationTest.java

git diff --cached --check
git commit -m "feat: add state-changing tool idempotency"
```

---

### Task 3: Same Identity With Different Request Must Fail Closed

**Files:**
- Modify: `src/main/java/com/finsecseal/sandbox/tool/StateChangingToolExecutionService.java`
- Test: `src/test/java/com/finsecseal/sandbox/tool/StateChangingToolIdempotencyConflictIntegrationTest.java`

**Interfaces:**
- Consumes:
  - completed idempotency receipt from Task 2
  - `ToolInvocation`
- Produces:
  - `BusinessException(ErrorCode.IDEMPOTENCY_CONFLICT)` before adapter invocation.

- [ ] **Step 1: Write the failing digest/input conflict test**

The test must execute one successful `LOAN_DECISION_UPDATE` with:

```json
{"caseId":"CASE-1001","decision":"APPROVED"}
```

Then construct a second invocation using the same `toolCallId` but request content representing:

```json
{"caseId":"CASE-1001","decision":"REJECTED"}
```

Assert:

```java
assertThatThrownBy(() -> execute(secondInvocation))
        .isInstanceOfSatisfying(
                BusinessException.class,
                exception -> assertThat(exception.errorCode())
                        .isEqualTo(ErrorCode.IDEMPOTENCY_CONFLICT)
        );
```

Then assert:

```text
decision = APPROVED
row_version = 1
one TOOL_REQUEST
one TOOL_RESPONSE
one SANDBOX_STATE_CHANGED
```

- [ ] **Step 2: Run the test and verify RED**

Run:

```bash
./gradlew test \
  --tests "com.finsecseal.sandbox.tool.StateChangingToolIdempotencyConflictIntegrationTest" \
  --stacktrace
```

Expected: test fails because the current duplicate path accepts or reconstructs the same identity without detecting changed request content.

- [ ] **Step 3: Add strict persisted proposal comparison**

Before returning a completed duplicate, load the canonical `TOOL_PROPOSED` event referenced by `toolCallId`.

Require:

```java
Objects.equals(
        persistedProposal.toolName(),
        invocation.proposal().toolName()
)
```

and deep JSON equality between persisted proposal input and current validated arguments.

On mismatch:

```java
throw new BusinessException(
        ErrorCode.IDEMPOTENCY_CONFLICT,
        "toolCallId cannot be reused for different Tool request content"
);
```

Do not append `TOOL_REQUEST` before this validation.

- [ ] **Step 4: Run conflict + sequential regression**

Run:

```bash
./gradlew test \
  --tests "com.finsecseal.sandbox.tool.StateChangingToolIdempotencyConflictIntegrationTest" \
  --tests "com.finsecseal.sandbox.tool.StateChangingToolIdempotencyIntegrationTest" \
  --stacktrace
```

Expected:

```text
BUILD SUCCESSFUL
```

- [ ] **Step 5: Commit Task 3**

```bash
git add \
  src/main/java/com/finsecseal/sandbox/tool/StateChangingToolExecutionService.java \
  src/test/java/com/finsecseal/sandbox/tool/StateChangingToolIdempotencyConflictIntegrationTest.java

git diff --cached --check
git commit -m "test: reject conflicting tool call replay"
```

---

### Task 4: Concurrent Duplicate Must Commit One Mutation

**Files:**
- Modify if required: `src/main/java/com/finsecseal/sandbox/tool/StateChangingToolExecutionService.java`
- Test: `src/test/java/com/finsecseal/sandbox/tool/StateChangingToolIdempotencyConcurrencyIntegrationTest.java`

**Interfaces:**
- Consumes:
  - Task 2 DB unique constraint
  - Task 2 transactional state-changing executor
- Produces:
  - at most one committed adapter mutation for concurrent callers.

- [ ] **Step 1: Write concurrent same-identity test**

Use `ExecutorService` with two workers and `CountDownLatch` so both call the state-changing executor with the same `ToolInvocation`.

Pseudo-test body:

```java
ExecutorService pool = Executors.newFixedThreadPool(2);
CountDownLatch start = new CountDownLatch(1);

Callable<Outcome> call = () -> {
    start.await();
    try {
        return Outcome.success(execute(invocation));
    } catch (BusinessException exception) {
        return Outcome.failure(exception.errorCode());
    }
};

Future<Outcome> first = pool.submit(call);
Future<Outcome> second = pool.submit(call);

start.countDown();

Outcome one = first.get(10, TimeUnit.SECONDS);
Outcome two = second.get(10, TimeUnit.SECONDS);
```

Accept either of these valid duplicate outcomes:

```text
A. one new execution + one replayed completed result
B. one new execution + one IDEMPOTENCY_IN_PROGRESS
```

But always require:

```text
loan row_version = 1
one idempotency receipt
receipt state = COMPLETED
one TOOL_REQUEST
one TOOL_RESPONSE
one SANDBOX_STATE_CHANGED
```

- [ ] **Step 2: Run the concurrency test and verify RED or characterize current behavior**

Run:

```bash
./gradlew test \
  --tests "com.finsecseal.sandbox.tool.StateChangingToolIdempotencyConcurrencyIntegrationTest" \
  --stacktrace
```

If it already passes because PostgreSQL unique-index waiting serializes the insert until the first transaction commits, record that behavior and do not add unnecessary locking.

If it fails with a second mutation or duplicate Tool execution evidence, proceed to Step 3.

- [ ] **Step 3: Fix only the demonstrated concurrency gap**

Preferred implementation order:

1. rely on the V13 unique constraint,
2. use `INSERT ... ON CONFLICT DO NOTHING`,
3. after conflict, re-read the receipt in the same method,
4. if still `PROCESSING`, throw `IDEMPOTENCY_IN_PROGRESS`,
5. if `COMPLETED`, reconstruct result,
6. do not introduce Redis/distributed locks/advisory locks unless the test demonstrates PostgreSQL alone is insufficient.

- [ ] **Step 4: Run concurrency + sequential + conflict tests**

Run:

```bash
./gradlew test \
  --tests "com.finsecseal.sandbox.tool.StateChangingToolIdempotencyConcurrencyIntegrationTest" \
  --tests "com.finsecseal.sandbox.tool.StateChangingToolIdempotencyIntegrationTest" \
  --tests "com.finsecseal.sandbox.tool.StateChangingToolIdempotencyConflictIntegrationTest" \
  --stacktrace
```

Expected:

```text
BUILD SUCCESSFUL
```

- [ ] **Step 5: Commit Task 4**

If production code changed:

```bash
git add \
  src/main/java/com/finsecseal/sandbox/tool/StateChangingToolExecutionService.java \
  src/test/java/com/finsecseal/sandbox/tool/StateChangingToolIdempotencyConcurrencyIntegrationTest.java
```

If production code did not need a change:

```bash
git add \
  src/test/java/com/finsecseal/sandbox/tool/StateChangingToolIdempotencyConcurrencyIntegrationTest.java
```

Then:

```bash
git diff --cached --check
git commit -m "test: verify concurrent tool call idempotency"
```

---

### Task 5: Event Correlation and Full FA Regression

**Files:**
- Modify if required:
  - `src/main/java/com/finsecseal/sandbox/tool/StateChangingToolExecutionService.java`
  - `src/main/java/com/finsecseal/sandbox/tool/TemporaryPolicyGatewayBridge.java`
- Modify tests if exact event metadata assertions are absent:
  - `src/test/java/com/finsecseal/sandbox/tool/StateChangingToolIdempotencyIntegrationTest.java`
- Regression:
  - FA-03
  - FA-04
  - FA-05
  - Policy Gateway
  - ExternalHttp Mock
  - Full Gradle suite

**Interfaces:**
- Required event metadata:

```text
TOOL_REQUEST.metadata.toolCallId
TOOL_RESPONSE.metadata.toolCallId
SANDBOX_STATE_CHANGED.metadata.toolCallId
SANDBOX_STATE_CHANGED.metadata.sourceToolResponseEventId
```

- [ ] **Step 1: Add failing event-correlation assertions**

For the state-changing idempotency integration test, query the original Tool execution events and require:

```java
assertThat(requestEvent.metadata()
        .path("toolCallId").asString())
        .isEqualTo(invocation.toolCallId().toString());

assertThat(responseEvent.metadata()
        .path("toolCallId").asString())
        .isEqualTo(invocation.toolCallId().toString());

assertThat(stateEvent.metadata()
        .path("toolCallId").asString())
        .isEqualTo(invocation.toolCallId().toString());

assertThat(stateEvent.metadata()
        .path("sourceToolResponseEventId").asString())
        .isEqualTo(responseEvent.eventId().toString());
```

For a replayed completed duplicate, require the same original event IDs are returned and no additional Tool execution evidence is appended.

- [ ] **Step 2: Run correlation test and verify RED if metadata is missing**

Run:

```bash
./gradlew test \
  --tests "com.finsecseal.sandbox.tool.StateChangingToolIdempotencyIntegrationTest" \
  --stacktrace
```

- [ ] **Step 3: Add `toolCallId` to state-changing execution event metadata**

When appending `TOOL_REQUEST`:

```java
objectMapper.createObjectNode()
        .put("toolCallId", invocation.toolCallId().toString())
```

When appending `TOOL_RESPONSE`:

```java
ObjectNode responseMetadata = objectMapper.createObjectNode();
responseMetadata.put(
        "toolCallId",
        invocation.toolCallId().toString()
);
responseMetadata.put("deliveredToAgent", false);
responseMetadata.put("deliveryState", "PENDING");
responseMetadata.put(
        "stateChanged",
        execution.stateChanged()
);
```

When appending `SANDBOX_STATE_CHANGED`:

```java
ObjectNode stateMetadata = objectMapper.createObjectNode();
stateMetadata.put(
        "toolCallId",
        invocation.toolCallId().toString()
);
stateMetadata.put("stateChanged", true);
stateMetadata.put(
        "sourceToolResponseEventId",
        responseEvent.eventId().toString()
);
```

Do not change the existing `sourceToolResponseEventId` causal contract.

- [ ] **Step 4: Run focused cross-feature regression**

Run:

```bash
./gradlew test \
  --tests "com.finsecseal.execution.Fa03GoldenFlowIntegrationTest" \
  --tests "com.finsecseal.execution.Fa04GoldenFlowIntegrationTest" \
  --tests "com.finsecseal.execution.Fa05GoldenFlowIntegrationTest" \
  --tests "com.finsecseal.execution.ExfiltrationToolLoopOracleEvaluatorIntegrationTest" \
  --tests "com.finsecseal.execution.HighImpactToolLoopOracleEvaluatorIntegrationTest" \
  --tests "com.finsecseal.sandbox.tool.ExternalHttpMockToolAdapterContractTest" \
  --tests "com.finsecseal.sandbox.tool.ExternalHttpMockToolAdapterPersistenceIntegrationTest" \
  --tests "com.finsecseal.sandbox.tool.TemporaryPolicyGatewayBridgeBehaviorTest" \
  --tests "com.finsecseal.sandbox.tool.PolicyGatewayResultInvariantTest" \
  --tests "com.finsecseal.sandbox.tool.StateChangingToolIdempotencyIntegrationTest" \
  --tests "com.finsecseal.sandbox.tool.StateChangingToolIdempotencyConflictIntegrationTest" \
  --tests "com.finsecseal.sandbox.tool.StateChangingToolIdempotencyConcurrencyIntegrationTest" \
  --stacktrace
```

Expected:

```text
BUILD SUCCESSFUL
```

- [ ] **Step 5: Verify no old migration changed**

Run:

```bash
git diff --name-only -- \
  src/main/resources/db/migration/V1__release_platform.sql \
  src/main/resources/db/migration/V2__execution_evidence.sql \
  src/main/resources/db/migration/V3__sandbox_storage.sql \
  src/main/resources/db/migration/V4__append_only_guards.sql \
  src/main/resources/db/migration/V5__api_idempotency.sql \
  src/main/resources/db/migration/V6__event_delivery_and_audit_scope.sql \
  src/main/resources/db/migration/V7__attestation_projection_integrity.sql \
  src/main/resources/db/migration/V8__idempotency_operator_recovery.sql \
  src/main/resources/db/migration/V9__*.sql \
  src/main/resources/db/migration/V10__application_instance_lease_owner_guard.sql \
  src/main/resources/db/migration/V11__oracle_finding_audit_scope.sql \
  src/main/resources/db/migration/V12__sandbox_exfil_case_run_provenance.sql
```

Expected:

```text
(no output)
```

- [ ] **Step 6: Run the full suite**

Run:

```bash
./gradlew clean test \
  --warning-mode all \
  --rerun-tasks \
  --stacktrace
```

Expected:

```text
BUILD SUCCESSFUL
```

Shutdown-only Hikari/Testcontainers lifecycle warnings may remain if they match the already-observed baseline; new test failures or new stack traces are not acceptable.

- [ ] **Step 7: Commit final correlation/regression adjustments**

```bash
git add \
  src/main/java/com/finsecseal/sandbox/tool/StateChangingToolExecutionService.java \
  src/main/java/com/finsecseal/sandbox/tool/TemporaryPolicyGatewayBridge.java \
  src/test/java/com/finsecseal/sandbox/tool/StateChangingToolIdempotencyIntegrationTest.java

git diff --cached --check
git commit -m "test: harden tool call idempotency evidence"
```

If Step 3 required no production change, stage only the tests actually changed.

---

# Final Verification Checklist

Before opening a PR or declaring Task 8 complete:

- [ ] `ToolProposal` is still exactly `toolName + arguments`.
- [ ] `SandboxExecutionContext` has not gained `toolCallId`.
- [ ] `TOOL_PROPOSED.eventId` is the only canonical `toolCallId`.
- [ ] Initial and follow-up proposals both produce stable Tool invocation identity.
- [ ] Read-only adapters do not create idempotency receipts.
- [ ] `LOAN_DECISION_UPDATE` declares `STATE_CHANGING`.
- [ ] `EXTERNAL_HTTP` declares `STATE_CHANGING`.
- [ ] V13 has unique `(test_case_run_id, tool_call_id)`.
- [ ] V13 identity columns are immutable.
- [ ] V13 allows only `PROCESSING -> COMPLETED`.
- [ ] Same Tool call replay does not increment loan `row_version` twice.
- [ ] Same Tool call replay does not insert duplicate mock exfil rows.
- [ ] Same `toolCallId` with different request content throws `IDEMPOTENCY_CONFLICT`.
- [ ] Concurrent duplicate commits at most one mutation.
- [ ] Completed duplicate returns original response evidence.
- [ ] Tool execution events include `toolCallId`.
- [ ] `sourceToolResponseEventId` remains intact.
- [ ] FA-03 golden flow passes.
- [ ] FA-04 golden flow passes.
- [ ] FA-05 golden flow and completed replay pass.
- [ ] Full `./gradlew clean test --warning-mode all --rerun-tasks --stacktrace` passes.
- [ ] V1-V12 are untouched.

# Commit Sequence

Recommended commit history:

```text
feat: add FA-05 high-impact action abuse flow
docs: define tool call idempotency design
docs: add tool call idempotency implementation plan
feat: propagate canonical tool call identity
feat: add state-changing tool idempotency
test: reject conflicting tool call replay
test: verify concurrent tool call idempotency
test: harden tool call idempotency evidence
```

The exact first two commits may already exist. Do not rewrite them merely to match this list.
