# B-C Policy Gateway Boundary Design

Date: 2026-09-04
Status: Proposed for implementation after review

## 1. Goal

Establish a single B-to-C Tool execution boundary before C's full policy implementation exists.

All Agent Tool proposals must flow through:

```text
AgentToolLoopService [B]
        ↓
ToolDispatcher [B]
        ↓
PolicyGateway [shared boundary]
        ↓
Gateway implementation [C-owned policy behavior]
        ↓ ALLOW only
Namespaced ToolAdapter [B]
```

This change must preserve the already-merged multi-step Agent runtime and must not move Safety Contract or ALLOW/DENY policy ownership from C to B.

## 2. Current State

The merged Backend already contains:

- `AgentToolLoopService`, which invokes `ToolDispatcher.dispatch(...)` for every initial and follow-up Tool proposal.
- `ToolDispatcher`, which currently:
  1. validates the proposal,
  2. chooses a `ToolExecutionPolicy`,
  3. evaluates policy,
  4. writes `POLICY_EVALUATED`,
  5. invokes a `ToolAdapter` directly on allow.
- `BaselineToolExecutionPolicy`, which supports only `BASELINE` and returns `BASELINE_ALLOW`.
- No C-owned Policy Gateway implementation on `dev`.

The approved Policy Gateway specification requires every Tool invocation to pass through the Gateway before any Mock Adapter invocation.

## 3. Ownership Boundaries

### Development B owns

- Agent Runtime
- `AgentToolLoopService`
- `ToolDispatcher`
- Tool proposal validation before the Gateway boundary
- Sandbox Tool Adapter registry
- Adapter invocation plumbing
- Sandbox namespace usage
- Tool execution lifecycle integration with the Agent loop

### Development C owns

- Safety Contract evaluation
- Preflight policy integrity checks
- ALLOW/DENY decisions
- Decision reason semantics
- Release/contract/fingerprint integrity validation
- Business object, field, cardinality, egress, workflow, human-boundary and Tool trust policy rules
- Gateway operational timeout/fail-closed behavior

### Shared boundary

B and C jointly depend on the stable `PolicyGateway` interface and result contract.

B must not encode C's policy rules in `ToolDispatcher`.

## 4. Chosen Approach

Introduce a B-side `PolicyGateway` port now, together with a temporary compatibility implementation backed by the existing `ToolExecutionPolicy` abstraction.

The compatibility implementation exists only to keep current `BASELINE` behavior working until C provides the real Gateway implementation.

The public execution path becomes:

```text
AgentToolLoopService
    ↓
ToolDispatcher
    ↓
PolicyGateway.invoke(...)
    ↓
TemporaryPolicyGatewayBridge
    ↓
legacy ToolExecutionPolicy
    ↓
ALLOW → ToolAdapter
DENY  → no ToolAdapter
```

After C integration:

```text
TemporaryPolicyGatewayBridge
    ↓ replace
C PolicyGateway implementation
```

`AgentToolLoopService` and its callers must not change again for this replacement.

## 5. PolicyGateway Contract

The initial shared interface is intentionally minimal.

```java
public interface PolicyGateway {

    GatewayResult invoke(
            SandboxExecutionContext context,
            ToolProposal proposal,
            String actorId
    );
}
```

The result must provide enough information for `ToolDispatcher` and `AgentToolLoopService` to preserve their current behavior without inspecting C internals.

Conceptually:

```text
GatewayResult
- allowed
- reasonCode
- policyEvent
- requestEvent
- responseEvent
- execution
```

Invariants:

1. `allowed=false`
   - `execution == null`
   - `requestEvent == null`
   - `responseEvent == null`
   - a `POLICY_EVALUATED` deny event exists.

2. `allowed=true`
   - the Gateway path may invoke exactly one registered Tool Adapter,
   - request/response evidence is returned,
   - the Adapter never runs before the Gateway decision.

3. Gateway exceptions are fail-closed and must not result in Adapter invocation.

## 6. ToolDispatcher Responsibility After the Change

`ToolDispatcher` remains the only entry point used by Runtime/Orchestrators.

It performs:

1. `ToolProposalValidator.validate(...)`.
2. Call `PolicyGateway.invoke(...)`.
3. Convert the Gateway result into the existing `DispatchResult` used by `AgentToolLoopService`.

It no longer:

- selects `ToolExecutionPolicy` directly,
- evaluates policy rules directly,
- decides ALLOW/DENY itself,
- invokes Tool Adapters outside the Gateway path.

No Runtime or Orchestrator may import or call concrete Tool Adapters.

## 7. Temporary Gateway Bridge

Until C supplies the real implementation, B provides a compatibility bridge.

Behavior:

### BASELINE

- Uses the current legacy `BaselineToolExecutionPolicy`.
- Keeps business-policy behavior equivalent to the current `BASELINE_ALLOW`.
- Still requires the Gateway path.
- Invokes only registered Mock Tool Adapters.
- Does not permit arbitrary network, real financial APIs, code execution, or cross-namespace access.

### SEAL_REPLAY / HELD_OUT / REGRESSION

The temporary bridge does not fabricate enforcement behavior.

If no C-owned policy implementation supports the mode, execution fails closed with `CONFIGURATION_ERROR` or the project's equivalent operational configuration failure.

This failure:

- does not invoke an Adapter,
- is not counted as successful policy blocking,
- must not be converted to `ATTACK_BLOCKED`.

## 8. Trusted Context and releaseId

`SandboxExecutionContext` remains:

- runId
- caseRunId
- traceId
- mode
- caseKey
- currentApplicantId

No `releaseId` is added to Tool arguments or accepted from Python.

The future C Gateway resolves trusted release context server-side from `runId`, consistent with the existing `runId → releaseId` pattern already used for the AI client.

This prevents caller-supplied release identity from becoming an authorization input.

## 9. Multi-Step Agent Behavior

No Agent state-machine change is required.

For every Tool proposal:

```text
TOOL_PROPOSAL #1
→ ToolDispatcher
→ PolicyGateway
→ Tool result
→ Python next step

TOOL_PROPOSAL #2
→ ToolDispatcher
→ PolicyGateway
→ Tool result
→ Python next step
```

Every follow-up Tool is independently re-evaluated by the Gateway.

A previous ALLOW does not authorize the next Tool invocation.

## 10. Evidence Semantics

### DENY

Required evidence:

```text
TOOL_PROPOSED
POLICY_EVALUATED(DENY, reasonCode)
```

Forbidden evidence after the deny:

```text
TOOL_REQUEST
TOOL_RESPONSE
state delta
```

### ALLOW

Expected sequence:

```text
TOOL_PROPOSED
POLICY_EVALUATED(ALLOW)
TOOL_REQUEST
TOOL_RESPONSE
```

The exact C-owned policy payload may evolve, but B must preserve event ordering and must not manufacture C decision details.

## 11. Bypass Prevention

The implementation must include tests enforcing:

1. `ToolDispatcher` depends on `PolicyGateway`.
2. Runtime/Orchestrator packages do not reference concrete Tool Adapter classes.
3. A DENY result causes zero Adapter invocations.
4. A DENY result creates no `TOOL_REQUEST` or `TOOL_RESPONSE`.
5. Each Tool proposal in a multi-step loop causes a separate Gateway invocation.
6. An unsupported enforcement mode with only the temporary bridge fails closed.
7. `BASELINE` still executes through the Gateway rather than bypassing it.

An architecture/contract test should inspect dependency shape so a later refactor cannot silently restore direct Adapter access.

## 12. Error Handling

### Proposal validation failure

- Fails before Gateway invocation.
- No Adapter invocation.
- Existing validation error semantics remain.

### Gateway configuration failure

- Fail closed.
- No Adapter invocation.
- Run treated as operational/configuration failure, not an attack block.

### Gateway DENY

- Normal policy decision, not an operational exception.
- No Adapter invocation.
- `AgentToolLoopService` terminates with its existing policy-denied path.

### Adapter failure after ALLOW

- Propagates as Tool execution failure according to existing Sandbox/runtime error handling.
- Must not be relabeled as policy denial.

## 13. Migration and Data Model

No Flyway migration is required for this B-side boundary work.

Constraints:

- V1-V11 remain untouched.
- No speculative C-owned policy tables are added.
- Any future persistence needed by C will be introduced separately through a new migration owned by the agreed DB boundary.

## 14. Tests and Verification

Implementation uses TDD.

Required RED/GREEN coverage:

1. `ToolDispatcher` requires `PolicyGateway`.
2. Gateway ALLOW invokes Adapter exactly once.
3. Gateway DENY invokes Adapter zero times.
4. DENY produces no Tool request/response evidence.
5. Multi-step Agent invokes Gateway once per Tool proposal.
6. Enforcement mode without C implementation fails closed.
7. Existing FA-02 baseline flow remains green.
8. Existing FA-03 baseline/quarantine flows remain green.
9. `AgentToolLoopServiceTest` remains green.
10. Full `./gradlew clean test`.

Before commit:

```text
git diff --check
git status --short src/main/resources/db/migration
```

The migration status must be empty.

## 15. Out of Scope

This change does not implement:

- C's 10-step policy algorithm,
- Safety Contract persistence or approval,
- release/contract/fingerprint verification,
- response classification enforcement,
- egress policy,
- human approval policy,
- FA-04,
- FA-05,
- FA-01.

Those follow after the B-C execution boundary is stable.

## 16. Acceptance Criteria

The boundary work is complete when:

- every current and follow-up Tool proposal goes through `PolicyGateway`,
- no Runtime/Orchestrator path can invoke a concrete Adapter directly,
- BASELINE behavior remains functionally compatible,
- non-baseline modes fail closed until C provides enforcement,
- DENY cannot produce Tool invocation evidence or state changes,
- no DB migration is modified,
- targeted regression tests and the full Backend suite pass.
