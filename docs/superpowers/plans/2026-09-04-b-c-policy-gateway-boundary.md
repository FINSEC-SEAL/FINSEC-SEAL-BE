# B-C Policy Gateway Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route every Spring Tool invocation through a stable `PolicyGateway` boundary so C can later replace the temporary baseline bridge without changing Agent Runtime or Tool loop callers.

**Architecture:** `AgentToolLoopService` continues to call only `ToolDispatcher`. `ToolDispatcher` validates proposals and delegates the policy/execution boundary to `PolicyGateway`. A temporary B-side bridge preserves current BASELINE behavior with the legacy `ToolExecutionPolicy` and registered Mock `ToolAdapter`s, while unsupported enforcement modes fail closed.

**Tech Stack:** Java 21, Spring Boot 4.1.1, JUnit 5, AssertJ, Mockito, PostgreSQL-backed ExecutionEvent infrastructure.

**Spec:** `docs/superpowers/specs/2026-09-04-b-c-policy-gateway-boundary-design.md`

## Global Constraints

- Spring Backend remains the canonical state owner.
- Python AI remains stateless and never executes FINSEC SEAL Tools.
- Every current and follow-up Tool proposal must pass through `ToolDispatcher -> PolicyGateway`.
- Development B must not implement C's Safety Contract or policy rules.
- BASELINE remains behaviorally compatible but still traverses the Gateway.
- SEAL_REPLAY / HELD_OUT / REGRESSION fail closed while only the temporary bridge exists.
- DENY must produce no Tool Adapter invocation, `TOOL_REQUEST`, `TOOL_RESPONSE`, or state delta.
- No Flyway migration is required; V1-V11 remain untouched.

---

### Task 1: Lock the architectural boundary

**Files:**
- Create: `src/test/java/com/finsecseal/sandbox/tool/PolicyGatewayBoundaryContractTest.java`
- Create: `src/main/java/com/finsecseal/sandbox/tool/PolicyGateway.java`
- Modify: `src/main/java/com/finsecseal/sandbox/tool/ToolDispatcher.java`

**Interfaces:**
- Produces `PolicyGateway.invoke(SandboxExecutionContext, ToolProposal, String)`.
- Produces `PolicyGateway.PolicyDecision(boolean allowed, String reasonCode)`.
- Produces `PolicyGateway.GatewayResult(...)`.
- `ToolDispatcher` must depend on `PolicyGateway`, not own adapter/policy registries.

- [ ] Add the reflection-based failing boundary tests.
- [ ] Run `PolicyGatewayBoundaryContractTest` and verify RED.
- [ ] Add the minimal `PolicyGateway` port.
- [ ] Switch `ToolDispatcher` constructor/fields to `PolicyGateway`.
- [ ] Keep `dispatch(...)` caller signature unchanged.
- [ ] Re-run contract test until GREEN.

### Task 2: Implement temporary BASELINE Gateway bridge

**Files:**
- Create: `src/main/java/com/finsecseal/sandbox/tool/TemporaryPolicyGatewayBridge.java`
- Create: `src/test/java/com/finsecseal/sandbox/tool/TemporaryPolicyGatewayBridgeTest.java`
- Existing: `ToolExecutionPolicy.java`, `BaselineToolExecutionPolicy.java`, `ToolAdapter.java`

**Interfaces:**
- Consumes legacy policies/adapters plus `ExecutionEventService` and `ObjectMapper`.
- Produces `PolicyGateway.GatewayResult`.

- [ ] RED: BASELINE ALLOW invokes registered adapter exactly once through Gateway.
- [ ] RED: unsupported enforcement mode fails closed before adapter invocation.
- [ ] RED: DENY creates policy evidence but no Tool request/response.
- [ ] Implement exactly-one-supporting-policy selection.
- [ ] Move policy event, request event, adapter execution, and response event behind Gateway.
- [ ] Verify bridge tests GREEN.

### Task 3: Make ToolDispatcher a thin single path

**Files:**
- Modify: `src/main/java/com/finsecseal/sandbox/tool/ToolDispatcher.java`
- Modify: `src/test/java/com/finsecseal/runtime/AgentToolLoopServiceTest.java`
- Modify: `src/test/java/com/finsecseal/execution/Fa0203AgentToolLoopWiringIntegrationTest.java`
- Modify: `src/test/java/com/finsecseal/execution/Fa0203MultiStepOracleIntegrationTest.java`

**Interfaces:**
- `ToolDispatcher.dispatch(context, proposal, actorId)` remains unchanged.
- Dispatcher validates then delegates to Gateway and returns `DispatchResult`.

- [ ] RED: validation occurs before Gateway invocation.
- [ ] Implement thin delegation.
- [ ] Update legacy decision test fixtures to Gateway decision.
- [ ] Run targeted runtime tests until GREEN.

### Task 4: Prove multi-step re-entry

**Files:**
- Modify: `src/test/java/com/finsecseal/runtime/AgentToolLoopServiceTest.java`
- Modify: `src/test/java/com/finsecseal/execution/Fa0203AgentToolLoopWiringIntegrationTest.java`

- [ ] RED: two Tool proposals cause two Gateway invocations.
- [ ] Verify FINAL_RESPONSE causes no third Gateway call.
- [ ] Verify policy denial stops before Tool Result delivery.

### Task 5: Preserve baseline and fail closed outside baseline

**Files:**
- Test existing FA-02/FA-03 integration suites.
- Create if needed: `src/test/java/com/finsecseal/sandbox/tool/PolicyGatewayModeIntegrationTest.java`

- [ ] Verify BASELINE still yields `BASELINE_ALLOW`.
- [ ] Verify SEAL_REPLAY / HELD_OUT / REGRESSION with no C implementation fail with configuration failure.
- [ ] Verify unsupported mode produces no Tool request/response evidence.

### Task 6: Final regression

- [ ] `git diff --check`
- [ ] `git status --short src/main/resources/db/migration` -> no output
- [ ] Policy Gateway targeted tests
- [ ] Agent Tool loop tests
- [ ] FA-02/FA-03 regressions
- [ ] `./gradlew clean test`
