# Development B Agent Context Implementation Plan

**Goal:** Establish the trusted Spring → FastAPI execution-context contract required before real OpenAI integration.

## Task 1 — FastAPI contract RED/GREEN

- Add `agentContext` contract tests first.
- Confirm current `extra="forbid"` model rejects the new field (RED).
- Add strict nested Pydantic models.
- Enforce top-level/runtime identity and allowed-document consistency.
- Update existing step tests to include the new required context.
- Run all AI tests (GREEN).

## Task 2 — BE resolver contract

- Keep legacy one-argument functional resolver for existing deterministic test fixtures.
- Add scoped `resolve(testRunId, caseKey, currentApplicantId)`.
- Resolve persisted release model/business/workflow/normal Tool definitions.
- Read the system prompt from encrypted `SYSTEM_PROMPT/system-prompt` artifact, not redacted manifest text.
- Validate manifest/artifact/plaintext prompt digests.
- Reuse `PromptAccessAuditService` for runtime decrypt audit.
- Resolve sandbox case and enforce applicant identity.
- Resolve only same-run/same-case explicitly allowed documents.
- Validate decrypted document digest.
- Fail closed with `EVIDENCE_INCOMPLETE`.

## Task 3 — BE HTTP serialization

- Make `HttpAgentAiClient` call the scoped resolver.
- Add `agentContext` with model, plaintext runtime prompt, business purpose, workflow, tools, runtime, and documents.
- Preserve orchestration metadata, attack variant, previous Tool result, retry semantics, and body-size limits.

## Task 4 — Integration/regression tests

- Add focused resolver integration tests.
- Add focused HTTP serialization tests.
- Update `JdbcAgentRunContextHttpIntegrationTest` to seed production-shaped redacted manifest + encrypted prompt artifact + sandbox case.
- Verify `serverToolCatalog` is not serialized into model-visible Tool schemas.
- Verify system prompt decryption emits existing prompt-access audit.
- Run the full role-B AI HTTP/FA regression suite locally in the real BE checkout.

## Verification Commands

### FINSEC-SEAL-AI

```bash
pytest -q
```

### FINSEC-SEAL-BE focused

```bash
./gradlew test \
  --tests "com.finsecseal.runtime.ai.JdbcAgentRunContextResolverIntegrationTest" \
  --tests "com.finsecseal.runtime.ai.HttpAgentAiContextSerializationTest" \
  --tests "com.finsecseal.runtime.ai.JdbcAgentRunContextHttpIntegrationTest" \
  --stacktrace
```

### FINSEC-SEAL-BE role-B regressions

```bash
./gradlew test \
  --tests "com.finsecseal.runtime.ai.*" \
  --tests "com.finsecseal.runtime.AgentToolLoopServiceTest" \
  --tests "com.finsecseal.execution.Fa02GoldenFlowIntegrationTest" \
  --tests "com.finsecseal.execution.Fa03GoldenFlowIntegrationTest" \
  --tests "com.finsecseal.execution.Fa04GoldenFlowIntegrationTest" \
  --tests "com.finsecseal.execution.Fa05GoldenFlowIntegrationTest" \
  --stacktrace
```

### Full BE regression

```bash
./gradlew test --stacktrace
```
