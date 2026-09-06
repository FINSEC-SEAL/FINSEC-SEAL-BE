# Development B — Agent Execution Context Contract Design

Date: 2026-09-06
Target repositories:
- `FINSEC-SEAL/FINSEC-SEAL-BE` (`dev`)
- `FINSEC-SEAL/FINSEC-SEAL-AI` (`main`)

Suggested branches:
- BE: `feat/development-b-agent-context`
- AI: `feat/development-b-agent-context-contract`

## 1. Goal

Expand the stateless Spring → FastAPI Agent step contract so the AI worker receives all trusted execution inputs required for a real provider adapter without giving the AI service ownership of release state, sandbox state, or PostgreSQL.

Spring resolves trusted state and sends a self-contained `agentContext` on every Agent step. FastAPI strictly validates that context but remains stateless.

## 2. Non-goals

This slice does **not** call OpenAI yet.

It also does not implement FA-01, attack mutation, generic TestRun routing, cancellation, or token/cost accounting. Those follow after this contract is stable.

## 3. Existing State and Important Storage Invariant

Before this slice, `HttpAgentAiClient` sends only orchestration metadata plus the attack variant and previous Tool result. `AgentRunContextResolver` resolves only `releaseId`.

The release contains model/business/tool/workflow configuration. However, the persisted `agent_releases.manifest_json` intentionally **does not contain the plaintext system prompt**. `ReleaseService` stores:

```text
manifest_json.systemPrompt.text = "[ENCRYPTED]"
manifest_json.systemPrompt.storedSha256 = <prompt digest>
```

The plaintext is encrypted separately in `release_artifacts` as:

```text
artifact_type = SYSTEM_PROMPT
name          = system-prompt
content_text_encrypted = <ciphertext>
sha256        = <plaintext digest>
```

Therefore runtime context resolution must never use `manifest_json.systemPrompt.text` as the actual prompt. It must resolve the encrypted artifact, validate its digest, decrypt it, and record the existing prompt-access audit event.

## 4. Architecture

```text
TestRun / Release / Release Artifact / Sandbox DB
                    ↓
        JdbcAgentRunContextResolver
                    ↓
       ResolvedAgentExecutionContext
                    ↓
          HttpAgentAiClient
                    ↓
       POST /v1/agent/steps
                    ↓
     FastAPI AgentStepRequest
                    ↓
       deterministic service now
       provider adapter next slice
```

Spring remains authoritative. FastAPI never queries FINSEC-SEAL PostgreSQL.

## 5. Trusted Context Contract

```java
record ResolvedAgentExecutionContext(
    UUID releaseId,
    ModelContext model,
    String systemPrompt,
    BusinessContext businessContext,
    JsonNode workflow,
    List<ToolContext> tools,
    RuntimeCaseContext runtime,
    List<DocumentContext> documents
) {}
```

### 5.1 Model

```java
record ModelContext(String provider, String name, JsonNode parameters) {}
```

Source: persisted release manifest `model`.

### 5.2 System prompt

Source: encrypted `SYSTEM_PROMPT/system-prompt` release artifact, not the redacted manifest field.

Required checks:

1. persisted manifest prompt text is `[ENCRYPTED]`;
2. `storedSha256` exists;
3. exactly one prompt artifact exists;
4. artifact digest matches manifest `storedSha256`;
5. decrypted plaintext digest matches the artifact digest;
6. plaintext is non-empty;
7. access emits `SYSTEM_PROMPT_DECRYPTED_INTERNAL` through the existing `PromptAccessAuditService`.

### 5.3 Business purpose

```java
record BusinessContext(String code, String description) {}
```

Source: `manifest_json.businessPurpose`.

### 5.4 Model-visible tools

```java
record ToolContext(String name, String description, JsonNode inputSchema) {}
```

Only normal executable tools in `manifest_json.tools` are copied into `agentContext.tools`.

`serverToolCatalog` is **not automatically copied into model-visible tools**. High-risk attack-only behavior remains server-controlled and can be introduced by a later explicit attack-tool exposure mechanism if required by FA-05 provider execution.

### 5.5 Runtime case

```java
record RuntimeCaseContext(
    String caseKey,
    String currentApplicantId,
    String status,
    JsonNode context,
    List<String> allowedDocumentIds
) {}
```

Source: `sandbox_loan_cases`, scoped by `(testRunId, caseKey)`.

`currentApplicantId` supplied by orchestration must equal the trusted sandbox applicant.

### 5.6 Documents

```java
record DocumentContext(
    String documentId,
    String documentType,
    String content,
    String contentDigest,
    String trustLevel,
    JsonNode classification
) {}
```

Only IDs in `allowed_document_ids_json` are resolved. Every document must be in the same TestRun namespace and same case. After decryption, the plaintext digest must equal `content_digest`.

`documents: []` remains valid so FA-01 can later add controlled malicious-document fixtures without another contract redesign.

## 6. HTTP Shape

```json
{
  "releaseId": "...",
  "testRunId": "...",
  "testCaseRunId": "...",
  "traceId": "...",
  "caseKey": "CASE-1001",
  "currentApplicantId": "CUST-1001",
  "agentContext": {
    "model": {
      "provider": "openai-compatible",
      "name": "configured-model-id",
      "parameters": {"temperature": 0, "maxTokens": 2048}
    },
    "systemPrompt": "decrypted runtime plaintext",
    "businessPurpose": {
      "code": "LOAN_DOCUMENT_COMPLETENESS_REVIEW",
      "description": "..."
    },
    "workflow": {},
    "tools": [
      {
        "name": "CUSTOMER_DATA_READ",
        "description": "...",
        "inputSchema": {}
      }
    ],
    "runtime": {
      "caseKey": "CASE-1001",
      "currentApplicantId": "CUST-1001",
      "status": "IN_REVIEW",
      "context": {},
      "allowedDocumentIds": []
    },
    "documents": []
  },
  "attackVariant": {},
  "previousToolResult": null
}
```

Top-level run/trace/case IDs remain orchestration metadata. Trusted model/prompt/tool/document state is never accepted from an external caller into Spring; it is assembled from persisted state.

## 7. FastAPI Boundary

FastAPI currently uses `ConfigDict(extra="forbid")`. Adding a new BE field without changing its Pydantic model would produce HTTP 422. Therefore this slice updates both repositories together.

New strict nested Pydantic models validate:

- model provider/name/parameters;
- non-empty bounded system prompt;
- business purpose;
- unique model-visible Tool names;
- runtime case/applicant identity;
- unique allowed document IDs;
- exact equality between `documents[].documentId` and `runtime.allowedDocumentIds`;
- document digest format;
- attack variant digest format;
- unknown nested fields remain forbidden.

The deterministic service does not consume these values yet; it only proves the transport/validation contract. The next OpenAI-provider slice will consume them.

## 8. Fail-closed Rules

Any of the following becomes `EVIDENCE_INCOMPLETE` on the BE side or 422 at the AI boundary:

- missing/duplicate TestRun release context;
- missing/invalid model/business/workflow/tools;
- raw plaintext system prompt stored in `manifest_json`;
- missing/duplicate/tampered prompt artifact;
- system prompt decrypt/digest mismatch;
- missing sandbox case;
- applicant mismatch;
- malformed or duplicate allowed document IDs;
- missing/cross-case/cross-namespace document;
- document decrypt/digest mismatch;
- malformed nested AI context;
- runtime identity mismatch in FastAPI;
- model-visible document list not matching the allowed ID list.

## 9. Backward Compatibility

`AgentRunContextResolver.resolve(UUID testRunId)` and `ResolvedRunContext(UUID releaseId)` remain as a legacy functional-interface path for existing deterministic Java test fixtures.

A default three-argument bridge builds a small valid compatibility `agentContext`. Production `JdbcAgentRunContextResolver` overrides the scoped three-argument resolver and never uses compatibility state.

Existing Agent state-machine semantics remain unchanged:

```text
previousToolResult == null     → next Agent action
previousToolResult != null     → next TOOL_PROPOSAL or FINAL_RESPONSE
```

## 10. Files

### FINSEC-SEAL-BE

Modify:
- `src/main/java/com/finsecseal/runtime/ai/AgentRunContextResolver.java`
- `src/main/java/com/finsecseal/runtime/ai/JdbcAgentRunContextResolver.java`
- `src/main/java/com/finsecseal/runtime/ai/HttpAgentAiClient.java`
- `src/test/java/com/finsecseal/runtime/ai/JdbcAgentRunContextHttpIntegrationTest.java`

Add:
- `src/test/java/com/finsecseal/runtime/ai/HttpAgentAiContextSerializationTest.java`
- `src/test/java/com/finsecseal/runtime/ai/JdbcAgentRunContextResolverIntegrationTest.java`

No Flyway migration is required.

### FINSEC-SEAL-AI

Modify:
- `app/domain/agent.py`
- `tests/test_agent_steps.py`

Add:
- `tests/test_agent_context_contract.py`

## 11. Acceptance Tests

### BE resolver

- trusted model/business/workflow/tool context resolves;
- actual encrypted system prompt artifact is decrypted;
- prompt access is audited;
- serverToolCatalog is excluded;
- sandbox identity mismatch is rejected before prompt decryption;
- empty documents are supported;
- allowed document decrypts;
- missing/tampered document is rejected;
- missing/tampered prompt artifact is rejected;
- malformed manifest context is rejected.

### BE HTTP

- initial step contains `agentContext`;
- Tool-result delivery contains the same trusted context;
- existing 512 KiB request limit still applies;
- persisted release and sandbox state become outbound HTTP context.

### AI boundary

- complete `agentContext` accepted;
- unknown nested fields rejected;
- runtime identity mismatch rejected;
- documents must exactly match allowed IDs;
- Tool names must be unique;
- existing deterministic step behavior remains unchanged.

## 12. Completion Boundary

This slice is considered implemented when:

```text
Spring trusted persisted state
→ scoped resolver
→ audited prompt/document decryption + integrity checks
→ agentContext serialization
→ strict FastAPI validation
→ deterministic Agent step still works
```

Actual OpenAI provider invocation is intentionally the **next** development slice.
