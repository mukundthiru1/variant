# VARIANT Engine — Security Analysis Report

**Date:** 2026-03-07  
**Scope:** Full codebase security audit (231 files)  
**Focus Areas:** Input validation, event system, sandbox isolation, type safety, race conditions, resource exhaustion

---

## Executive Summary

The VARIANT engine implements a **defense-in-depth security architecture** with multiple layers of protection:

| Layer | Defense | Status |
|-------|---------|--------|
| WorldSpec Input | Validator with path traversal, prototype pollution, executable code detection | ✅ Strong |
| VM Isolation | Air-gapped v86 (no network_relay_url), memory clamping | ✅ Strong |
| Immutability | deepFreeze() prevents runtime mutation | ✅ Strong |
| Trust Boundaries | Community vs Curated trust levels | ✅ Strong |
| Module Isolation | Read-only subscriptions, no cross-module direct access | ✅ Strong |
| Resource Limits | EventBus (10k), TrafficLog (50k), Validator enforces limits | ✅ Strong |
| VFS Security | Path validation, symlink depth limits, size limits | ✅ Strong |
| Detection Engines | XSS, SQLi, Path Traversal detection | ✅ Strong |

**Overall Security Posture:** Good, with some areas needing attention (see Gaps below).

---

## Detailed Security Analysis

### 1. Input Validation Gaps

#### 1.1 Validator Coverage (✅ GOOD)

`src/core/world/validator.ts` provides comprehensive validation:

```typescript
// Path traversal detection
const PATH_TRAVERSAL_PATTERNS = ['..', '\0', '%00', '%2e%2e'];

// Trust boundary enforcement
if (details?.payloadSource === 'invariant-live' && trust !== 'curated') {
    errors.push({ code: 'TRUST_VIOLATION' });
}

// Prototype pollution defense
const dangerousKeys = ['__proto__', 'constructor', 'prototype'];

// Executable code detection (recursive depth limit: 20)
function detectExecutableCode(obj, path, errors, depth = 0) {
    if (depth > 20) { errors.push(...); return; }
    if (typeof obj === 'function') { errors.push(...); return; }
}
```

**Tests verify:**
- Functions rejected (SECURITY_VIOLATION)
- `__proto__` keys rejected
- `constructor` keys rejected
- `..` paths rejected (PATH_TRAVERSAL)
- Null bytes rejected
- Relative paths rejected
- `invariant-live` blocked for community trust

#### 1.2 Module Input Validation (⚠️ MODERATE CONCERN)

Modules parse external input without centralized validation framework:

| Module | Input Method | Risk |
|--------|--------------|------|
| `cloud-api.ts` | `decodeURIComponent()` + regex parsing | Potential malformed URI DoS |
| `k8s-api-module.ts` | `base64Decode()` + string split | Token format validation only |
| `variant-internet.ts` | `decodeURIComponent()` + regex | Same as above |
| `fs-monitor.ts` | Regex marker parsing | Low risk (controlled format) |
| `terminal-lens.ts` | Byte-by-byte OSC parsing | Buffer limits enforced (256→64 chars) |
| `pipeline-sim.ts` | `JSON.parse()` | Try/catch present |

**Recommendation:** Consider adding a shared input validation utility for modules handling external input.

#### 1.3 VM Image URL Validation (⚠️ GAP IDENTIFIED)

`src/core/vm/v86-backend.ts` loads VM images:

```typescript
const imageUrl = `${imageBaseUrl}/${spec.image}.bin`;
// No validation of imageBaseUrl or spec.image before fetch
```

**Risk:** If `imageBaseUrl` or `spec.image` is attacker-controlled, could lead to:
- SSRF (Server-Side Request Forgery)
- Loading of untrusted VM images

**Recommendation:** Validate URL components against allowlist before fetch.

---

### 2. Event System Gaps

#### 2.1 EventBus Security (✅ GOOD)

`src/core/event-bus.ts` implements:
- Read-only subscriptions (handlers receive readonly events)
- Emit-only (no modification after emit)
- Bounded log size (10,000 events)

```typescript
export interface EventBus {
    emit<T extends EngineEvent>(event: T): void;  // Only emit
    on<T extends EngineEvent>(filter: EventFilter, handler: EventHandler<T>): () => void;
}
```

#### 2.2 Event Type Validation (⚠️ MINOR)

Modules emit events with arbitrary types. No runtime validation that emitted events conform to expected schemas.

**Risk:** Malformed events could confuse downstream handlers.

---

### 3. Sandbox Escapes

#### 3.1 VM Isolation (✅ EXCELLENT)

`src/core/vm/v86-backend.ts` is properly air-gapped:

```typescript
const options: V86Options = {
    wasm_path: V86_WASM_URL,
    memory_size: memoryMB * 1024 * 1024,
    // SECURITY: No network relay. Frames go through our fabric.
    // network_relay_url is intentionally omitted.
    // ...
};
```

All network traffic is routed through `NetworkFabric` which has no external connectivity.

#### 3.2 Frame Handler Isolation (✅ GOOD)

```typescript
for (const handler of frameHandlers) {
    try { handler(frame); } catch { /* Handler errors must not crash VM */ }
}
```

Frame handler errors are caught to prevent VM crashes.

#### 3.3 File Overlay Application (⚠️ VALIDATION CHAIN)

```typescript
async applyOverlay(vm: VMInstance, overlay: FilesystemOverlay): Promise<void> {
    for (const [path, file] of overlay.files) {
        // Paths come from WorldSpec which is validated by validator.ts
        // But no re-validation here
        await state.emulator.create_file(path, content);
    }
}
```

**Risk:** If validation is bypassed or there's a bug in validator, path traversal could occur here.

**Recommendation:** Add defensive path validation in `applyOverlay` as defense-in-depth.

---

### 4. Type Safety Gaps

#### 4.1 `as unknown as` Casts (⚠️ WIDESPREAD)

Found 29 occurrences across codebase:

```typescript
// Critical locations:
src/core/world/compose.ts:313:    return composed as unknown as WorldSpec;
src/core/world/compose.ts:388:    return merged as unknown as MachineSpec;
src/modules/traffic-generator.ts:271: (module as unknown as { _patterns: ... })._patterns = ...;
src/modules/mail-module.ts:399:     spec.accounts as unknown as Readonly<...>;
src/lib/scenario/scenario-store.ts:176: const forked = deepClone(original) as unknown as Record<string, unknown>;
```

**Risk:** These bypass TypeScript's type checking, potentially masking security issues.

**Priority fixes:**
1. `traffic-generator.ts` - accesses private `_patterns` via type cast
2. `compose.ts` - core world composition uses unsafe casts

#### 4.2 Token ID Generation (⚠️ PREDICTABLE)

```typescript
let nextTokenId = 1;  // Module-level mutable state

function issueToken(): CapabilityToken {
    const id = `token-${nextTokenId++}`;  // Simple increment
    // ...
}
```

**Risk:** Token IDs are predictable (token-1, token-2, ...).

**Recommendation:** Use cryptographically random IDs.

---

### 5. Race Conditions

#### 5.1 Async VM Operations (✅ GOOD)

```typescript
public async sendKeys(vm: VMInstance, text: string): Promise<void> {
    const state = getVMState(vm);
    for (const char of text) {
        await state.emulator.keyboard_send_text(char);
        await new Promise(r => setTimeout(r, 10));
    }
}
```

Serial execution prevents race conditions in keyboard input.

#### 5.2 EventBus (✅ GOOD)

Synchronous event emission prevents interleaving attacks:

```typescript
emit<T extends EngineEvent>(event: T): void {
    const frozen = deepFreeze(event);
    // ... synchronous dispatch
}
```

#### 5.3 Module Loading (✅ GOOD)

```typescript
public async loadModules(): Promise<void> {
    for (const module of this.modules) {
        try {
            await module.initialize?.(this.context);
        } catch (error) {
            console.error(`[Module] Failed to load ${module.id}:`, error);
        }
    }
}
```

Sequential initialization with error isolation.

---

### 6. Resource Exhaustion

#### 6.1 Global Limits (✅ GOOD)

| Resource | Limit | Location |
|----------|-------|----------|
| Machines | 20 | validator.ts |
| Memory per VM | 256 MB | validator.ts |
| Files per machine | 200 | validator.ts |
| File content | 1 MB | validator.ts |
| EventBus log | 10,000 events | event-bus.ts |
| Traffic log | 50,000 entries | fabric/frames.ts |
| VFS file size | 5 MB | vfs.ts |
| Symlink depth | 20 | vfs.ts |
| Path length | 8192 chars | vfs.ts |

#### 6.2 Sandbox Engine Limits (✅ GOOD)

```typescript
checkLimits(sandbox, operation): boolean {
    if (sandbox.usage.totalOps >= limits.maxTotalOps) return false;
    // Per-tick limits for file ops, shell ops, events
}
```

#### 6.3 Module-Specific Limits (MIXED)

| Module | Limit | Status |
|--------|-------|--------|
| `terminal-lens.ts` | OSC buffer 256 chars | ✅ |
| `http-service.ts` | 2 MB request, 500 headers | ✅ |
| `network-monitor.ts` | Port scan threshold 10 | ✅ |
| `cloud-api.ts` | None | ⚠️ |
| `variant-internet.ts` | None | ⚠️ |

---

## Trust Boundary Analysis

### WorldSpec → Execution Flow

```
User WorldSpec
     ↓
[Validator] ← Trust boundary enforced here
     ↓
[deepFreeze] ← Immutable from this point
     ↓
[Compose/Migrate] ← Type casts present (risk)
     ↓
[Boot VMs] ← VM image URL loading (validation gap)
     ↓
[Load Modules] ← Module input validation (decentralized)
     ↓
[Run Simulation]
```

### Trust Levels

| Level | Description | Restrictions |
|-------|-------------|--------------|
| `community` | User-created levels | Cannot use `invariant-live` payloads |
| `curated` | Reviewed levels | Full access |

---

## Recommendations

### High Priority

1. **Fix VM Image URL Validation**
   - Add URL component validation in `v86-backend.ts`
   - Allowlist allowed image base URLs

2. **Reduce Type Casts**
   - Replace `as unknown as` with proper type guards
   - Priority: `traffic-generator.ts`, `compose.ts`

3. **Add Defensive Path Validation**
   - Add path validation in `applyOverlay` even though validator covers it

### Medium Priority

4. **Module Input Validation Framework**
   - Create shared validation utilities for external input
   - Apply to `cloud-api.ts`, `k8s-api-module.ts`, `variant-internet.ts`

5. **Random Token IDs**
   - Replace incrementing IDs with crypto-random values

6. **Rate Limiting**
   - Add request rate limits to external-facing module handlers

### Low Priority

7. **Event Schema Validation**
   - Add runtime event validation for critical event types

8. **Security Headers**
   - Add security headers to HTTP responses in `http-service.ts`

---

## Security Test Coverage

| Component | Test File | Coverage |
|-----------|-----------|----------|
| Validator | `tests/core/validator.test.ts` | Functions, proto pollution, path traversal, trust boundary |
| Deep Freeze | `tests/core/freeze.test.ts` | Immutability, circular refs, ArrayBuffer handling |
| Firewall | `tests/security-systems.test.ts` | Rule matching, CIDR, chain evaluation |
| Process Tree | `tests/security-systems.test.ts` | Spawning, killing, reparenting, anomaly detection |
| SIEM | `tests/security-systems.test.ts` | Ingestion, queries, rules, alerts |
| VFS | `tests/lib/vfs/vfs.test.ts` | Path traversal, symlinks, file operations |
| Sandbox | `tests/lib/sandbox/sandbox.test.ts` | Resource limits, permissions, violations |

---

## Conclusion

The VARIANT engine has a **strong security foundation** with:
- Comprehensive input validation at the trust boundary
- Proper VM isolation (air-gapped)
- Resource limits throughout the stack
- Good test coverage for security features

**Main areas for improvement:**
1. VM image URL validation
2. Type safety (reduce `as unknown as` casts)
3. Module input validation standardization

**Overall Risk Level:** LOW-MEDIUM
