# Code Review — `src/index.ts`

Review of validation gaps, bugs, and inconsistencies found across the Issue VC and VP flows.

---

## Bugs

### Bug 1 — `bbsPublicKey` silently dropped in VP flow

**Files:** `src/index.ts` lines 1855, 1936  
**Severity:** High — BBS+ selective disclosure is completely broken when `bbsPublicKey` is supplied

**Root cause:**

```typescript
// zetrix_vp_create (line 1855) and zetrix_vp_present (line 1936)
bbsPublicKey: asEncodedEd25519PubKey(args.bbsPublicKey as string | undefined),
```

`asEncodedEd25519PubKey()` only accepts `b001…` 76-hex strings — the Ed25519 encoded format. BBS+ public keys use multibase encoding (typically starts with `z`), which is a completely different format. This function always returns `undefined` for any valid BBS+ key, so the key is silently dropped before the BaaS call.

**Fix:** Pass `bbsPublicKey` through as-is without filtering through the Ed25519 check:

```typescript
// Before
bbsPublicKey: asEncodedEd25519PubKey(args.bbsPublicKey as string | undefined),

// After
bbsPublicKey: pick(args.bbsPublicKey as string | undefined),
```

---

### Bug 2 — `ISSUER_KEY` used as issuer address in revoke

**Files:** `src/index.ts` lines 2001, 2026, 2069  
**Severity:** High — revoke fails whenever `ISSUER_KEY` is set to an encoded pubkey (the normal case)

**Root cause:**

```typescript
// zetrix_vc_revoke_create_blob, zetrix_vc_revoke, zetrix_vc_revoke_status
const issuerAddress = requireEnv(
  ISSUER_KEY,   // ← holds b001… encoded pubkey, NOT a ZTX3 address
  "issuerAddress (or ISSUER_KEY env)",
  args.issuerAddress as string | undefined
);
```

`ISSUER_KEY` is the issuer's encoded Ed25519 public key (`b001…` form). The revoke API expects a Zetrix account address (`ZTX3…` form). These are different values. Passing a pubkey where an address is expected will cause the BaaS to reject the request.

**Fix options (pick one):**
1. Introduce a dedicated `ISSUER_ADDRESS` env var for the revoke tools
2. Derive the address from `ISSUER_PRIVATE_KEY` as a fallback when no explicit address is provided
3. In `zetrix_vc_revoke`, derive the address from `issuerPrivateKey` (already resolved) using the SDK

---

### Bug 3 — Template validation skipped when metadata has any field

**Files:** `src/index.ts` lines 1674, 1745  
**Severity:** Medium — partial metadata bypasses mandatory field validation in `apply` and `issue`

**Root cause:**

```typescript
// zetrix_vc_apply (line 1674) and zetrix_vc_issue (line 1745)
if (Object.keys(firstMetadata).length === 0) {
  // template validation only runs when metadata is completely empty
}
```

The guard means: if the user passes `{ name: "John" }` but the template also requires `icNo`, the local validation is skipped entirely because the metadata object is not empty. The BaaS will reject the request later with a cryptic error code instead of a clear "missing icNo" message.

Compare to `zetrix_vc_request_credential` which always validates regardless of metadata state.

**Fix:** Remove the empty-metadata guard and always run validation when TDS info is available:

```typescript
// Before
if (Object.keys(firstMetadata).length === 0) {
  const tdsAddr = pick(TDS_CONTRACT_ADDRESS);
  if (tdsAddr) {
    try {
      const template = await nodeClient.getTemplateDetail(...);
      const info = extractTemplateInfo(template.value);
      if (info) {
        const missing = findMissingRequiredAttributes(firstMetadata, info);
        if (missing.length > 0) { throw NEXT_STEP_REQUIRED }
      }
    } catch (e) { ... }
  }
}

// After — always validate when TDS address is available
const tdsAddr = pick(TDS_CONTRACT_ADDRESS);
if (tdsAddr) {
  try {
    const template = await nodeClient.getTemplateDetail(...);
    const info = extractTemplateInfo(template.value);
    if (info) {
      const missing = findMissingRequiredAttributes(firstMetadata, info);
      if (missing.length > 0) { throw NEXT_STEP_REQUIRED }
    }
  } catch (e) { ... }
}
```

---

## Missing Validations

### Missing 1 — No date format validation

**Files:** `src/index.ts` — all date args across `request_credential`, `apply`, `issue`, `vc_create`  
**Severity:** Low-Medium — wrong date formats cause cryptic BaaS errors

Date fields (`issuanceDate`, `validFrom`, `validUntil`, `expirationDate`) accept any string. A value like `"2025/04/17"` or `"17-04-2025"` passes local checks and the BaaS returns a confusing error.

**Fix:** Add a simple format guard before any date is used:

```typescript
function validateDateFormat(value: string, fieldName: string): void {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    throw new Error(`${fieldName} must be in yyyy-MM-dd format (got "${value}").`);
  }
}
```

---

### Missing 2 — No `validFrom` / `validUntil` ordering check

**Files:** `src/index.ts` — `request_credential`, `issue` handlers  
**Severity:** Low — can produce a VC that is never valid

Nothing prevents issuing a VC where `validUntil` is before `validFrom`. The BaaS may accept it silently.

**Fix:** After resolving both dates, compare them:

```typescript
if (validFrom && resolvedValidUntil && validFrom > resolvedValidUntil) {
  throw new Error(`validFrom (${validFrom}) must be before validUntil (${resolvedValidUntil}).`);
}
```

---

### Missing 3 — No VC expiry or revocation pre-check before VP creation

**Files:** `src/index.ts` — `zetrix_vp_present` handler (line 1912)  
**Severity:** Medium — expired or revoked VC gives a cryptic BaaS error instead of a clear message

`zetrix_vp_present` passes the VC directly to `createVp()` without checking:
- Whether `vc.validUntil` has already passed (VC expired)
- Whether the VC has been revoked (would need a `revokeStatus` call)

**Fix:** Add pre-flight checks before calling `createVp()`:

```typescript
// Check expiry locally (no network call needed)
const validUntil = pick((vc as any).validUntil);
if (validUntil && new Date(validUntil) < new Date()) {
  throw new Error(`This credential expired on ${validUntil} and cannot be presented.`);
}

// Optionally check revocation (network call — make it opt-in or best-effort)
```

---

### Missing 4 — `revealAttribute` paths not validated against VC structure

**Files:** `src/index.ts` — `zetrix_vp_create`, `zetrix_vp_present` handlers  
**Severity:** Low — wrong paths produce a VP with empty disclosures silently

Dotted paths like `mykad.icNo` are passed directly to the BaaS without checking that they exist in `vc.credentialSubject`. A typo like `myKad.icNo` (wrong casing) would silently produce an empty VP.

**Fix (best-effort):** Warn when a path doesn't resolve in the VC:

```typescript
function warnMissingRevealPaths(vc: VerifiableCredential, paths: string[]): string[] {
  const subject = (vc as any).credentialSubject ?? {};
  return paths.filter((path) => {
    const parts = path.split(".");
    let node: any = subject;
    for (const part of parts) {
      if (!node || typeof node !== "object" || !(part in node)) return true;
      node = node[part];
    }
    return false;
  });
}
```

---

## Inconsistencies

### Inconsistency 1 — Template check error handling differs across tools

**Files:** `src/index.ts`

| Tool | Behaviour when TDS node is unreachable |
|---|---|
| `request_credential` | Error propagates — user sees the network error |
| `apply` | Error silently swallowed — falls through to BaaS |
| `issue` | Error silently swallowed — falls through to BaaS |

In `apply` and `issue`, the catch block intentionally swallows non-`NEXT_STEP_REQUIRED` errors as best-effort. The downside is that a TDS node outage is invisible — the user sees a cryptic BaaS rejection instead of "could not reach template service".

**Suggested improvement:** Surface template check failures as a warning in the response rather than swallowing them completely:

```typescript
} catch (e) {
  if (e instanceof Error && e.message.startsWith("NEXT_STEP_REQUIRED")) throw e;
  // Instead of silently swallowing, include a non-fatal warning
  console.error("Template pre-flight check failed (non-fatal):", e);
}
```

---

### Inconsistency 2 — `zetrix_vc_issue` has no prior apply step

**Status:** ✅ Resolved — confirmed by design

Two separate flows exist intentionally:
- **Flow 1 (holder-initiated):** `apply → vc/create → vc/submit` — holder signs the application, then issuer finalises via the advanced signing pipeline
- **Flow 2 (issuer-initiated):** `zetrix_vc_issue` — issuer directly issues to a recipient DID without a prior apply; uses a different BaaS endpoint

`zetrix_vc_issue` is not missing an apply step — it is a separate issuer-driven path by design.

---

## Summary

| # | Type | Severity | Location |
|---|---|---|---|
| Bug 1 | BBS+ key silently dropped | **High** | `vp_create` / `vp_present` line 1855, 1936 |
| Bug 2 | `ISSUER_KEY` (pubkey) used as address in revoke | **High** | `revoke*` lines 2001, 2026, 2069 |
| Bug 3 | Template validation skipped on partial metadata | **Medium** | `apply` / `issue` lines 1674, 1745 |
| Missing 1 | No date format validation | Low-Medium | All date args |
| Missing 2 | No `validFrom` < `validUntil` check | Low | `request_credential`, `issue` |
| Missing 3 | No VC expiry / revocation pre-check before VP | Medium | `vp_present` line 1912 |
| Missing 4 | `revealAttribute` paths not validated | Low | `vp_create`, `vp_present` |
| Inconsistency 1 | Template error swallowed in apply/issue | Low | `apply` / `issue` catch blocks |
| Inconsistency 2 | `zetrix_vc_issue` skips apply step | ✅ By design | Two intentional BaaS flows |
