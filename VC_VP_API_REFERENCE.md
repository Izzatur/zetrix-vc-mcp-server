# myeg-ms-credential — VC & VP API Reference

Service: **myeg-credential-service**
Base URL (local): `http://localhost:8777`
Authentication: OAuth2 JWT (Bearer token), routed via `myeg-ms-gateway` under `/cred/`.
All responses are wrapped in `ResponseWrapper<T>`.

This document covers four key API flows:

| # | Flow | Endpoint | Actor |
|---|------|----------|-------|
| 1 | **Apply VC** | `POST /v1/vc/apply` | Holder |
| 2 | **Issue VC** | `POST /v1/vc/issue` | Issuer |
| 3 | **Download VC** | `POST /v1/vc/download` | Holder |
| 4 | **VP Present (Create + Submit + Cache + Verify)** | `POST /v1/vp/*` | Holder / Verifier |

---

## Common Response Envelope

Every endpoint returns a `ResponseWrapper<T>`:

```json
{
  "object": { },
  "success": true,
  "timestamp": "2026-04-13T10:30:45.123",
  "messages": [],
  "httpStatus": "OK"
}
```

On exception the wrapper contains `success: false` and a populated `messages` list with error code and message from the `ErrorCode` enum (650xxx range, see `shared/exception/ERROR_CODES.md`).

---

## 1. Apply VC

Holder submits a VC application to the issuer for a given template.

### Endpoint
```
POST /v1/vc/apply
Content-Type: application/json
Authorization: Bearer <JWT>
```

### Request DTO — `ApplyVcReqDto`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `data` | `List<TemplateMetadataDto>` | ✅ | Template + metadata to apply for |
| `signData` | `String` | ✅ | Holder Ed25519 signature over the request payload |
| `publicKey` | `String` | ✅ | Holder Ed25519 public key |

`TemplateMetadataDto`:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `templateId` | `String` | ✅ | VC template identifier |
| `passDesignId` | `String` | ❌ | Pass design identifier (optional) |
| `metadata` | `Map<String,Object>` | ✅ | Key/value claims that populate the VC |
| `tds` | `String` | ❌ | Template Data Store reference |

**Request example:**
```json
{
  "data": [
    {
      "templateId": "tpl-eKYC-2025",
      "passDesignId": "design-001",
      "metadata": {
        "fullName": "Ahmad bin Abdullah",
        "icNumber": "900101-01-1234"
      }
    }
  ],
  "signData": "3045022100...",
  "publicKey": "b001cf5b0e..."
}
```

### Response DTO — `ApplyVcRespDto`

| Field | Type | Description |
|-------|------|-------------|
| `vcId` | `String` | Newly created VC application id |
| `status` | `VcStatus` enum | e.g. `PENDING`, `APPROVED`, `REJECTED` |

**Response example:**
```json
{
  "object": {
    "vcId": "vc-7f2a1c8b-9d3e-4b11-8c42-3f5d6e7a8b90",
    "status": "PENDING"
  },
  "success": true,
  "timestamp": "2026-04-13T10:30:45.123",
  "httpStatus": "OK"
}
```

---

## 2. Issue VC

Issuer issues a VC directly to a holder DID in a single call (combines create + sign + submit).

### Endpoint
```
POST /v1/vc/issue
Content-Type: application/json
Authorization: Bearer <JWT>
```

### Request DTO — `IssueDirectVcReqDto`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `issuanceDate` | `String` | ❌ | ISO-8601 issuance date |
| `expirationDate` | `String` | ❌ | ISO-8601 expiration date |
| `validFrom` | `String` | ❌ | ISO-8601 validity start |
| `validUntil` | `String` | ❌ | ISO-8601 validity end |
| `data` | `List<TemplateMetadataDto>` | ✅ | Template + claim metadata |
| `issuerPrivateKey` | `String` (size = 56) | ✅ | Issuer Ed25519 private key (56 chars) |
| `keyExpiry` | `int` | ❌ | Key expiry (default `0`) |
| `holderDid` | `String` | ✅ | Holder DID/ZID to issue to |

**Request example:**
```json
{
  "issuanceDate": "2026-04-13T00:00:00Z",
  "expirationDate": "2027-04-13T00:00:00Z",
  "validFrom": "2026-04-13T00:00:00Z",
  "validUntil": "2027-04-13T00:00:00Z",
  "data": [
    {
      "templateId": "tpl-eKYC-2025",
      "metadata": { "fullName": "Ahmad bin Abdullah" }
    }
  ],
  "issuerPrivateKey": "privbs...........................................56chars",
  "keyExpiry": 0,
  "holderDid": "did:zid:ztx12345abcdef..."
}
```

### Response DTO — `SubmitVcRespDto`

| Field | Type | Description |
|-------|------|-------------|
| `vc` | `VerifiableCredential` | Fully formed W3C VC JSON-LD object |
| `vcPassBase64` | `List<String>` | Base64 encoded pass designs (Apple/Google wallet passes) |
| `downloadExpiryDate` | `Date` | Timestamp after which direct download is disabled |

**Response example:**
```json
{
  "object": {
    "vc": {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      "id": "urn:uuid:vc-7f2a1c8b-...",
      "type": ["VerifiableCredential"],
      "issuer": "did:zid:ztxIssuer...",
      "issuanceDate": "2026-04-13T00:00:00Z",
      "credentialSubject": { "id": "did:zid:ztxHolder...", "fullName": "Ahmad bin Abdullah" },
      "proof": { "type": "Ed25519Signature2020", "proofValue": "..." }
    },
    "vcPassBase64": ["iVBORw0KGgoAAA..."],
    "downloadExpiryDate": "2026-04-20T00:00:00Z"
  },
  "success": true,
  "timestamp": "2026-04-13T10:31:02.004",
  "httpStatus": "OK"
}
```

---

## 3. Download VC

Holder (or issuer) downloads an issued VC in JSON-LD form.

### Endpoint
```
POST /v1/vc/download
Content-Type: application/json
Authorization: Bearer <JWT>
```

### Request DTO — `DownloadVcReqDto`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `vcId` | `String` | ✅ | Identifier of the VC to download |
| `signVcId` | `String` | ✅ | Signature over `vcId` using holder's private key (proves ownership) |
| `isIssuer` | `Boolean` | ❌ | `true` when issuer is downloading; default `false` |

**Request example:**
```json
{
  "vcId": "vc-7f2a1c8b-9d3e-4b11-8c42-3f5d6e7a8b90",
  "signVcId": "3045022100abcdef...",
  "isIssuer": false
}
```

### Response DTO — `SubmitVcRespDto`

Same shape as the Issue VC response — returns the full VC, pass designs, and download expiry.

| Field | Type | Description |
|-------|------|-------------|
| `vc` | `VerifiableCredential` | The signed W3C VC JSON-LD object |
| `vcPassBase64` | `List<String>` | Base64 encoded wallet passes |
| `downloadExpiryDate` | `Date` | Timestamp when download link expires |

**Common errors:**
- `650200 VC_RECORD_NOT_EXIST` — VC id does not exist or is expired
- `650201 VC_EXPIRED` — VC has expired
- Invalid signature → `401 Unauthorized` via `VC_INVALID_ISSUER` / similar

---

## 4. VP Present Flow

Presenting a Verifiable Presentation is a multi-step flow. The holder **creates** a VP blob, **submits** the signed VP, optionally **caches** it to obtain a share-uuid, and the verifier **verifies** it.

### 4.1 Create VP — `POST /v1/vp/create`

Holder assembles a VP from a VC and selects the attributes to reveal (supports BBS+ selective disclosure and range proofs).

**Request DTO — `CreateVpReqDto`**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `vc` | `VerifiableCredential` | ✅ | The VC to present |
| `revealAttribute` | `List<String>` | ❌ | Attribute names to selectively disclose (BBS+) |
| `rangeProof` | `RangeProof` | ❌ | Range-proof configuration (e.g. age > 18) |
| `bbsPublicKey` | `String` | ❌ | Holder BBS+ public key (required for selective disclosure) |
| `ed25519PubKey` | `String` | ❌ | Holder Ed25519 public key |

**Response DTO — `CreateVpRespDto`**

| Field | Type | Description |
|-------|------|-------------|
| `blobId` | `String` | Reference to the unsigned VP blob held server-side |
| `blob` | `String` | Canonicalised VP payload the holder must sign |

---

### 4.2 Submit VP — `POST /v1/vp/submit`

Holder returns the signed VP blob; server assembles the final `VerifiablePresentation`.

**Request DTO — `SubmitVpReqDto`**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `blobId` | `String` | ✅ | Id returned from `/v1/vp/create` |
| `ed25519SignData` | `String` | ✅ | Holder Ed25519 signature over the blob |
| `ed25519PubKey` | `String` | ✅ | Holder Ed25519 public key |

**Response** — `VerifiablePresentation` (W3C VP JSON-LD):

```json
{
  "object": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiablePresentation"],
    "verifiableCredential": [ /* VC(s) */ ],
    "proof": { "type": "Ed25519Signature2020", "proofValue": "..." }
  },
  "success": true,
  "httpStatus": "OK"
}
```

---

### 4.3 Cache VP — `POST /v1/vp/cache`

Holder caches a signed VP on the server and receives a short `uuid` to share with a verifier (used by the GET `/v1/vp/verify?id=` flow).

**Request DTO — `CacheVpReqDto`**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `vp` | `VerifiablePresentation` | ✅ | Signed VP to cache |

**Response DTO — `CacheVpRespDto`**

| Field | Type | Description |
|-------|------|-------------|
| `uuid` | `String` | Share-token representing the cached VP |

---

### 4.4 Verify VP (by value) — `POST /v1/vp/verify`

Verifier validates a VP object. Also available:
- `POST /v1/vp/verify-lite` — lightweight verification (signature only; skips heavy checks)
- `POST /v1/vp/verifyVp` — accepts raw `vp` string plus biometric wrapper (`VpVerifyWrapperReqDto`)
- `GET /v1/vp/verify?id={uuid}` — back-compatible verify using the cache uuid from §4.3

**Request DTO — `VerifyVpReqDto`**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `vp` | `VerifiablePresentation` | ✅ | Signed VP to verify |
| `ed25519PubKey` | `String` | ❌ | Expected holder Ed25519 public key |
| `bbsPublicKey` | `String` | ❌ | Expected holder BBS+ public key (selective disclosure) |

**Response DTO — `VerifyVpRespDto`**

| Field | Type | Description |
|-------|------|-------------|
| `isVerified` | `boolean` | `true` if signature + revocation checks pass |
| `errMsg` | `String` | Error message when `isVerified == false` |
| `vcDetail` | `List<VcDetail>` | Extracted details per VC in the VP |

`VcDetail`:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `String` | VC id |
| `issuer` | `String` | Issuer DID |
| `issuanceDate` | `String` | Issuance timestamp |
| `expirationDate` | `String` | Expiration timestamp |
| `validFrom` | `String` | Validity start |
| `validUntil` | `String` | Validity end |
| `credentialSubject` | `Map<String,Object>` | Disclosed claims |

**Response example:**
```json
{
  "object": {
    "isVerified": true,
    "errMsg": null,
    "vcDetail": [
      {
        "id": "vc-7f2a1c8b-...",
        "issuer": "did:zid:ztxIssuer...",
        "issuanceDate": "2026-04-13T00:00:00Z",
        "expirationDate": "2027-04-13T00:00:00Z",
        "validFrom": "2026-04-13T00:00:00Z",
        "validUntil": "2027-04-13T00:00:00Z",
        "credentialSubject": { "fullName": "Ahmad bin Abdullah" }
      }
    ]
  },
  "success": true,
  "httpStatus": "OK"
}
```

---

## End-to-End Flow Summary

```
Holder                  Issuer                    Verifier
  │                       │                          │
  │── POST /v1/vc/apply ─▶│  (Apply VC)              │
  │◀── ApplyVcRespDto ────│                          │
  │                       │                          │
  │                       │── POST /v1/vc/issue ─────│  (Issue VC)
  │                       │◀── SubmitVcRespDto ──────│
  │                       │                          │
  │── POST /v1/vc/download ▶ (Download VC)           │
  │◀── SubmitVcRespDto ───│                          │
  │                       │                          │
  │── POST /v1/vp/create ─▶                          │  (Create VP blob)
  │◀── CreateVpRespDto ───│                          │
  │── POST /v1/vp/submit ─▶                          │  (Sign + Submit VP)
  │◀── VerifiablePresentation                        │
  │── POST /v1/vp/cache ──▶                          │  (optional)
  │◀── CacheVpRespDto (uuid)                         │
  │                                                  │
  │──── share VP / uuid ───────────────────────────▶ │
  │                                                  │── POST /v1/vp/verify
  │                                                  │◀── VerifyVpRespDto
```

---

## Error Code Reference (VC/VP slice of 650xxx range)

| Code | Name | HTTP | Meaning |
|------|------|------|---------|
| 650500 | `VC_RECORD_NOT_EXIST` | 404 | VC application/record not found or expired |
| 650501 | `VC_EXPIRED` | 410 | VC has passed its expiry date |
| 650502 | `TEMPLATE_NOT_EXIST` | 404 | Referenced template missing |
| 650xxx | `VP_VERIFY_FAILED` | 400 | VP signature / revocation check failed |

See `shared/exception/ErrorCode.java` for the full catalogue.

---

## Related Source Files

| Concern | Path |
|---------|------|
| VC controller | `src/main/java/com/myeg/credential/vc/controller/VcControllerV1.java` |
| VP controller | `src/main/java/com/myeg/credential/vp/controller/VpControllerV1.java` |
| VC DTOs (req) | `src/main/java/com/myeg/credential/vc/dto/req/` |
| VC DTOs (resp) | `src/main/java/com/myeg/credential/vc/dto/resp/` |
| VP DTOs (req) | `src/main/java/com/myeg/credential/vp/dto/req/` |
| VP DTOs (resp) | `src/main/java/com/myeg/credential/vp/dto/resp/` |
| Template DTO | `src/main/java/com/myeg/credential/tds/dto/TemplateMetadataDto.java` |
| Response wrapper | `src/main/java/com/myeg/credential/shared/dto/ResponseWrapper.java` |
| Error codes | `src/main/java/com/myeg/credential/shared/exception/ErrorCode.java` |

Swagger UI: `http://localhost:8777/swagger-ui.html`
