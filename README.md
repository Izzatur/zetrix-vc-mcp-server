# Zetrix VC MCP Server

A Model Context Protocol (MCP) server that exposes the **Zetrix BaaS Verifiable
Credentials (VC) / Verifiable Presentations (VP)** API as tools for MCP clients
(Claude, IDE integrations, custom agents).

Wraps the `myeg-ms-credential` service routed through the Zetrix BaaS gateway:

| Network | Base URL                         |
|---------|----------------------------------|
| UAT     | `https://api-sandbox.zetrix.com` |
| Prod    | `https://api.zetrix.com`         |

See [`VC_VP_API_REFERENCE.md`](VC_VP_API_REFERENCE.md) for the full API contract.

## Supported Flows

| # | Flow               | Endpoint              | Actor             | Tool                  |
|---|--------------------|-----------------------|-------------------|-----------------------|
| 1 | Apply VC           | `POST /v1/vc/apply`   | Holder            | `zetrix_vc_apply`     |
| 2 | Issue VC           | `POST /v1/vc/issue`   | Issuer            | `zetrix_vc_issue`     |
| 3 | Download VC        | `POST /v1/vc/download`| Holder / Issuer   | `zetrix_vc_download`  |
| 4 | Create VP (blob)   | `POST /v1/vp/create`  | Holder            | `zetrix_vp_create`    |
| 5 | Submit VP (signed) | `POST /v1/vp/submit`  | Holder            | `zetrix_vp_submit`    |
| 6 | Present VP (combo) | create+sign+submit    | Holder            | `zetrix_vp_present`   |
| 7 | Cache VP           | `POST /v1/vp/cache`   | Holder            | `zetrix_vp_cache`     |
| 8 | Verify VP          | `POST /v1/vp/verify`  | Verifier          | `zetrix_vp_verify`    |

Plus `zetrix_vc_version` for diagnostics.

## Install & Build

```bash
npm install
npm run build
```

Run locally (stdio transport, for MCP clients):

```bash
npm start
```

Run in HTTP mode (Streamable HTTP transport on `http://localhost:3000/mcp`):

```bash
npm run start:http
```

## Configuration (environment variables)

Copy `.env.example` to `.env` (or set these in your MCP client's `env` block):

| Variable                | Required | Description                                                                 |
|-------------------------|----------|-----------------------------------------------------------------------------|
| `ZETRIX_VC_NETWORK`     | no       | `uat` (default) or `prod` — selects the base URL.                            |
| `ZETRIX_VC_BASE_URL`    | no       | Explicit base URL override.                                                  |
| `ZETRIX_VC_TRANSPORT`   | no       | `stdio` (default) or `http`.                                                 |
| `ZETRIX_VC_PORT`        | no       | Port for HTTP transport (default `3000`).                                    |
| `AWS_GATEWAY_API_KEY`   | yes\*    | Sent as `x-api-key`.                                                         |
| `BAAS_API_KEY`          | yes\*    | Sent as `Authorization: Bearer <key>`.                                       |
| `ISSUER_KEY`            | no       | Issuer public key (informational).                                           |
| `ISSUER_PRIVATE_KEY`    | †        | Required for `zetrix_vc_issue` (unless passed per-call).                     |
| `HOLDER_KEY`            | no       | Holder public key. If omitted, derived from `HOLDER_PRIVATE_KEY`.            |
| `HOLDER_PRIVATE_KEY`    | †        | Required for apply / download / VP flows (unless passed per-call).          |
| `DEFAULT_TEMPLATE_ID`   | no       | Fallback `templateId` used by `zetrix_vc_apply` / `zetrix_vc_issue` when a caller omits it on a `data[]` item. |

\* Required whenever the Zetrix BaaS gateway enforces the keys.
† Private keys may alternatively be passed as tool arguments (`issuerPrivateKey`,
`holderPrivateKey`) to avoid storing them in the environment.

## MCP Client Configuration

Examples under [`configs/`](configs/):

- `mcp-config-uat.json` — connects to `https://api-sandbox.zetrix.com`
- `mcp-config-prod.json` — connects to `https://api.zetrix.com`

Update the `args` path to point at your built `dist/index.js` and fill in the
env keys, then register the config with your MCP client (e.g. Claude Desktop,
Claude Code, Cursor).

## How signing works

All BaaS VC/VP flows use **Ed25519** signatures. This server uses
`zetrix-encryption-nodejs` (the same library as the main Zetrix MCP server) to
sign canonicalised payloads:

- `zetrix_vc_apply` — signs a canonical JSON of `{ data }` with the holder's key.
- `zetrix_vc_download` — signs `vcId` with the holder's (or issuer's) key.
- `zetrix_vp_submit` / `zetrix_vp_present` — signs the server-returned `blob`
  with the holder's key.

If you'd rather sign externally and submit the signature, every tool accepts
pre-computed signature fields (`signData` / `ed25519SignData` / `signVcId`).

## End-to-end example

```text
Holder                       Issuer                     Verifier
  │                            │                           │
  │── zetrix_vc_apply ────────▶│                           │
  │◀── { vcId, status }────────│                           │
  │                            │                           │
  │                            │── zetrix_vc_issue ───────▶│  (or auto after apply)
  │                            │                           │
  │── zetrix_vc_download ─────▶│                           │
  │◀── { vc, vcPassBase64 }────│                           │
  │                            │                           │
  │── zetrix_vp_present (cache:true) ──────────────────────│
  │◀── { vp, cache.uuid }                                  │
  │                                                        │
  │──── share uuid / vp ──────────────────────────────────▶│
  │                                                        │── zetrix_vp_verify
  │                                                        │◀── { isVerified, vcDetail }
```

## Related

- Zetrix blockchain MCP server (accounts, transactions, contracts):
  [`zetrix-mcp-server`](https://www.npmjs.com/package/zetrix-mcp-server)
- Zetrix BaaS documentation: [https://docs.zetrix.com](https://docs.zetrix.com)
