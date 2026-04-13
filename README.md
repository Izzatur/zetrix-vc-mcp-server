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

Plus:

- `zetrix_vc_version` — diagnostics (effective network / base URLs / env status).
- `zetrix_vc_get_template_detail` — fetches a template record from the on-chain
  TDS contract via `GET <NODE>/getAccountMetaData?address=<TDS_CONTRACT_ADDRESS>&key=template__<templateId>`.
  Falls back to `DEFAULT_TEMPLATE_ID` / `TDS_CONTRACT_ADDRESS` when args omitted.

## Install & Build

```bash
npm install
npm run build
```

The build step is required — the MCP server runs from `dist/index.js`.

## Running the Server

The server supports two transports. **Where the env vars live depends on
which you pick** — see [Environment Variables](#environment-variables) below.

### Option 1 — stdio transport (recommended for single-user / desktop clients)

With stdio, the **MCP client spawns the server as a child process** every time
it connects. You don't run the server yourself — the client does. Just build
once and point your client config at `dist/index.js`.

```bash
npm start                    # manual run, for smoke-testing only
```

For real use, register it with your MCP client using one of the config files in
[`configs/`](configs/):

- `mcp-config-uat.json` — connects to `https://api-sandbox.zetrix.com`
- `mcp-config-prod.json` — connects to `https://api.zetrix.com`

Both set `env` on the client side — see [Placing env vars](#placing-env-vars)
for what lands where.

### Option 2 — HTTP transport (recommended for shared / remote deployments)

With HTTP, you start the server **once, yourself**, and clients connect to a
URL. Secrets live on the **server** side.

```bash
# foreground
npm run start:http

# or with explicit env (no .env file — see "Placing env vars" below)
ZETRIX_VC_TRANSPORT=http \
ZETRIX_VC_PORT=3000 \
ZETRIX_VC_NETWORK=uat \
AWS_GATEWAY_API_KEY=your-aws-key \
BAAS_API_KEY=your-baas-key \
HOLDER_PRIVATE_KEY=... \
ISSUER_PRIVATE_KEY=... \
node dist/index.js
```

On startup you'll see:

```
Zetrix VC MCP Server running on http://localhost:3000/mcp (network=uat, baseUrl=https://api-sandbox.zetrix.com)
```

Endpoints:

| Path     | Method | Purpose                                                  |
|----------|--------|----------------------------------------------------------|
| `/health`| GET    | Status JSON (version, network, base URL, active sessions)|
| `/mcp`   | POST   | MCP Streamable HTTP — all JSON-RPC traffic               |

Verify it's up:

```bash
curl -s http://localhost:3000/health | jq .
```

Register it with an MCP client by URL (no `env` block needed client-side):

```bash
# Claude Code
claude mcp add --transport http zetrix-vc-uat http://localhost:3000/mcp
```

Or in a client config:

```json
{ "mcpServers": { "zetrix-vc-uat": { "type": "http", "url": "http://localhost:3000/mcp" } } }
```

⚠️ `/mcp` has **no built-in authentication** — don't expose it on the public
internet without a reverse proxy (nginx/Caddy) terminating TLS and enforcing
auth. The keys in env are used for *outbound* BaaS calls only.

## Environment Variables

| Variable                | Required | Description                                                                 |
|-------------------------|----------|-----------------------------------------------------------------------------|
| `ZETRIX_VC_NETWORK`     | no       | `uat` (default) or `prod` — selects the BaaS base URL.                       |
| `ZETRIX_VC_BASE_URL`    | no       | Explicit BaaS base URL override.                                             |
| `ZETRIX_VC_TRANSPORT`   | no       | `stdio` (default) or `http`.                                                 |
| `ZETRIX_VC_PORT`        | no       | Port for HTTP transport (default `3000`).                                    |
| `AWS_GATEWAY_API_KEY`   | yes\*    | Sent as `x-api-key`.                                                         |
| `BAAS_API_KEY`          | yes\*    | Sent as `Authorization: Bearer <key>`.                                       |
| `ISSUER_KEY`            | no       | Issuer public key (informational / diagnostics only).                        |
| `ISSUER_PRIVATE_KEY`    | †        | Required for `zetrix_vc_issue` (unless passed per-call).                     |
| `HOLDER_KEY`            | no       | Holder public key. If omitted, derived from `HOLDER_PRIVATE_KEY`.            |
| `HOLDER_PRIVATE_KEY`    | †        | Required for apply / download / VP flows (unless passed per-call).           |
| `DEFAULT_TEMPLATE_ID`   | no       | Fallback `templateId` used by `zetrix_vc_apply` / `zetrix_vc_issue` when a caller omits it on a `data[]` item. |
| `TDS_CONTRACT_ADDRESS`  | no       | Template Data Store contract address. Used by `zetrix_vc_get_template_detail`. |
| `RCL_CONTRACT_ADDRESS`  | no       | Revocation Contract List address (reserved for revocation lookups).          |
| `ZETRIX_NODE_BASE_URL`  | no       | Override for the node RPC. Defaults by network: uat → `https://test-node.zetrix.com`, prod → `https://node.zetrix.com`. |

\* Required whenever the Zetrix BaaS gateway enforces the keys.
† Private keys may alternatively be passed as tool arguments to avoid storing
them in the environment.

### Placing env vars

**The env vars must live where the server *process* runs.** That's a different
place depending on transport:

| Transport | Who starts the server?    | Where do env vars live?                                  |
|-----------|---------------------------|----------------------------------------------------------|
| stdio     | The MCP client, per call  | **Client-side config** — in the `env` block of `mcp-config-*.json` |
| http      | You, once                 | **Server-side** — shell env / systemd unit / `.env` / container env |

#### stdio — client-side config

The server is launched on demand by the client; it has no persistent `.env`.
Put the keys in the `env` block of your client's MCP config. Examples:

- Claude Desktop: `~/Library/Application Support/Claude/claude_desktop_config.json` (mac), `%APPDATA%\Claude\claude_desktop_config.json` (win)
- Claude Code: `~/.claude.json`
- Cursor: `~/.cursor/mcp.json`

Use [`configs/mcp-config-uat.json`](configs/mcp-config-uat.json) or
[`configs/mcp-config-prod.json`](configs/mcp-config-prod.json) as a template
— copy the `mcpServers` block into your client config and fill in values:

```json
{
  "mcpServers": {
    "zetrix-vc-uat": {
      "command": "node",
      "args": ["/absolute/path/to/zetrix-vc-mcp-server/dist/index.js"],
      "env": {
        "ZETRIX_VC_NETWORK": "uat",
        "AWS_GATEWAY_API_KEY": "...",
        "BAAS_API_KEY": "...",
        "HOLDER_PRIVATE_KEY": "...",
        "ISSUER_PRIVATE_KEY": "...",
        "DEFAULT_TEMPLATE_ID": "did:zid:...",
        "TDS_CONTRACT_ADDRESS": "ZTX..."
      }
    }
  }
}
```

A `.env` file in this repo is **not read** in stdio mode.

#### http — server-side

The server runs as a long-lived process that you start yourself. Pick any of:

**1. Inline on the command line (easiest for testing):**

```bash
ZETRIX_VC_TRANSPORT=http AWS_GATEWAY_API_KEY=... BAAS_API_KEY=... \
HOLDER_PRIVATE_KEY=... ISSUER_PRIVATE_KEY=... node dist/index.js
```

**2. `.env` file + shell export (dev loop):**

Copy the template and fill in values:

```bash
cp .env.example .env
# edit .env
set -a; source .env; set +a     # export every line into the shell
npm run start:http
```

The server itself does **not** auto-load `.env` — you must export it before
running node. (Ask if you'd like `dotenv` wired up so `node dist/index.js`
reads `.env` automatically.)

**3. systemd unit (production):**

```ini
# /etc/systemd/system/zetrix-vc-mcp.service
[Unit]
Description=Zetrix VC MCP Server
After=network.target

[Service]
Type=simple
User=armmarov
WorkingDirectory=/home/armmarov/work/projects/zetrix-vc-mcp-server
EnvironmentFile=/home/armmarov/work/projects/zetrix-vc-mcp-server/.env
Environment=ZETRIX_VC_TRANSPORT=http
Environment=ZETRIX_VC_PORT=3000
ExecStart=/usr/bin/node dist/index.js
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now zetrix-vc-mcp
journalctl -u zetrix-vc-mcp -f     # tail logs
```

**4. Docker / container env:** pass env vars via `-e` flags or a compose file.

### Override semantics

Every holder/issuer credential field has matching tool arguments — when passed,
they **always override** the environment. Empty strings in env (e.g. placeholder
values in config templates) are treated as "not set" so they don't block the
explicit arg.

| Env var                | Overriding tool arg                                |
|------------------------|----------------------------------------------------|
| `HOLDER_PRIVATE_KEY`   | `holderPrivateKey` (apply / download / vp_*)      |
| `HOLDER_KEY`           | `holderPublicKey` (apply), `ed25519PubKey` (vp_*) |
| `ISSUER_PRIVATE_KEY`   | `issuerPrivateKey` (issue / download with `isIssuer:true`) |
| `TDS_CONTRACT_ADDRESS` | `tdsContractAddress` (get_template_detail)        |
| `DEFAULT_TEMPLATE_ID`  | `templateId` on each `data[]` item, or top-level on get_template_detail |

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
