# Zetrix VC MCP Server

A Model Context Protocol (MCP) server for the **Zetrix BaaS Verifiable Credentials** API. Provides **20 tools** across 6 categories — VC issuance (apply / issue / download), Verifiable Presentations, revocation, DID generation & resolution, and on-chain template lookup. Supports both **stdio** and **HTTP** transport modes.

Wraps the `myeg-ms-credential` service exposed through the Zetrix BaaS gateway under `/cred/v1/*`.

## Quick Start

```bash
npx zetrix-vc-mcp-server
```

Or install globally:

```bash
npm install -g zetrix-vc-mcp-server
```

Minimum configuration — add to your MCP client's config (see [Claude Desktop](#claude-desktop) / [Claude Code](#claude-code-cli) below):

```json
{
  "mcpServers": {
    "zetrix-vc": {
      "command": "npx",
      "args": ["-y", "zetrix-vc-mcp-server"],
      "env": {
        "ZETRIX_VC_NETWORK": "uat",
        "AWS_GATEWAY_API_KEY": "<your AWS API Gateway key>",
        "BAAS_API_KEY": "<your Zetrix BaaS key>",
        "ISSUER_PRIVATE_KEY": "<issuer ed25519 private key>",
        "HOLDER_PRIVATE_KEY": "<holder ed25519 private key>",
        "DEFAULT_TEMPLATE_ID": "did:zid:…"
      }
    }
  }
}
```

## Features (20 tools)

### General (1 tool)

| Tool | Description |
|---|---|
| `zetrix_vc_version` | Server version, effective network / base URL, env status |

### DID Utilities (2 tools)

| Tool | Description |
|---|---|
| `zetrix_vc_generate_did` | Generate a DID (`did:zid:<rawPubKey>`) from a private / public / raw pubkey. No network call |
| `zetrix_vc_resolve_did` | Resolve a DID to its DID document (verification methods, service endpoints, permissions) via the Zetrix ZID resolver |

### Template Lookup (1 tool)

| Tool | Description |
|---|---|
| `zetrix_vc_get_template_detail` | Fetch a VC template (incl. required fields, label + format) from the on-chain Template Data Store contract |

### VC Issuance (8 tools)

The **preferred** entrypoint is `zetrix_vc_request_credential` — it orchestrates apply → issue → download in one call and writes the final VC to a JSON file on disk. The other tools expose individual steps for advanced integrations.

| Tool | Description |
|---|---|
| `zetrix_vc_request_credential` | **End-to-end: apply → issue → download → save .json**. Use when the user says "apply VC for me" / "issue me a VC" / "create VC for me" |
| `zetrix_vc_apply` | Holder applies for a VC — creates pending application only |
| `zetrix_vc_issue` | Issuer directly issues a VC to a specific holder (by DID, pubkey, or privkey). Returns signed VC |
| `zetrix_vc_download` | Download an already-issued VC by `vcId`; saves as `.json` on disk |
| `zetrix_vc_create` | *(Advanced)* Multi-step Flow 1 — prepare canonical VC payload for BBS+ and Ed25519 signing |
| `zetrix_vc_sign_bbs` | *(Advanced)* Sign canonical statements with issuer BBS+ keys |
| `zetrix_vc_submit` | *(Advanced)* Finalise issuance by submitting both signatures |

### VC Revocation (4 tools)

| Tool | Description |
|---|---|
| `zetrix_vc_revoke` | **One-shot revocation: create-blob → sign → submit**. Destructive — recorded on-chain permanently |
| `zetrix_vc_revoke_create_blob` | *(Advanced)* Step 1 — request hex-encoded revocation blob |
| `zetrix_vc_revoke_submit` | *(Advanced)* Step 3 — submit the signed blob |
| `zetrix_vc_revoke_status` | Query whether a VC is revoked (read-only) |

### Verifiable Presentations (5 tools)

| Tool | Description |
|---|---|
| `zetrix_vp_present` | **End-to-end VP: create → sign → submit (+ optional cache)**. Use when the user says "create VP" / "present my VC" |
| `zetrix_vp_create` | *(Advanced)* Returns the unsigned VP blob only |
| `zetrix_vp_submit` | *(Advanced)* Submit an already-signed VP blob |
| `zetrix_vp_cache` | Cache a signed VP and get a short share uuid to send to a verifier |
| `zetrix_vp_verify` | Verifier validates a VP. Accepts either the full VP object **or** a share uuid |

## Supported Networks

| Network | BaaS Gateway | Node RPC | ZID Resolver |
|---|---|---|---|
| UAT (sandbox) | `https://api-sandbox.zetrix.com` | `https://test-node.zetrix.com` | `https://zid-resolver-sandbox.zetrix.com` |
| Prod | `https://api.zetrix.com` | `https://node.zetrix.com` | `https://zid-resolver.zetrix.com` |

## Official Addresses & Template IDs

Use these when filling in `TDS_CONTRACT_ADDRESS`, `RCL_CONTRACT_ADDRESS`, and `DEFAULT_TEMPLATE_ID` environment variables.

### Contract addresses

| Contract | UAT | Prod |
|---|---|---|
| **TDS** (Template Data Store) | `ZTX3JszqPgRUx743SAp7q7zURfjvkWuH2FMEz` | `ZTX3GqJM1U6ifMPonwD4fGvrgoTKJua7b2cKX` |
| **RCL** (Revocation Contract List) | `ZTX3Mmovq155gzrD6Medi6bC5pGKAi5Y3QMwx` | `ZTX3H5w3CR3Eih5Uucoj4taL9kenmf83imYAk` |

### Official templates

| Template | UAT (`DEFAULT_TEMPLATE_ID`) | Prod (`DEFAULT_TEMPLATE_ID`) |
|---|---|---|
| **MyKAD** | `did:zid:f1d675934d353394fa90d6132a3f8393b670a326632d936d1174df7307fadba4` | `did:zid:2139cb5dc5c2080ff4f85a85f6ae49322d109992a921d5f8d50e1af5eadf01d5` |
| **Email** | `did:zid:9833ccc5238cfe4c61ccad652487c8b05f8c6f20e60073efe051fbbd1ea395aa` | `did:zid:9d0b9a925c66dab30a682446ea0bc75245e93eec6c0bb3a425b50795ebbb1a2e` |
| **Driving License** | `did:zid:313dc2cf2a9950a688f6b759dfbbbc8cd69e1fb6db1d15d877970119748c0a7c` | `did:zid:89b37ba3ab25c02d96f3acfd948c68aa7b86c5c313b421522db06b86fc831d6e` |
| **Passport** | `did:zid:4820fdbc080dda72335a436bba02252d341302382a58d7bb2ae8fe845579993e` | `did:zid:24cbe3286714b8dde39cdd04094f6b2c8d2c1803882d5762d06eb883971385f1` |

Use `zetrix_vc_get_template_detail` at runtime to inspect a template's required claim fields.

## Configuration

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `ZETRIX_VC_NETWORK` | Network (`uat` or `prod`) | `uat` |
| `ZETRIX_VC_BASE_URL` | Custom BaaS gateway URL (overrides network default) | — |
| `ZETRIX_VC_TRANSPORT` | Transport mode (`stdio` or `http`) | `stdio` |
| `ZETRIX_VC_PORT` | HTTP server port (only when `ZETRIX_VC_TRANSPORT=http`) | `3000` |
| `AWS_GATEWAY_API_KEY` | AWS API Gateway key (sent as `x-api-key`) | — |
| `BAAS_API_KEY` | Zetrix BaaS API key (sent as `Authorization: Bearer …`) | — |
| `ISSUER_KEY` | Issuer Zetrix address or encoded pubkey (informational) | — |
| `ISSUER_PRIVATE_KEY` | Issuer Ed25519 private key (56-char `priv…` form) | — |
| `ISSUER_DID` | Issuer DID (`did:zid:…`); derived from keys if unset | — |
| `HOLDER_KEY` | Holder Zetrix address or encoded pubkey (informational) | — |
| `HOLDER_PRIVATE_KEY` | Holder Ed25519 private key | — |
| `HOLDER_DID` | Holder DID (`did:zid:…`); derived from keys if unset | — |
| `DEFAULT_TEMPLATE_ID` | Default template id used when a call omits `templateId` | — |
| `TDS_CONTRACT_ADDRESS` | Template Data Store contract address | — |
| `RCL_CONTRACT_ADDRESS` | Revocation Contract List address | — |
| `ZETRIX_NODE_BASE_URL` | Custom node RPC URL (overrides network default) | — |
| `ZETRIX_ZID_RESOLVER_URL` | Custom ZID resolver URL (overrides network default) | — |
| `ZETRIX_VC_DOWNLOAD_DIR` | Default directory for saved VC `.json` files (supports `~`) | CWD |

### Secure Credentials (Recommended)

By setting keys as environment variables, the LLM never needs to see or handle the raw secrets. The server uses them silently; users can refer to the holder/issuer as "me" without mentioning keys.

```json
{
  "mcpServers": {
    "zetrix-vc": {
      "command": "npx",
      "args": ["-y", "zetrix-vc-mcp-server"],
      "env": {
        "ZETRIX_VC_NETWORK": "uat",
        "AWS_GATEWAY_API_KEY": "…",
        "BAAS_API_KEY": "…",
        "ISSUER_PRIVATE_KEY": "…",
        "HOLDER_PRIVATE_KEY": "…",
        "DEFAULT_TEMPLATE_ID": "did:zid:…",
        "TDS_CONTRACT_ADDRESS": "ZTX3…"
      }
    }
  }
}
```

> **Note:** Every credential can also be passed per-call via tool arguments (`issuerPrivateKey`, `holderPublicKey`, etc.). Explicit arguments always override env values. Addresses like `ZTX3…` cannot be used as DIDs — the tool will reject them and ask for the DID / public key / private key instead.

### Claude Code (CLI)

Add the MCP server directly from the command line:

**UAT (sandbox):**
```bash
claude mcp add zetrix-vc-uat -s user -- npx -y zetrix-vc-mcp-server \
  -e ZETRIX_VC_NETWORK=uat \
  -e AWS_GATEWAY_API_KEY=<aws-key> \
  -e BAAS_API_KEY=<baas-key> \
  -e ISSUER_PRIVATE_KEY=<issuer-priv> \
  -e HOLDER_PRIVATE_KEY=<holder-priv> \
  -e DEFAULT_TEMPLATE_ID=<did:zid:…> \
  -e TDS_CONTRACT_ADDRESS=<ZTX3…>
```

**Prod:**
```bash
claude mcp add zetrix-vc -s user -- npx -y zetrix-vc-mcp-server \
  -e ZETRIX_VC_NETWORK=prod \
  -e AWS_GATEWAY_API_KEY=<aws-key> \
  -e BAAS_API_KEY=<baas-key> \
  -e ISSUER_PRIVATE_KEY=<issuer-priv> \
  -e HOLDER_PRIVATE_KEY=<holder-priv>
```

### Claude Desktop

Edit your Claude Desktop configuration file:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

**UAT (sandbox):**
```json
{
  "mcpServers": {
    "zetrix-vc-uat": {
      "command": "npx",
      "args": ["-y", "zetrix-vc-mcp-server"],
      "env": {
        "ZETRIX_VC_NETWORK": "uat",
        "AWS_GATEWAY_API_KEY": "<aws-key>",
        "BAAS_API_KEY": "<baas-key>",
        "ISSUER_PRIVATE_KEY": "<issuer-priv>",
        "HOLDER_PRIVATE_KEY": "<holder-priv>",
        "DEFAULT_TEMPLATE_ID": "did:zid:…",
        "TDS_CONTRACT_ADDRESS": "ZTX3…"
      }
    }
  }
}
```

**Prod:**
```json
{
  "mcpServers": {
    "zetrix-vc": {
      "command": "npx",
      "args": ["-y", "zetrix-vc-mcp-server"],
      "env": {
        "ZETRIX_VC_NETWORK": "prod",
        "AWS_GATEWAY_API_KEY": "<aws-key>",
        "BAAS_API_KEY": "<baas-key>",
        "ISSUER_PRIVATE_KEY": "<issuer-priv>",
        "HOLDER_PRIVATE_KEY": "<holder-priv>"
      }
    }
  }
}
```

**Both networks:**
```json
{
  "mcpServers": {
    "zetrix-vc-uat":  { "command": "npx", "args": ["-y", "zetrix-vc-mcp-server"], "env": { "ZETRIX_VC_NETWORK": "uat",  "…": "…" } },
    "zetrix-vc-prod": { "command": "npx", "args": ["-y", "zetrix-vc-mcp-server"], "env": { "ZETRIX_VC_NETWORK": "prod", "…": "…" } }
  }
}
```

After saving, restart Claude Desktop for changes to take effect. See ready-made templates in [`configs/`](configs/).

### HTTP Transport (API Server)

Run the MCP server as an HTTP API using the Streamable HTTP transport — useful for remote MCP clients or shared team deployments.

**Start the server:**
```bash
ZETRIX_VC_TRANSPORT=http ZETRIX_VC_PORT=3000 \
  ZETRIX_VC_NETWORK=uat \
  AWS_GATEWAY_API_KEY=<aws-key> \
  BAAS_API_KEY=<baas-key> \
  ISSUER_PRIVATE_KEY=<issuer-priv> \
  HOLDER_PRIVATE_KEY=<holder-priv> \
  npx zetrix-vc-mcp-server
```

**Endpoints:**

| Endpoint | Method | Description |
|---|---|---|
| `/mcp` | POST | MCP protocol endpoint (Streamable HTTP, session-aware) |
| `/health` | GET | Health check — returns `{ status, version, network, baseUrl, activeSessions }` |

**Connect from an MCP client:**
```json
{
  "mcpServers": {
    "zetrix-vc": {
      "type": "http",
      "url": "http://localhost:3000/mcp"
    }
  }
}
```

> ⚠️ The `/mcp` endpoint has no built-in authentication. Do not expose it on the public internet without a reverse proxy (nginx/Caddy) terminating TLS and enforcing auth. The BaaS / AWS keys in env are used for outbound calls only.

**Server logs:** go to stderr. Run foreground to watch, or redirect:

```bash
# Foreground
ZETRIX_VC_TRANSPORT=http ZETRIX_VC_PORT=3000 npx zetrix-vc-mcp-server

# Background with logs
ZETRIX_VC_TRANSPORT=http ZETRIX_VC_PORT=3000 npx zetrix-vc-mcp-server 2> server.log &
tail -f server.log
```

## End-to-End Example

Once configured, simply ask the LLM to do what you want — the agent discovers required fields via the tool itself and asks only for what it needs.

```
You:    apply VC for me

Agent:  I need your Full Name, IC Number, and MyDigitalID Expiry Date.

You:    Ahmad bin Abdullah, 900101-01-1234, 2030-01-01

Agent:  Done. Your VC has been issued. Saved to ~/mykad-a7fb32898f6a.json.
        (VC id: did:zid:a7fb32898f6ab6b55e40af533745972e10a276701ac96a463693ce5034ea5e1d)
```

Behind the scenes:
1. Agent calls the issuance tool with no arguments → tool returns the required template fields.
2. Agent asks user for those specific fields.
3. Agent calls again with the answers → tool runs apply → issue → download → writes the VC file.
4. `validUntil` defaults to +1 year unless the user specifies otherwise.

## Development

### Project Structure

```
zetrix-vc-mcp-server/
├── src/
│   ├── index.ts                # MCP server (20 tool definitions + handlers)
│   ├── zetrix-vc-client.ts     # BaaS HTTP client (/cred/v1/*)
│   ├── zetrix-vc-signer.ts     # Ed25519 signing (sign / signHex / DID derivation)
│   ├── zetrix-node-client.ts   # Zetrix public node RPC (template lookup)
│   └── zetrix-zid-resolver.ts  # DID document resolver
├── configs/
│   ├── mcp-config-uat.json     # Claude Desktop template for UAT
│   └── mcp-config-prod.json    # Claude Desktop template for prod
├── docs/
│   └── TEST_SUITE.md           # Live UAT test suite (31 test cases)
└── dist/                       # Compiled output (gitignored)
```

### Build

```bash
npm install
npm run build
```

### Run from source

```bash
npm start                 # stdio transport
npm run start:http        # HTTP transport on port 3000
```

### Test

See [`docs/TEST_SUITE.md`](docs/TEST_SUITE.md) for the full test suite and live-verified results against the UAT BaaS.

## License

MIT
