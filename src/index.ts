#!/usr/bin/env node

// Redirect console.log to stderr to prevent library debug output from
// corrupting the MCP stdio protocol on stdout.
console.log = console.error;

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { createServer, IncomingMessage, ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";

import {
  ZetrixVcClient,
  ZetrixVcNetwork,
  ZETRIX_VC_BASE_URLS,
  TemplateMetadataDto,
  RangeProofDto,
  VerifiableCredential,
  VerifiablePresentation,
} from "./zetrix-vc-client.js";
import { ZetrixVcSigner, stableStringify } from "./zetrix-vc-signer.js";

// -------------------------------------------------------------------------
// Configuration
// -------------------------------------------------------------------------

const MCP_VERSION = "1.0.0";

const ZETRIX_VC_NETWORK = (process.env.ZETRIX_VC_NETWORK || "uat") as ZetrixVcNetwork;
const ZETRIX_VC_BASE_URL = process.env.ZETRIX_VC_BASE_URL;
const ZETRIX_VC_TRANSPORT = process.env.ZETRIX_VC_TRANSPORT || "stdio";
const ZETRIX_VC_PORT = parseInt(process.env.ZETRIX_VC_PORT || "3000", 10);

const AWS_GATEWAY_API_KEY = process.env.AWS_GATEWAY_API_KEY;
const BAAS_API_KEY = process.env.BAAS_API_KEY;

const ISSUER_KEY = process.env.ISSUER_KEY;
const ISSUER_PRIVATE_KEY = process.env.ISSUER_PRIVATE_KEY;
const HOLDER_KEY = process.env.HOLDER_KEY;
const HOLDER_PRIVATE_KEY = process.env.HOLDER_PRIVATE_KEY;

const vcClient = new ZetrixVcClient({
  network: ZETRIX_VC_NETWORK,
  baseUrl: ZETRIX_VC_BASE_URL,
  awsApiKey: AWS_GATEWAY_API_KEY,
  baasApiKey: BAAS_API_KEY,
});

const signer = new ZetrixVcSigner();

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

function requireEnv(value: string | undefined, name: string, arg?: string): string {
  const resolved = arg ?? value;
  if (!resolved) {
    throw new Error(
      `Missing ${name}. Provide it as a tool argument or set the ${name} environment variable.`
    );
  }
  return resolved;
}

function toTextResult(payload: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text: typeof payload === "string" ? payload : JSON.stringify(payload, null, 2),
      },
    ],
  };
}

function errorResult(err: unknown) {
  const message = err instanceof Error ? err.message : String(err);
  return {
    content: [{ type: "text" as const, text: `Error: ${message}` }],
    isError: true,
  };
}

// -------------------------------------------------------------------------
// Tool registry
// -------------------------------------------------------------------------

const tools: Tool[] = [
  {
    name: "zetrix_vc_version",
    description:
      "Get the current version, network (uat/prod) and effective base URL of the Zetrix VC MCP server.",
    inputSchema: { type: "object", properties: {}, required: [] },
  },

  // --------------------- VC: Apply (holder) ---------------------
  {
    name: "zetrix_vc_apply",
    description:
      "Holder applies for a Verifiable Credential from an issuer. Signs the canonicalised request payload with the holder's Ed25519 private key. " +
      "The holder's public key + signature are included so the issuer can verify the application. " +
      "If `holderPrivateKey` / `holderPublicKey` are omitted, HOLDER_PRIVATE_KEY / HOLDER_KEY from the environment are used. " +
      "Maps to POST /v1/vc/apply.",
    inputSchema: {
      type: "object",
      properties: {
        data: {
          type: "array",
          description:
            "List of TemplateMetadataDto — the VC template(s) + claim metadata to apply for.",
          items: {
            type: "object",
            properties: {
              templateId: { type: "string", description: "VC template identifier" },
              passDesignId: { type: "string", description: "Pass design identifier (optional)" },
              metadata: {
                type: "object",
                description: "Key/value claims that populate the VC",
                additionalProperties: true,
              },
              tds: { type: "string", description: "Template Data Store reference (optional)" },
            },
            required: ["templateId", "metadata"],
          },
        },
        holderPrivateKey: {
          type: "string",
          description:
            "Holder Ed25519 private key (56 chars). Defaults to HOLDER_PRIVATE_KEY env var.",
        },
        holderPublicKey: {
          type: "string",
          description:
            "Holder Ed25519 public key. If omitted, derived from the private key. Defaults to HOLDER_KEY env var.",
        },
      },
      required: ["data"],
    },
  },

  // --------------------- VC: Issue (issuer) ---------------------
  {
    name: "zetrix_vc_issue",
    description:
      "Issuer issues a Verifiable Credential directly to a holder DID in a single call (create + sign + submit). " +
      "If `issuerPrivateKey` is omitted, ISSUER_PRIVATE_KEY from the environment is used. " +
      "Maps to POST /v1/vc/issue.",
    inputSchema: {
      type: "object",
      properties: {
        holderDid: {
          type: "string",
          description: "Holder DID / ZID that will receive the VC (e.g. did:zid:ztx...).",
        },
        data: {
          type: "array",
          description: "List of TemplateMetadataDto — template(s) + claim metadata for the VC.",
          items: {
            type: "object",
            properties: {
              templateId: { type: "string" },
              passDesignId: { type: "string" },
              metadata: { type: "object", additionalProperties: true },
              tds: { type: "string" },
            },
            required: ["templateId", "metadata"],
          },
        },
        issuanceDate: {
          type: "string",
          description: "ISO-8601 issuance date (optional).",
        },
        expirationDate: {
          type: "string",
          description: "ISO-8601 expiration date (optional).",
        },
        validFrom: {
          type: "string",
          description: "ISO-8601 validity start (optional).",
        },
        validUntil: {
          type: "string",
          description: "ISO-8601 validity end (optional).",
        },
        keyExpiry: {
          type: "number",
          description: "Key expiry (default 0).",
        },
        issuerPrivateKey: {
          type: "string",
          description:
            "Issuer Ed25519 private key (56 chars). Defaults to ISSUER_PRIVATE_KEY env var.",
        },
      },
      required: ["holderDid", "data"],
    },
  },

  // --------------------- VC: Download (holder) ---------------------
  {
    name: "zetrix_vc_download",
    description:
      "Holder downloads an issued VC. The `vcId` is signed with the holder's Ed25519 private key to prove ownership. " +
      "If `holderPrivateKey` is omitted, HOLDER_PRIVATE_KEY from the environment is used. " +
      "Set `isIssuer: true` when the issuer (not the holder) is downloading. " +
      "Maps to POST /v1/vc/download.",
    inputSchema: {
      type: "object",
      properties: {
        vcId: { type: "string", description: "Identifier of the VC to download." },
        holderPrivateKey: {
          type: "string",
          description:
            "Holder (or issuer, when `isIssuer=true`) Ed25519 private key used to sign `vcId`. " +
            "Defaults to HOLDER_PRIVATE_KEY env var.",
        },
        signVcId: {
          type: "string",
          description:
            "Pre-computed signature over `vcId`. If omitted, the server will sign `vcId` using `holderPrivateKey`.",
        },
        isIssuer: {
          type: "boolean",
          description: "Set to true when the issuer is downloading (default false).",
        },
      },
      required: ["vcId"],
    },
  },

  // --------------------- VP: Create (holder) ---------------------
  {
    name: "zetrix_vp_create",
    description:
      "Holder creates a Verifiable Presentation blob from a VC, selecting which attributes to reveal. " +
      "Returns `blobId` and `blob` — the canonicalised payload the holder must sign. " +
      "Maps to POST /v1/vp/create.",
    inputSchema: {
      type: "object",
      properties: {
        vc: {
          type: "object",
          description: "The VerifiableCredential to present (as returned by issue/download).",
          additionalProperties: true,
        },
        revealAttribute: {
          type: "array",
          description: "Attribute names to selectively disclose (BBS+).",
          items: { type: "string" },
        },
        rangeProof: {
          type: "object",
          description: "Range-proof configuration (e.g. age > 18).",
          additionalProperties: true,
        },
        bbsPublicKey: {
          type: "string",
          description: "Holder BBS+ public key (required for selective disclosure).",
        },
        ed25519PubKey: {
          type: "string",
          description:
            "Holder Ed25519 public key. If omitted, defaults to HOLDER_KEY env var (or derived from HOLDER_PRIVATE_KEY).",
        },
      },
      required: ["vc"],
    },
  },

  // --------------------- VP: Submit (holder) ---------------------
  {
    name: "zetrix_vp_submit",
    description:
      "Holder returns the signed VP blob to the server, which assembles the final VerifiablePresentation. " +
      "If `ed25519SignData` is omitted, this tool signs `blob` with `holderPrivateKey` (or HOLDER_PRIVATE_KEY env var). " +
      "Maps to POST /v1/vp/submit.",
    inputSchema: {
      type: "object",
      properties: {
        blobId: { type: "string", description: "Id returned from zetrix_vp_create." },
        blob: {
          type: "string",
          description:
            "Canonicalised VP payload returned from zetrix_vp_create — required if `ed25519SignData` is not supplied so the tool can sign it.",
        },
        ed25519SignData: {
          type: "string",
          description:
            "Holder Ed25519 signature over `blob`. If omitted, the tool signs `blob` with `holderPrivateKey`.",
        },
        ed25519PubKey: {
          type: "string",
          description:
            "Holder Ed25519 public key. Defaults to HOLDER_KEY env var (or derived from HOLDER_PRIVATE_KEY).",
        },
        holderPrivateKey: {
          type: "string",
          description:
            "Holder Ed25519 private key used to sign `blob` when `ed25519SignData` is not provided. Defaults to HOLDER_PRIVATE_KEY env var.",
        },
      },
      required: ["blobId"],
    },
  },

  // --------------------- VP: Create + Submit (holder) ---------------------
  {
    name: "zetrix_vp_present",
    description:
      "Convenience flow for the holder: create a VP blob, sign it with the holder's Ed25519 private key, " +
      "submit it, and (optionally) cache it to get a share uuid. " +
      "If `holderPrivateKey` / `ed25519PubKey` are omitted, HOLDER_PRIVATE_KEY / HOLDER_KEY from the environment are used. " +
      "Combines POST /v1/vp/create → sign → POST /v1/vp/submit → POST /v1/vp/cache (optional).",
    inputSchema: {
      type: "object",
      properties: {
        vc: {
          type: "object",
          description: "The VerifiableCredential to present.",
          additionalProperties: true,
        },
        revealAttribute: {
          type: "array",
          items: { type: "string" },
          description: "Attribute names to selectively disclose (BBS+).",
        },
        rangeProof: {
          type: "object",
          description: "Range-proof configuration.",
          additionalProperties: true,
        },
        bbsPublicKey: { type: "string" },
        ed25519PubKey: {
          type: "string",
          description:
            "Holder Ed25519 public key. Defaults to HOLDER_KEY env var (or derived from HOLDER_PRIVATE_KEY).",
        },
        holderPrivateKey: {
          type: "string",
          description:
            "Holder Ed25519 private key used to sign the VP blob. Defaults to HOLDER_PRIVATE_KEY env var.",
        },
        cache: {
          type: "boolean",
          description:
            "If true, also caches the signed VP via POST /v1/vp/cache and returns the share uuid. Default false.",
        },
      },
      required: ["vc"],
    },
  },

  // --------------------- VP: Cache (holder) ---------------------
  {
    name: "zetrix_vp_cache",
    description:
      "Holder caches a signed VP on the server and receives a short uuid to share with a verifier. " +
      "Maps to POST /v1/vp/cache.",
    inputSchema: {
      type: "object",
      properties: {
        vp: {
          type: "object",
          description: "Signed VerifiablePresentation to cache.",
          additionalProperties: true,
        },
      },
      required: ["vp"],
    },
  },

  // --------------------- VP: Verify (verifier) ---------------------
  {
    name: "zetrix_vp_verify",
    description:
      "Verifier validates a VerifiablePresentation. Returns isVerified + per-VC disclosed claims. " +
      "Maps to POST /v1/vp/verify.",
    inputSchema: {
      type: "object",
      properties: {
        vp: {
          type: "object",
          description: "Signed VerifiablePresentation to verify.",
          additionalProperties: true,
        },
        ed25519PubKey: {
          type: "string",
          description: "Expected holder Ed25519 public key (optional).",
        },
        bbsPublicKey: {
          type: "string",
          description: "Expected holder BBS+ public key (optional, selective disclosure).",
        },
      },
      required: ["vp"],
    },
  },
];

// -------------------------------------------------------------------------
// Tool handlers
// -------------------------------------------------------------------------

function createMcpServer(): Server {
  const srv = new Server(
    { name: "zetrix-vc-mcp-server", version: MCP_VERSION },
    { capabilities: { tools: {} } }
  );
  registerHandlers(srv);
  return srv;
}

function registerHandlers(server: Server) {
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: rawArgs } = request.params;
    const args = (rawArgs ?? {}) as Record<string, unknown>;

    try {
      switch (name) {
        case "zetrix_vc_version": {
          return toTextResult({
            name: "zetrix-vc-mcp-server",
            version: MCP_VERSION,
            network: ZETRIX_VC_BASE_URL ? "custom" : ZETRIX_VC_NETWORK,
            baseUrl: vcClient.baseUrl,
            defaultBaseUrls: ZETRIX_VC_BASE_URLS,
            auth: {
              awsGatewayApiKey: AWS_GATEWAY_API_KEY ? "set" : "missing",
              baasApiKey: BAAS_API_KEY ? "set" : "missing",
            },
            identities: {
              issuerKey: ISSUER_KEY ? "set" : "missing",
              issuerPrivateKey: ISSUER_PRIVATE_KEY ? "set" : "missing",
              holderKey: HOLDER_KEY ? "set" : "missing",
              holderPrivateKey: HOLDER_PRIVATE_KEY ? "set" : "missing",
            },
          });
        }

        case "zetrix_vc_apply": {
          const data = args.data as TemplateMetadataDto[] | undefined;
          if (!data || !Array.isArray(data) || data.length === 0) {
            throw new Error("`data` must be a non-empty array of TemplateMetadataDto.");
          }
          const holderPrivateKey = requireEnv(
            HOLDER_PRIVATE_KEY,
            "HOLDER_PRIVATE_KEY",
            args.holderPrivateKey as string | undefined
          );
          const holderPublicKey =
            (args.holderPublicKey as string | undefined) ??
            HOLDER_KEY ??
            (await signer.getPublicKey(holderPrivateKey));

          // Sign the canonicalised `data` payload; server re-canonicalises to verify.
          const signPayload = stableStringify({ data });
          const { signData } = await signer.sign(signPayload, holderPrivateKey);

          const resp = await vcClient.applyVc({
            data,
            signData,
            publicKey: holderPublicKey,
          });
          return toTextResult(resp);
        }

        case "zetrix_vc_issue": {
          const holderDid = args.holderDid as string | undefined;
          if (!holderDid) throw new Error("`holderDid` is required.");
          const data = args.data as TemplateMetadataDto[] | undefined;
          if (!data || !Array.isArray(data) || data.length === 0) {
            throw new Error("`data` must be a non-empty array of TemplateMetadataDto.");
          }
          const issuerPrivateKey = requireEnv(
            ISSUER_PRIVATE_KEY,
            "ISSUER_PRIVATE_KEY",
            args.issuerPrivateKey as string | undefined
          );
          const resp = await vcClient.issueVc({
            holderDid,
            data,
            issuerPrivateKey,
            issuanceDate: args.issuanceDate as string | undefined,
            expirationDate: args.expirationDate as string | undefined,
            validFrom: args.validFrom as string | undefined,
            validUntil: args.validUntil as string | undefined,
            keyExpiry: args.keyExpiry as number | undefined,
          });
          return toTextResult(resp);
        }

        case "zetrix_vc_download": {
          const vcId = args.vcId as string | undefined;
          if (!vcId) throw new Error("`vcId` is required.");
          const isIssuer = Boolean(args.isIssuer);

          let signVcId = args.signVcId as string | undefined;
          if (!signVcId) {
            // When the signer isn't supplied, derive it from holder (or issuer) private key.
            const privateKey = requireEnv(
              isIssuer ? ISSUER_PRIVATE_KEY : HOLDER_PRIVATE_KEY,
              isIssuer ? "ISSUER_PRIVATE_KEY" : "HOLDER_PRIVATE_KEY",
              args.holderPrivateKey as string | undefined
            );
            const sig = await signer.sign(vcId, privateKey);
            signVcId = sig.signData;
          }

          const resp = await vcClient.downloadVc({ vcId, signVcId, isIssuer });
          return toTextResult(resp);
        }

        case "zetrix_vp_create": {
          const vc = args.vc as VerifiableCredential | undefined;
          if (!vc) throw new Error("`vc` is required.");

          let ed25519PubKey = args.ed25519PubKey as string | undefined;
          if (!ed25519PubKey) {
            if (HOLDER_KEY) {
              ed25519PubKey = HOLDER_KEY;
            } else if (HOLDER_PRIVATE_KEY) {
              ed25519PubKey = await signer.getPublicKey(HOLDER_PRIVATE_KEY);
            }
          }

          const resp = await vcClient.createVp({
            vc,
            revealAttribute: args.revealAttribute as string[] | undefined,
            rangeProof: args.rangeProof as RangeProofDto | undefined,
            bbsPublicKey: args.bbsPublicKey as string | undefined,
            ed25519PubKey,
          });
          return toTextResult(resp);
        }

        case "zetrix_vp_submit": {
          const blobId = args.blobId as string | undefined;
          if (!blobId) throw new Error("`blobId` is required.");

          let signData = args.ed25519SignData as string | undefined;
          let ed25519PubKey = args.ed25519PubKey as string | undefined;

          if (!signData) {
            const blob = args.blob as string | undefined;
            if (!blob) {
              throw new Error(
                "Either `ed25519SignData` (pre-computed) or `blob` (to sign locally) must be provided."
              );
            }
            const holderPrivateKey = requireEnv(
              HOLDER_PRIVATE_KEY,
              "HOLDER_PRIVATE_KEY",
              args.holderPrivateKey as string | undefined
            );
            const sig = await signer.sign(blob, holderPrivateKey);
            signData = sig.signData;
            if (!ed25519PubKey) ed25519PubKey = HOLDER_KEY ?? sig.publicKey;
          } else if (!ed25519PubKey) {
            if (HOLDER_KEY) ed25519PubKey = HOLDER_KEY;
            else if (HOLDER_PRIVATE_KEY)
              ed25519PubKey = await signer.getPublicKey(HOLDER_PRIVATE_KEY);
          }

          if (!ed25519PubKey) {
            throw new Error(
              "`ed25519PubKey` is required (set HOLDER_KEY env var, pass it as an argument, or supply HOLDER_PRIVATE_KEY)."
            );
          }

          const resp = await vcClient.submitVp({
            blobId,
            ed25519SignData: signData,
            ed25519PubKey,
          });
          return toTextResult(resp);
        }

        case "zetrix_vp_present": {
          const vc = args.vc as VerifiableCredential | undefined;
          if (!vc) throw new Error("`vc` is required.");
          const holderPrivateKey = requireEnv(
            HOLDER_PRIVATE_KEY,
            "HOLDER_PRIVATE_KEY",
            args.holderPrivateKey as string | undefined
          );
          const ed25519PubKey =
            (args.ed25519PubKey as string | undefined) ??
            HOLDER_KEY ??
            (await signer.getPublicKey(holderPrivateKey));

          // 1. Create the VP blob
          const created = await vcClient.createVp({
            vc,
            revealAttribute: args.revealAttribute as string[] | undefined,
            rangeProof: args.rangeProof as RangeProofDto | undefined,
            bbsPublicKey: args.bbsPublicKey as string | undefined,
            ed25519PubKey,
          });

          // 2. Sign the blob with the holder's private key
          const { signData } = await signer.sign(created.blob, holderPrivateKey);

          // 3. Submit the signed blob
          const vp = await vcClient.submitVp({
            blobId: created.blobId,
            ed25519SignData: signData,
            ed25519PubKey,
          });

          // 4. Optionally cache the VP for sharing with a verifier
          let cache: { uuid: string } | undefined;
          if (args.cache === true) {
            cache = await vcClient.cacheVp({ vp });
          }

          return toTextResult({
            blobId: created.blobId,
            vp,
            ...(cache ? { cache } : {}),
          });
        }

        case "zetrix_vp_cache": {
          const vp = args.vp as VerifiablePresentation | undefined;
          if (!vp) throw new Error("`vp` is required.");
          const resp = await vcClient.cacheVp({ vp });
          return toTextResult(resp);
        }

        case "zetrix_vp_verify": {
          const vp = args.vp as VerifiablePresentation | undefined;
          if (!vp) throw new Error("`vp` is required.");
          const resp = await vcClient.verifyVp({
            vp,
            ed25519PubKey: args.ed25519PubKey as string | undefined,
            bbsPublicKey: args.bbsPublicKey as string | undefined,
          });
          return toTextResult(resp);
        }

        default:
          throw new Error(`Unknown tool: ${name}`);
      }
    } catch (err) {
      return errorResult(err);
    }
  });
}

// -------------------------------------------------------------------------
// Transport bootstrap
// -------------------------------------------------------------------------

async function main() {
  if (ZETRIX_VC_TRANSPORT === "http") {
    const sessions = new Map<
      string,
      { server: Server; transport: StreamableHTTPServerTransport }
    >();

    const httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
      const url = new URL(req.url || "/", `http://localhost:${ZETRIX_VC_PORT}`);

      if (url.pathname === "/mcp") {
        const sessionId = req.headers["mcp-session-id"] as string | undefined;

        if (sessionId && sessions.has(sessionId)) {
          const session = sessions.get(sessionId)!;
          await session.transport.handleRequest(req, res);
        } else if (!sessionId && req.method === "POST") {
          const sessionServer = createMcpServer();
          const transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
            onsessioninitialized: (id) => {
              sessions.set(id, { server: sessionServer, transport });
            },
          });
          transport.onclose = () => {
            if (transport.sessionId) sessions.delete(transport.sessionId);
          };
          await sessionServer.connect(transport);
          await transport.handleRequest(req, res);
        } else {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Invalid or missing session ID" }));
        }
      } else if (url.pathname === "/health") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            status: "ok",
            version: MCP_VERSION,
            network: ZETRIX_VC_BASE_URL ? "custom" : ZETRIX_VC_NETWORK,
            baseUrl: vcClient.baseUrl,
            activeSessions: sessions.size,
          })
        );
      } else {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            error: "Not found. Use /mcp for MCP protocol or /health for status.",
          })
        );
      }
    });

    httpServer.listen(ZETRIX_VC_PORT, () => {
      console.error(
        `Zetrix VC MCP Server running on http://localhost:${ZETRIX_VC_PORT}/mcp (network=${ZETRIX_VC_NETWORK}, baseUrl=${vcClient.baseUrl})`
      );
    });
  } else {
    const server = createMcpServer();
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error(
      `Zetrix VC MCP Server running on stdio (network=${ZETRIX_VC_NETWORK}, baseUrl=${vcClient.baseUrl})`
    );
  }
}

main().catch((error) => {
  console.error("Fatal error in main():", error);
  process.exit(1);
});
