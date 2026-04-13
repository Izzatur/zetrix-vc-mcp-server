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
import {
  ZetrixVcSigner,
  stableStringify,
  deriveDidFromEncodedPublicKey,
} from "./zetrix-vc-signer.js";
import {
  ZetrixNodeClient,
  ZETRIX_NODE_BASE_URLS,
} from "./zetrix-node-client.js";
import {
  ZetrixZidResolver,
  ZETRIX_ZID_RESOLVER_BASE_URLS,
} from "./zetrix-zid-resolver.js";

// -------------------------------------------------------------------------
// Configuration
// -------------------------------------------------------------------------

const MCP_VERSION = "1.0.0";

const RAW_NETWORK = (process.env.ZETRIX_VC_NETWORK || "uat").trim().toLowerCase();
if (RAW_NETWORK !== "uat" && RAW_NETWORK !== "prod") {
  throw new Error(
    `Invalid ZETRIX_VC_NETWORK="${RAW_NETWORK}". Must be "uat" or "prod". ` +
      `(Note: this server is for the Zetrix BaaS — use ZETRIX_VC_NETWORK=uat for sandbox, prod for production.)`
  );
}
const ZETRIX_VC_NETWORK: ZetrixVcNetwork = RAW_NETWORK;
const ZETRIX_VC_BASE_URL = process.env.ZETRIX_VC_BASE_URL;
const ZETRIX_VC_TRANSPORT = process.env.ZETRIX_VC_TRANSPORT || "stdio";
const ZETRIX_VC_PORT = parseInt(process.env.ZETRIX_VC_PORT || "3000", 10);

const AWS_GATEWAY_API_KEY = process.env.AWS_GATEWAY_API_KEY;
const BAAS_API_KEY = process.env.BAAS_API_KEY;

const ISSUER_KEY = process.env.ISSUER_KEY;
const ISSUER_PRIVATE_KEY = process.env.ISSUER_PRIVATE_KEY;
const ISSUER_DID = process.env.ISSUER_DID;
const HOLDER_KEY = process.env.HOLDER_KEY;
const HOLDER_PRIVATE_KEY = process.env.HOLDER_PRIVATE_KEY;
const HOLDER_DID = process.env.HOLDER_DID;

const DEFAULT_TEMPLATE_ID = process.env.DEFAULT_TEMPLATE_ID;

// Contract addresses — on-chain stores for credential templates and revocation state.
const TDS_CONTRACT_ADDRESS = process.env.TDS_CONTRACT_ADDRESS;
const RCL_CONTRACT_ADDRESS = process.env.RCL_CONTRACT_ADDRESS;

// Zetrix public node RPC — used to resolve template / RCL metadata on-chain.
const ZETRIX_NODE_BASE_URL = process.env.ZETRIX_NODE_BASE_URL;

// Zetrix ZID (DID) resolver — resolves did:zid:... to its DID document.
const ZETRIX_ZID_RESOLVER_URL = process.env.ZETRIX_ZID_RESOLVER_URL;

const vcClient = new ZetrixVcClient({
  network: ZETRIX_VC_NETWORK,
  baseUrl: ZETRIX_VC_BASE_URL,
  awsApiKey: AWS_GATEWAY_API_KEY,
  baasApiKey: BAAS_API_KEY,
});

const nodeClient = new ZetrixNodeClient({
  network: ZETRIX_VC_NETWORK,
  baseUrl: ZETRIX_NODE_BASE_URL,
});

const zidResolver = new ZetrixZidResolver({
  network: ZETRIX_VC_NETWORK,
  baseUrl: ZETRIX_ZID_RESOLVER_URL,
  awsApiKey: AWS_GATEWAY_API_KEY,
  baasApiKey: BAAS_API_KEY,
});

const signer = new ZetrixVcSigner();

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

/**
 * Return the first non-empty string from the given candidates, trimmed.
 *
 * Used to coalesce a tool argument with an environment fallback. Explicitly
 * passed arguments ALWAYS win when they are non-empty — even if the matching
 * env var is also set — so the caller can override the env per call. Empty
 * or whitespace-only strings are treated as "not set" so that placeholder
 * values in config templates (e.g. `HOLDER_PRIVATE_KEY=""`) don't block
 * resolution. The return value is trimmed so that stray `\r` or surrounding
 * whitespace (common from Windows files / EnvironmentFile) doesn't leak into
 * signing / URL construction.
 */
function pick(...candidates: Array<string | undefined | null>): string | undefined {
  for (const v of candidates) {
    if (typeof v === "string") {
      const trimmed = v.trim();
      if (trimmed !== "") return trimmed;
    }
  }
  return undefined;
}

/**
 * Detect whether `candidate` looks like a Zetrix-encoded Ed25519 public key
 * (76 hex chars starting with `b001`). If yes, return it trimmed+lowercased;
 * otherwise return undefined so callers know to derive the pubkey from the
 * private key instead. Handles the common user mistake of putting an address
 * (`ZTX3...`) in HOLDER_KEY/ISSUER_KEY — those aren't usable as API pubkeys.
 */
function asEncodedEd25519PubKey(candidate: string | undefined): string | undefined {
  const picked = pick(candidate);
  if (!picked) return undefined;
  const lower = picked.toLowerCase();
  if (lower.length === 76 && lower.startsWith("b001") && /^[0-9a-f]+$/.test(lower)) {
    return lower;
  }
  return undefined;
}

/**
 * Resolve the encoded Ed25519 public key (`b001…` form) the BaaS API expects
 * in `publicKey` / `ed25519PubKey` fields. Priority: explicit arg → env var
 * (only when it's in the right format) → derive from the private key.
 *
 * `HOLDER_KEY` / `ISSUER_KEY` env vars may be addresses (`ZTX3…`) instead of
 * encoded pubkeys — we detect that and fall through to key derivation so the
 * API gets the correct format regardless of what the user put in those vars.
 */
async function resolveEncodedPublicKey(
  argCandidate: string | undefined,
  envCandidate: string | undefined,
  privateKeyForDerivation: string
): Promise<string> {
  const arg = asEncodedEd25519PubKey(argCandidate);
  if (arg) return arg;
  const env = asEncodedEd25519PubKey(envCandidate);
  if (env) return env;
  return signer.getPublicKey(privateKeyForDerivation);
}

/**
 * Resolve a value from candidates (arg first, env last). Throws a helpful
 * error when none of the candidates has a non-empty value.
 */
function requireEnv(value: string | undefined, name: string, arg?: string): string {
  const resolved = pick(arg, value);
  if (!resolved) {
    throw new Error(
      `Missing ${name}. Provide it as a tool argument or set the ${name} environment variable.`
    );
  }
  return resolved;
}

/**
 * Generate (i.e. derive locally) a Zetrix DID for the holder or issuer role
 * from the strongest available source:
 *   1. explicit `didArg` argument                     (tool arg override)
 *   2. explicit `didEnv` environment value            (HOLDER_DID / ISSUER_DID)
 *   3. derive from an explicit public-key arg         (holderPublicKey / …)
 *   4. derive from the corresponding public-key env   (HOLDER_KEY / ISSUER_KEY)
 *   5. derive from an explicit private-key arg        (holderPrivateKey / …)
 *   6. derive from the corresponding private-key env  (HOLDER_PRIVATE_KEY / ISSUER_PRIVATE_KEY)
 *
 * "Generate" rather than "resolve" — in DID terminology, resolving a DID means
 * fetching its DID document from a DID resolver service (see the
 * zetrix_vc_resolve_did tool for that). This function just constructs the DID
 * string from local key material.
 *
 * Throws a descriptive error when none of the above yields a value.
 */
async function generateDid(params: {
  role: "holder" | "issuer";
  didArg?: string;
  didEnv?: string;
  publicKeyArg?: string;
  publicKeyEnv?: string;
  privateKeyArg?: string;
  privateKeyEnv?: string;
}): Promise<string> {
  const explicit = pick(params.didArg, params.didEnv);
  if (explicit) return explicit;

  // Only encoded pubkeys (b001…) are usable for DID derivation. HOLDER_KEY /
  // ISSUER_KEY env values that are addresses (ZTX3…) are skipped so we fall
  // through to deriving from the private key.
  const pub =
    asEncodedEd25519PubKey(params.publicKeyArg) ??
    asEncodedEd25519PubKey(params.publicKeyEnv);
  if (pub) return deriveDidFromEncodedPublicKey(pub);

  const priv = pick(params.privateKeyArg, params.privateKeyEnv);
  if (priv) {
    const encoded = await signer.getPublicKey(priv);
    return deriveDidFromEncodedPublicKey(encoded);
  }

  const ROLE = params.role === "holder" ? "HOLDER" : "ISSUER";
  throw new Error(
    `Missing ${params.role}Did. Provide ${params.role}Did (or ${ROLE}_DID env), ` +
      `or supply ${params.role}PublicKey (76-char b001… form) / ${params.role}PrivateKey ` +
      `(or ${ROLE}_PRIVATE_KEY env) so the DID can be derived as did:zid:<rawPubKey>.`
  );
}

/**
 * Fill in `templateId` on each TemplateMetadataDto from DEFAULT_TEMPLATE_ID
 * when the caller didn't supply one. If no default is set and an item is
 * missing `templateId`, throw.
 */
function applyDefaultTemplateId(data: TemplateMetadataDto[]): TemplateMetadataDto[] {
  const fallback = pick(DEFAULT_TEMPLATE_ID);
  return data.map((item, idx) => {
    const itemTemplateId = pick(
      typeof item?.templateId === "string" ? item.templateId : undefined
    );
    if (itemTemplateId) return { ...item, templateId: itemTemplateId };
    if (!fallback) {
      throw new Error(
        `data[${idx}].templateId is missing and DEFAULT_TEMPLATE_ID is not set. ` +
          `Either include a templateId per item or configure DEFAULT_TEMPLATE_ID in the environment.`
      );
    }
    return { ...item, templateId: fallback };
  });
}

/**
 * A single attribute spec entry inside a TDS template's `applyFormat`.
 * Shape (observed on-chain):
 *   { attribute: "Name", format: "String", key: "name", mandatory: 1, type: 3 }
 */
interface TemplateAttributeSpec {
  attribute: string;
  format: string;
  key: string;
  mandatory: number | boolean;
  type?: number;
}

interface TemplateInfo {
  templateName?: string;
  applyFormat: TemplateAttributeSpec[];
}

/**
 * Extract the `applyFormat` schema from a template record pulled from the TDS
 * contract. Returns `null` when the record has no applyFormat (e.g. legacy
 * templates without validation metadata) so validation becomes best-effort.
 */
function extractTemplateInfo(templateValue: unknown): TemplateInfo | null {
  if (!templateValue || typeof templateValue !== "object") return null;
  const v = templateValue as Record<string, unknown>;
  const applyFormat = v.applyFormat;
  if (!Array.isArray(applyFormat)) return null;
  const specs: TemplateAttributeSpec[] = applyFormat
    .filter((s): s is Record<string, unknown> => !!s && typeof s === "object")
    .map((s) => ({
      attribute: String(s.attribute ?? ""),
      format: String(s.format ?? ""),
      key: String(s.key ?? ""),
      mandatory: (s.mandatory as number | boolean) ?? 0,
      type: typeof s.type === "number" ? s.type : undefined,
    }))
    .filter((s) => s.key);
  return {
    templateName: typeof v.templateName === "string" ? v.templateName : undefined,
    applyFormat: specs,
  };
}

/**
 * Check a metadata object against a template's applyFormat and return the list
 * of mandatory attributes that are missing or empty. Mandatory is truthy when
 * `mandatory === 1 || mandatory === true`.
 */
function findMissingRequiredAttributes(
  metadata: Record<string, unknown>,
  info: TemplateInfo
): TemplateAttributeSpec[] {
  return info.applyFormat.filter((spec) => {
    const isMandatory = spec.mandatory === 1 || spec.mandatory === true;
    if (!isMandatory) return false;
    const value = metadata[spec.key];
    return value === undefined || value === null || value === "";
  });
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

  // --------------------- Utility: Derive DID ---------------------
  {
    name: "zetrix_vc_generate_did",
    description:
      "Derive the Zetrix DID (`did:zid:<rawPubKey>`) from an Ed25519 private key, Zetrix-encoded public key, or already-known raw public key. " +
      "Handy for discovering 'what is my DID' without hitting the BaaS. Resolution order for the input: " +
      "explicit `privateKey` → explicit `publicKey` → explicit `rawPublicKey` → HOLDER_PRIVATE_KEY env → HOLDER_KEY env → ISSUER_PRIVATE_KEY env → ISSUER_KEY env.",
    inputSchema: {
      type: "object",
      properties: {
        privateKey: {
          type: "string",
          description: "Zetrix Ed25519 private key (56-char `priv…` form).",
        },
        publicKey: {
          type: "string",
          description: "Zetrix-encoded Ed25519 public key (76-char `b001…` form).",
        },
        rawPublicKey: {
          type: "string",
          description: "Already-raw Ed25519 public key hex (64 chars).",
        },
        role: {
          type: "string",
          enum: ["holder", "issuer"],
          description:
            "When no key args are provided, which env role to fall back to: 'holder' (HOLDER_*) or 'issuer' (ISSUER_*). Default 'holder'.",
        },
      },
      required: [],
    },
  },

  // --------------------- DID: Resolve ---------------------
  {
    name: "zetrix_vc_resolve_did",
    description:
      "Resolve a Zetrix DID (did:zid:...) to its DID document using the Zetrix ZID resolver. " +
      "Calls GET <resolver>/1.0/identifiers/<did>. The response follows the W3C DID Resolution spec " +
      "— it contains `didDocument` (with verificationMethod, service endpoints, and permissions) " +
      "plus `didResolutionMetadata` / `didDocumentMetadata`. " +
      "Use this to inspect what a DID is authorised to do — e.g. which verification methods it has " +
      "registered and which services / permissions it exposes on-chain. " +
      "Resolver URL is selected from ZETRIX_VC_NETWORK (uat → zid-resolver-sandbox.zetrix.com, " +
      "prod → zid-resolver.zetrix.com) or the ZETRIX_ZID_RESOLVER_URL override. " +
      "When `did` is omitted the holder's DID (derived from holder keys / HOLDER_DID) is used.",
    inputSchema: {
      type: "object",
      properties: {
        did: {
          type: "string",
          description:
            "The DID to resolve (e.g. did:zid:acfdbaa6…). If omitted, the holder's DID is generated from local keys (HOLDER_DID / HOLDER_KEY / HOLDER_PRIVATE_KEY).",
        },
      },
      required: [],
    },
  },

  // --------------------- VC: Template lookup ---------------------
  {
    name: "zetrix_vc_get_template_detail",
    description:
      "Fetch a VC template record from the on-chain Template Data Store (TDS). " +
      "Calls the Zetrix node RPC: GET /getAccountMetaData?address=<TDS_CONTRACT_ADDRESS>&key=template__<templateId>. " +
      "If `templateId` is not provided, DEFAULT_TEMPLATE_ID from the environment is used. " +
      "If `tdsContractAddress` is not provided, TDS_CONTRACT_ADDRESS from the environment is used. " +
      "The node base URL is selected from ZETRIX_VC_NETWORK (uat → test-node.zetrix.com, prod → node.zetrix.com) " +
      "or the explicit ZETRIX_NODE_BASE_URL override. Returns the raw metadata value plus a parsed JSON form when possible.",
    inputSchema: {
      type: "object",
      properties: {
        templateId: {
          type: "string",
          description:
            "Template id (e.g. did:zid:...). Defaults to DEFAULT_TEMPLATE_ID env var when omitted.",
        },
        tdsContractAddress: {
          type: "string",
          description:
            "TDS contract address to query. Defaults to TDS_CONTRACT_ADDRESS env var when omitted.",
        },
      },
      required: [],
    },
  },

  // --------------------- VC: Full flow (apply + issue + download) ---------------------
  {
    name: "zetrix_vc_request_credential",
    description:
      "High-level tool to issue a Verifiable Credential end-to-end in one call. Runs the full flow: " +
      "(1) fetches the template record from the on-chain TDS contract to learn the required attributes, " +
      "(2) validates `metadata` contains every mandatory attribute — if any are missing, returns an error " +
      "listing them so the agent can ask the user for the values before retrying, " +
      "(3) holder applies for the VC (POST /cred/v1/vc/apply), " +
      "(4) issuer issues the VC to `holderDid` (POST /cred/v1/vc/issue), " +
      "(5) holder downloads the final signed VC (POST /cred/v1/vc/download), and " +
      "(6) returns the W3C JSON-LD VerifiableCredential. " +
      "Use this when the user asks 'issue me a VC' / 'give me a credential' — it hides the multi-step " +
      "orchestration. Env fallbacks: templateId → DEFAULT_TEMPLATE_ID, holderDid → HOLDER_DID, " +
      "tdsContractAddress → TDS_CONTRACT_ADDRESS, keys → HOLDER_/ISSUER_ env vars. Explicit args override env.",
    inputSchema: {
      type: "object",
      properties: {
        metadata: {
          type: "object",
          description:
            "Key/value claims that populate the VC. Keys must match the template's `applyFormat[].key` " +
            "(e.g. `name`, `icNo`, `class`). The tool will fetch the template on-chain and validate that " +
            "every mandatory attribute is present — if any are missing, the error response will list them " +
            "so you can ask the user for the values.",
          additionalProperties: true,
        },
        templateId: {
          type: "string",
          description:
            "Template id (e.g. did:zid:...). Overrides DEFAULT_TEMPLATE_ID env var when provided.",
        },
        holderDid: {
          type: "string",
          description:
            "Holder DID/ZID the VC is issued to (e.g. did:zid:ztx...). Overrides HOLDER_DID env var when provided.",
        },
        tdsContractAddress: {
          type: "string",
          description:
            "TDS contract address for the template lookup. Overrides TDS_CONTRACT_ADDRESS env var when provided.",
        },
        passDesignId: {
          type: "string",
          description: "Optional pass design identifier attached to the credential.",
        },
        issuanceDate: { type: "string", description: "ISO-8601 issuance date (optional)." },
        expirationDate: { type: "string", description: "ISO-8601 expiration date (optional)." },
        validFrom: { type: "string", description: "ISO-8601 validity start (optional)." },
        validUntil: { type: "string", description: "ISO-8601 validity end (optional)." },
        keyExpiry: { type: "number", description: "Key expiry (default 0)." },
        skipTemplateValidation: {
          type: "boolean",
          description:
            "Set to true to skip fetching the template and validating required attributes (useful when the TDS lookup is unavailable). Default false.",
        },
        skipDownload: {
          type: "boolean",
          description:
            "Set to true to return the VC from the issue step and skip the final download call. Default false.",
        },
        holderPrivateKey: {
          type: "string",
          description: "Holder Ed25519 private key. Overrides HOLDER_PRIVATE_KEY env var when provided.",
        },
        holderPublicKey: {
          type: "string",
          description: "Holder Ed25519 public key. Overrides HOLDER_KEY env var when provided; otherwise derived from the private key.",
        },
        issuerPrivateKey: {
          type: "string",
          description: "Issuer Ed25519 private key. Overrides ISSUER_PRIVATE_KEY env var when provided.",
        },
      },
      required: ["metadata"],
    },
  },

  // --------------------- VC: Apply (holder) ---------------------
  {
    name: "zetrix_vc_apply",
    description:
      "Holder applies for a Verifiable Credential from an issuer. Signs the canonicalised request payload with the holder's Ed25519 private key. " +
      "The holder's public key + signature are included so the issuer can verify the application. " +
      "Explicit `holderPrivateKey` / `holderPublicKey` args override HOLDER_PRIVATE_KEY / HOLDER_KEY from the environment. " +
      "Maps to POST /cred/v1/vc/apply.",
    inputSchema: {
      type: "object",
      properties: {
        data: {
          type: "array",
          description:
            "List of TemplateMetadataDto — the VC template(s) + claim metadata to apply for. " +
            "`templateId` may be omitted on any item; DEFAULT_TEMPLATE_ID from the environment will be used as fallback.",
          items: {
            type: "object",
            properties: {
              templateId: {
                type: "string",
                description:
                  "VC template identifier. If omitted, DEFAULT_TEMPLATE_ID env var is used.",
              },
              passDesignId: { type: "string", description: "Pass design identifier (optional)" },
              metadata: {
                type: "object",
                description: "Key/value claims that populate the VC",
                additionalProperties: true,
              },
              tds: { type: "string", description: "Template Data Store reference (optional)" },
            },
            required: ["metadata"],
          },
        },
        holderPrivateKey: {
          type: "string",
          description:
            "Holder Ed25519 private key (56 chars). Overrides HOLDER_PRIVATE_KEY env var when provided.",
        },
        holderPublicKey: {
          type: "string",
          description:
            "Holder Ed25519 public key. Overrides HOLDER_KEY env var when provided; otherwise derived from the private key.",
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
      "Explicit `issuerPrivateKey` arg overrides ISSUER_PRIVATE_KEY from the environment. " +
      "`holderDid` resolution order: explicit arg → HOLDER_DID env → derived from holderPublicKey/HOLDER_KEY → derived from holderPrivateKey/HOLDER_PRIVATE_KEY (did:zid:<rawPubKey>). " +
      "Maps to POST /cred/v1/vc/issue.",
    inputSchema: {
      type: "object",
      properties: {
        holderDid: {
          type: "string",
          description:
            "Holder DID / ZID that will receive the VC (e.g. did:zid:ztx...). " +
            "If omitted, falls back to HOLDER_DID env var or is derived as did:zid:<rawPubKey> from the holder's public or private key.",
        },
        holderPublicKey: {
          type: "string",
          description:
            "Holder Ed25519 public key used to derive holderDid when neither `holderDid` nor HOLDER_DID is set. Overrides HOLDER_KEY env var.",
        },
        holderPrivateKey: {
          type: "string",
          description:
            "Holder Ed25519 private key used to derive holderDid when no DID or public key is available. Overrides HOLDER_PRIVATE_KEY env var.",
        },
        data: {
          type: "array",
          description:
            "List of TemplateMetadataDto — template(s) + claim metadata for the VC. " +
            "`templateId` may be omitted on any item; DEFAULT_TEMPLATE_ID env var is used as fallback.",
          items: {
            type: "object",
            properties: {
              templateId: {
                type: "string",
                description:
                  "VC template identifier. If omitted, DEFAULT_TEMPLATE_ID env var is used.",
              },
              passDesignId: { type: "string" },
              metadata: { type: "object", additionalProperties: true },
              tds: { type: "string" },
            },
            required: ["metadata"],
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
            "Issuer Ed25519 private key (56 chars). Overrides ISSUER_PRIVATE_KEY env var when provided.",
        },
      },
      required: ["data"],
    },
  },

  // --------------------- VC: Download (holder) ---------------------
  {
    name: "zetrix_vc_download",
    description:
      "Holder downloads an issued VC. The `vcId` is signed with the holder's (or issuer's, when `isIssuer=true`) Ed25519 private key to prove ownership. " +
      "Explicit args override the environment: `holderPrivateKey` overrides HOLDER_PRIVATE_KEY; `issuerPrivateKey` overrides ISSUER_PRIVATE_KEY. " +
      "Set `isIssuer: true` when the issuer (not the holder) is downloading. " +
      "Maps to POST /cred/v1/vc/download.",
    inputSchema: {
      type: "object",
      properties: {
        vcId: { type: "string", description: "Identifier of the VC to download." },
        holderPrivateKey: {
          type: "string",
          description:
            "Holder Ed25519 private key used to sign `vcId` when `isIssuer` is false. " +
            "Overrides HOLDER_PRIVATE_KEY env var.",
        },
        issuerPrivateKey: {
          type: "string",
          description:
            "Issuer Ed25519 private key used to sign `vcId` when `isIssuer` is true. " +
            "Overrides ISSUER_PRIVATE_KEY env var.",
        },
        signerPrivateKey: {
          type: "string",
          description:
            "Generic alias — Ed25519 private key used for signing regardless of role. Overrides both `holderPrivateKey` / `issuerPrivateKey` args when set.",
        },
        signVcId: {
          type: "string",
          description:
            "Pre-computed signature over `vcId`. If omitted, the tool will sign `vcId` using the resolved private key.",
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
      "Maps to POST /cred/v1/vp/create.",
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
            "Holder Ed25519 public key. Overrides HOLDER_KEY env var when provided; otherwise derived from HOLDER_PRIVATE_KEY.",
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
      "If `ed25519SignData` is omitted, this tool signs `blob` with the resolved holder private key. " +
      "Explicit `holderPrivateKey` / `ed25519PubKey` args override HOLDER_PRIVATE_KEY / HOLDER_KEY from the environment. " +
      "Maps to POST /cred/v1/vp/submit.",
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
            "Holder Ed25519 public key. Overrides HOLDER_KEY env var when provided; otherwise derived from HOLDER_PRIVATE_KEY.",
        },
        holderPrivateKey: {
          type: "string",
          description:
            "Holder Ed25519 private key used to sign `blob` when `ed25519SignData` is not provided. Overrides HOLDER_PRIVATE_KEY env var when provided.",
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
      "Explicit `holderPrivateKey` / `ed25519PubKey` args override HOLDER_PRIVATE_KEY / HOLDER_KEY from the environment. " +
      "Combines POST /cred/v1/vp/create → sign → POST /cred/v1/vp/submit → POST /cred/v1/vp/cache (optional).",
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
            "Holder Ed25519 public key. Overrides HOLDER_KEY env var when provided; otherwise derived from HOLDER_PRIVATE_KEY.",
        },
        holderPrivateKey: {
          type: "string",
          description:
            "Holder Ed25519 private key used to sign the VP blob. Overrides HOLDER_PRIVATE_KEY env var when provided.",
        },
        cache: {
          type: "boolean",
          description:
            "If true, also caches the signed VP via POST /cred/v1/vp/cache and returns the share uuid. Default false.",
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
      "Maps to POST /cred/v1/vp/cache.",
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
      "Maps to POST /cred/v1/vp/verify.",
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
          // Derive DIDs for diagnostics when possible (non-fatal if keys missing).
          // Each derivation path is independently caught so a malformed pubkey
          // doesn't block the private-key fallback.
          const safeDerive = async (priv?: string, pub?: string) => {
            const encodedPub = asEncodedEd25519PubKey(pub);
            if (encodedPub) {
              try {
                return deriveDidFromEncodedPublicKey(encodedPub);
              } catch {
                /* fall through to private-key derivation */
              }
            }
            const p = pick(priv);
            if (p) {
              try {
                return await signer.getDid(p);
              } catch {
                /* diagnostics shouldn't fail — report null */
              }
            }
            return null;
          };
          const derivedHolderDid =
            pick(HOLDER_DID) ?? (await safeDerive(HOLDER_PRIVATE_KEY, HOLDER_KEY));
          const derivedIssuerDid =
            pick(ISSUER_DID) ?? (await safeDerive(ISSUER_PRIVATE_KEY, ISSUER_KEY));

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
              issuerDid: derivedIssuerDid,
              holderKey: HOLDER_KEY ? "set" : "missing",
              holderPrivateKey: HOLDER_PRIVATE_KEY ? "set" : "missing",
              holderDid: derivedHolderDid,
            },
            defaults: {
              templateId: DEFAULT_TEMPLATE_ID ?? null,
            },
            contracts: {
              tdsContractAddress: TDS_CONTRACT_ADDRESS ?? null,
              rclContractAddress: RCL_CONTRACT_ADDRESS ?? null,
            },
            node: {
              baseUrl: nodeClient.baseUrl,
              defaultBaseUrls: ZETRIX_NODE_BASE_URLS,
            },
            zidResolver: {
              baseUrl: zidResolver.baseUrl,
              defaultBaseUrls: ZETRIX_ZID_RESOLVER_BASE_URLS,
            },
          });
        }

        case "zetrix_vc_generate_did": {
          const role = (args.role as "holder" | "issuer" | undefined) ?? "holder";

          // Priority: all explicit args first (priv → pub → raw), then env
          // fallbacks in the same order. HOLDER_KEY / ISSUER_KEY env vars that
          // are actually addresses (ZTX3…) are skipped — only encoded pubkeys
          // (b001…) are usable for DID derivation.
          const privArg = pick(args.privateKey as string | undefined);
          if (privArg) {
            return toTextResult({ did: await signer.getDid(privArg), source: "privateKey" });
          }
          const pubArg = asEncodedEd25519PubKey(args.publicKey as string | undefined);
          if (pubArg) {
            return toTextResult({ did: deriveDidFromEncodedPublicKey(pubArg), source: "publicKey" });
          }
          const rawArg = pick(args.rawPublicKey as string | undefined);
          if (rawArg) {
            if (!/^[0-9a-fA-F]{64}$/.test(rawArg)) {
              throw new Error(
                `rawPublicKey must be 64 hex chars (32 bytes), got length ${rawArg.length}.`
              );
            }
            return toTextResult({ did: `did:zid:${rawArg.toLowerCase()}`, source: "rawPublicKey" });
          }

          const envPriv = pick(role === "holder" ? HOLDER_PRIVATE_KEY : ISSUER_PRIVATE_KEY);
          if (envPriv) {
            return toTextResult({
              did: await signer.getDid(envPriv),
              source: `${role === "holder" ? "HOLDER_PRIVATE_KEY" : "ISSUER_PRIVATE_KEY"} env`,
            });
          }
          const envPub = asEncodedEd25519PubKey(role === "holder" ? HOLDER_KEY : ISSUER_KEY);
          if (envPub) {
            return toTextResult({
              did: deriveDidFromEncodedPublicKey(envPub),
              source: `${role === "holder" ? "HOLDER_KEY" : "ISSUER_KEY"} env`,
            });
          }

          throw new Error(
            "No usable key provided. Pass `privateKey`, `publicKey` (76-char b001… form), or `rawPublicKey` (64 hex chars), " +
              `or set ${role === "holder" ? "HOLDER_PRIVATE_KEY" : "ISSUER_PRIVATE_KEY"} env var. ` +
              `(${role === "holder" ? "HOLDER_KEY" : "ISSUER_KEY"} env is only used when it's a b001… encoded pubkey; addresses like ZTX3… don't carry pubkey info.)`
          );
        }

        case "zetrix_vc_resolve_did": {
          // If the caller didn't pass a DID, generate it from the holder role
          // (most common case when user asks "show me my DID document / permissions").
          let did = pick(args.did as string | undefined);
          if (!did) {
            try {
              did = await generateDid({
                role: "holder",
                didEnv: HOLDER_DID,
                publicKeyEnv: HOLDER_KEY,
                privateKeyEnv: HOLDER_PRIVATE_KEY,
              });
            } catch {
              throw new Error(
                "No DID to resolve. Pass `did` (e.g. did:zid:…), or configure HOLDER_DID / HOLDER_PRIVATE_KEY " +
                  "so the holder's DID can be generated automatically."
              );
            }
          }
          const doc = await zidResolver.resolve(did);
          return toTextResult({
            did,
            resolver: zidResolver.baseUrl,
            resolution: doc,
          });
        }

        case "zetrix_vc_get_template_detail": {
          const templateId = requireEnv(
            DEFAULT_TEMPLATE_ID,
            "templateId (or DEFAULT_TEMPLATE_ID)",
            args.templateId as string | undefined
          );
          const tdsContractAddress = requireEnv(
            TDS_CONTRACT_ADDRESS,
            "tdsContractAddress (or TDS_CONTRACT_ADDRESS)",
            args.tdsContractAddress as string | undefined
          );
          const detail = await nodeClient.getTemplateDetail(tdsContractAddress, templateId);
          return toTextResult(detail);
        }

        case "zetrix_vc_request_credential": {
          const metadata = args.metadata as Record<string, unknown> | undefined;
          if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
            throw new Error("`metadata` must be an object of claim key/values.");
          }

          const templateId = requireEnv(
            DEFAULT_TEMPLATE_ID,
            "templateId (or DEFAULT_TEMPLATE_ID)",
            args.templateId as string | undefined
          );
          const holderDid = await generateDid({
            role: "holder",
            didArg: args.holderDid as string | undefined,
            didEnv: HOLDER_DID,
            publicKeyArg: args.holderPublicKey as string | undefined,
            publicKeyEnv: HOLDER_KEY,
            privateKeyArg: args.holderPrivateKey as string | undefined,
            privateKeyEnv: HOLDER_PRIVATE_KEY,
          });
          const skipTemplateValidation = args.skipTemplateValidation === true;
          const skipDownload = args.skipDownload === true;

          // ----- 1. Validate required attributes against on-chain template -----
          let templateName: string | undefined;
          if (!skipTemplateValidation) {
            const tdsContractAddress = requireEnv(
              TDS_CONTRACT_ADDRESS,
              "tdsContractAddress (or TDS_CONTRACT_ADDRESS)",
              args.tdsContractAddress as string | undefined
            );
            const template = await nodeClient.getTemplateDetail(tdsContractAddress, templateId);
            if (!template.found) {
              throw new Error(
                `Template "${templateId}" was not found on TDS contract ${tdsContractAddress}. ` +
                  `Check the templateId / TDS_CONTRACT_ADDRESS, or pass skipTemplateValidation: true to proceed without the on-chain check.`
              );
            }
            const info = extractTemplateInfo(template.value);
            if (info) {
              templateName = info.templateName;
              const missing = findMissingRequiredAttributes(metadata, info);
              if (missing.length > 0) {
                const list = missing
                  .map((m) => `  - ${m.key} (${m.attribute}, ${m.format})`)
                  .join("\n");
                throw new Error(
                  `Cannot issue VC — template "${templateName ?? templateId}" requires these attributes that are missing or empty in \`metadata\`:\n` +
                    `${list}\n\n` +
                    `Ask the user for these values and retry with them included in \`metadata\` (use the \`key\` names shown above).`
                );
              }
            }
            // If info === null the template has no applyFormat; best-effort — proceed.
          }

          // ----- 2. Resolve credentials -----
          const holderPrivateKey = requireEnv(
            HOLDER_PRIVATE_KEY,
            "HOLDER_PRIVATE_KEY",
            args.holderPrivateKey as string | undefined
          );
          const holderPublicKey = await resolveEncodedPublicKey(
            args.holderPublicKey as string | undefined,
            HOLDER_KEY,
            holderPrivateKey
          );
          const issuerPrivateKey = requireEnv(
            ISSUER_PRIVATE_KEY,
            "ISSUER_PRIVATE_KEY",
            args.issuerPrivateKey as string | undefined
          );

          // Build the data array — single-template request. passDesignId optional.
          const passDesignId = args.passDesignId as string | undefined;
          const data: TemplateMetadataDto[] = [
            {
              templateId,
              ...(passDesignId ? { passDesignId } : {}),
              metadata,
            },
          ];

          // ----- 3. Apply (holder) -----
          const signPayload = stableStringify({ data });
          const { signData: applySig } = await signer.sign(signPayload, holderPrivateKey);
          const applyResp = await vcClient.applyVc({
            data,
            signData: applySig,
            publicKey: holderPublicKey,
          });

          // ----- 4. Issue (issuer) -----
          const issueResp = await vcClient.issueVc({
            data,
            holderDid,
            issuerPrivateKey,
            issuanceDate: args.issuanceDate as string | undefined,
            expirationDate: args.expirationDate as string | undefined,
            validFrom: args.validFrom as string | undefined,
            validUntil: args.validUntil as string | undefined,
            keyExpiry: args.keyExpiry as number | undefined,
          });

          // ----- 5. Download (holder) unless skipped -----
          if (skipDownload) {
            return toTextResult({
              templateId,
              templateName,
              holderDid,
              apply: applyResp,
              vc: issueResp.vc,
              vcPassBase64: issueResp.vcPassBase64,
              downloadExpiryDate: issueResp.downloadExpiryDate,
            });
          }

          // Sign the vcId from apply for the download proof-of-ownership.
          const { signData: dlSig } = await signer.sign(applyResp.vcId, holderPrivateKey);
          try {
            const downloadResp = await vcClient.downloadVc({
              vcId: applyResp.vcId,
              signVcId: dlSig,
            });
            return toTextResult({
              templateId,
              templateName,
              holderDid,
              apply: applyResp,
              vc: downloadResp.vc,
              vcPassBase64: downloadResp.vcPassBase64,
              downloadExpiryDate: downloadResp.downloadExpiryDate,
            });
          } catch (downloadErr) {
            // Download failed — surface the VC returned by issue with a warning
            // so the caller still gets a usable credential.
            const msg = downloadErr instanceof Error ? downloadErr.message : String(downloadErr);
            return toTextResult({
              templateId,
              templateName,
              holderDid,
              apply: applyResp,
              vc: issueResp.vc,
              vcPassBase64: issueResp.vcPassBase64,
              downloadExpiryDate: issueResp.downloadExpiryDate,
              warning: `Download step failed; returning VC from the issue step instead. Download error: ${msg}`,
            });
          }
        }

        case "zetrix_vc_apply": {
          const rawData = args.data as TemplateMetadataDto[] | undefined;
          if (!rawData || !Array.isArray(rawData) || rawData.length === 0) {
            throw new Error("`data` must be a non-empty array of TemplateMetadataDto.");
          }
          const data = applyDefaultTemplateId(rawData);
          // Explicit args override env vars (HOLDER_PRIVATE_KEY / HOLDER_KEY).
          // HOLDER_KEY is ignored unless it's an encoded (b001…) pubkey — if
          // it's an address, we derive the pubkey from the private key.
          const holderPrivateKey = requireEnv(
            HOLDER_PRIVATE_KEY,
            "HOLDER_PRIVATE_KEY",
            args.holderPrivateKey as string | undefined
          );
          const holderPublicKey = await resolveEncodedPublicKey(
            args.holderPublicKey as string | undefined,
            HOLDER_KEY,
            holderPrivateKey
          );

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
          const holderDid = await generateDid({
            role: "holder",
            didArg: args.holderDid as string | undefined,
            didEnv: HOLDER_DID,
            publicKeyArg: args.holderPublicKey as string | undefined,
            publicKeyEnv: HOLDER_KEY,
            privateKeyArg: args.holderPrivateKey as string | undefined,
            privateKeyEnv: HOLDER_PRIVATE_KEY,
          });
          const rawData = args.data as TemplateMetadataDto[] | undefined;
          if (!rawData || !Array.isArray(rawData) || rawData.length === 0) {
            throw new Error("`data` must be a non-empty array of TemplateMetadataDto.");
          }
          const data = applyDefaultTemplateId(rawData);
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

          let signVcId = pick(args.signVcId as string | undefined);
          if (!signVcId) {
            // Explicit args override env. Prefer the role-specific arg name
            // (issuerPrivateKey when isIssuer=true, holderPrivateKey otherwise)
            // but also accept the generic signerPrivateKey for either role.
            const argSigner = pick(
              args.signerPrivateKey as string | undefined,
              isIssuer
                ? (args.issuerPrivateKey as string | undefined)
                : (args.holderPrivateKey as string | undefined)
            );
            const privateKey = requireEnv(
              isIssuer ? ISSUER_PRIVATE_KEY : HOLDER_PRIVATE_KEY,
              isIssuer ? "ISSUER_PRIVATE_KEY" : "HOLDER_PRIVATE_KEY",
              argSigner
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

          // Resolve the encoded pubkey from arg → HOLDER_KEY (only if encoded)
          // → derive from HOLDER_PRIVATE_KEY. Address-form HOLDER_KEY is skipped.
          let ed25519PubKey: string | undefined =
            asEncodedEd25519PubKey(args.ed25519PubKey as string | undefined) ??
            asEncodedEd25519PubKey(HOLDER_KEY);
          const envPriv = pick(HOLDER_PRIVATE_KEY);
          if (!ed25519PubKey && envPriv) {
            ed25519PubKey = await signer.getPublicKey(envPriv);
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

          let signData = pick(args.ed25519SignData as string | undefined);
          // Explicit ed25519PubKey arg always overrides HOLDER_KEY env var; env
          // HOLDER_KEY is only accepted when it's an encoded (b001…) pubkey.
          let ed25519PubKey: string | undefined =
            asEncodedEd25519PubKey(args.ed25519PubKey as string | undefined) ??
            asEncodedEd25519PubKey(HOLDER_KEY);

          if (!signData) {
            const blob = pick(args.blob as string | undefined);
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
            if (!ed25519PubKey) ed25519PubKey = sig.publicKey;
          } else if (!ed25519PubKey) {
            const envPriv = pick(HOLDER_PRIVATE_KEY);
            if (envPriv) ed25519PubKey = await signer.getPublicKey(envPriv);
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
          // Explicit args override env vars (HOLDER_PRIVATE_KEY / HOLDER_KEY).
          const holderPrivateKey = requireEnv(
            HOLDER_PRIVATE_KEY,
            "HOLDER_PRIVATE_KEY",
            args.holderPrivateKey as string | undefined
          );
          const ed25519PubKey = await resolveEncodedPublicKey(
            args.ed25519PubKey as string | undefined,
            HOLDER_KEY,
            holderPrivateKey
          );

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
