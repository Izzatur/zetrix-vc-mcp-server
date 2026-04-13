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
  RevokeSignerEntry,
} from "./zetrix-vc-client.js";
import {
  ZetrixVcSigner,
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
 * Require a non-empty tool argument. No env fallback.
 */
function requireArg(value: string | undefined, name: string): string {
  const resolved = pick(value);
  if (!resolved) {
    throw new Error(`Missing \`${name}\`. Provide it as a tool argument.`);
  }
  return resolved;
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
/**
 * Reshape each `TemplateMetadataDto` into the exact field order Jackson uses
 * server-side (templateId → passDesignId → metadata → tds), with null/empty
 * optional fields omitted. The apply/issue signature is verified against
 * Jackson's re-serialization of `data`, so our outgoing JSON must match that
 * order exactly — alphabetical or insertion-from-spread orderings produce
 * different bytes and the signature then fails (error 650530).
 *
 * Also applies DEFAULT_TEMPLATE_ID as a fallback when an item has no
 * explicit templateId.
 */
function applyDefaultTemplateId(data: TemplateMetadataDto[]): TemplateMetadataDto[] {
  const fallback = pick(DEFAULT_TEMPLATE_ID);
  return data.map((item, idx) => {
    const itemTemplateId = pick(
      typeof item?.templateId === "string" ? item.templateId : undefined
    );
    const resolvedTemplateId = itemTemplateId ?? fallback;
    if (!resolvedTemplateId) {
      throw new Error(
        `data[${idx}].templateId is missing and DEFAULT_TEMPLATE_ID is not set. ` +
          `Either include a templateId per item or configure DEFAULT_TEMPLATE_ID in the environment.`
      );
    }
    // Build each item in Jackson field-declaration order: templateId →
    // passDesignId → metadata → tds (omit unset optional fields). This exact
    // byte order must match what the server signs against, otherwise the
    // signature fails verification (error 650530).
    const out: Record<string, unknown> = {};
    out.templateId = resolvedTemplateId;
    if (pick(item.passDesignId)) out.passDesignId = item.passDesignId;
    out.metadata = item.metadata;
    if (pick(item.tds)) out.tds = item.tds;
    return out as unknown as TemplateMetadataDto;
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
      "Derive the Zetrix DID (`did:zid:<rawPubKey>`) from a key. " +
      "Handy for discovering 'what is my DID' without any network call. " +
      "If called with no arguments, uses the configured holder (or issuer when `role: \"issuer\"`).",
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
      "When `did` is omitted the holder's DID (derived from the configured holder keys) is used.",
    inputSchema: {
      type: "object",
      properties: {
        did: {
          type: "string",
          description:
            "The DID to resolve (e.g. did:zid:acfdbaa6…). If omitted, the configured holder's DID is resolved.",
        },
      },
      required: [],
    },
  },

  // --------------------- VC: Template lookup ---------------------
  {
    name: "zetrix_vc_get_template_detail",
    description:
      "Fetch a VC template record (including which fields it requires) from the on-chain Template Data Store. " +
      "Useful when you need to know what claim fields a credential template expects before asking the user for values. " +
      "Both `templateId` and `tdsContractAddress` are optional — omit them to use the configured defaults. " +
      "Returns the template metadata and the parsed `applyFormat` (list of required attributes with their human-readable labels).",
    inputSchema: {
      type: "object",
      properties: {
        templateId: {
          type: "string",
          description: "Optional template id override. Omit to use the configured default.",
        },
        tdsContractAddress: {
          type: "string",
          description: "Optional TDS contract address override. Omit to use the configured default.",
        },
      },
      required: [],
    },
  },

  // --------------------- VC: Full flow (apply + issue + download) ---------------------
  {
    name: "zetrix_vc_request_credential",
    description:
      "Issue a Verifiable Credential end-to-end in one call. Use this when the user says 'apply a VC', 'issue me a VC', 'give me a credential', or similar. " +
      "The tool runs the full apply → issue → download sequence and returns the signed W3C JSON-LD VerifiableCredential. " +
      "\n\n" +
      "**How to gather inputs from the user:**\n" +
      "• Holder and issuer identity, template id, and contract addresses are pre-configured — don't ask the user about these unless they're not configured (the tool will tell you if something's missing). Never mention environment variables, fallbacks, or the underlying configuration mechanism to the user.\n" +
      "• The ONLY thing you typically need from the user is the claim values — but don't ask for them generically. If the user hasn't given you the claim values, call this tool immediately with `metadata: {}`. The tool will return an error listing exactly which fields the template requires (with human-readable labels like 'IC Number' or 'Full Name'). Use that list to ask the user for the specific values.\n" +
      "• Once you have the values, call the tool again with `metadata: {...}` filled in.\n" +
      "\n" +
      "**What the tool does internally (informational only — don't expose to the user):**\n" +
      "1. Fetches the template from the on-chain TDS contract.\n" +
      "2. Validates every required attribute is present in `metadata`.\n" +
      "3. Applies (holder), issues (issuer), downloads (holder) — in strict order.\n" +
      "4. Returns the signed W3C VerifiableCredential.",
    inputSchema: {
      type: "object",
      properties: {
        metadata: {
          type: "object",
          description:
            "Claim values for the VC, one entry per required template field (e.g. `{ name, icNo, expiry }`). " +
            "If you don't know the required fields yet, pass `{}` and the tool will return the list.",
          additionalProperties: true,
        },
        templateId: {
          type: "string",
          description: "Optional template id override. Omit to use the configured default.",
        },
        holderDid: {
          type: "string",
          description: "Optional holder DID override. Omit to use the configured holder.",
        },
        tdsContractAddress: {
          type: "string",
          description: "Optional TDS contract address override. Omit to use the configured default.",
        },
        passDesignId: {
          type: "string",
          description: "Optional pass design identifier attached to the credential.",
        },
        issuanceDate: { type: "string", description: "Optional issuance date (`yyyy-MM-dd`). Note: the BaaS preserves only validFrom/validUntil on issued VCs." },
        expirationDate: { type: "string", description: "Optional expiration date (`yyyy-MM-dd`). See issuanceDate note." },
        validFrom: { type: "string", description: "Optional validity start (`yyyy-MM-dd`)." },
        validUntil: { type: "string", description: "Optional validity end (`yyyy-MM-dd`)." },
        keyExpiry: { type: "number", description: "Optional key expiry override (default 0)." },
        skipTemplateValidation: {
          type: "boolean",
          description: "Skip the pre-flight template check. Default false; rarely needed.",
        },
        skipDownload: {
          type: "boolean",
          description: "Return the VC from the issue step and skip the final download. Default false.",
        },
        holderPrivateKey: {
          type: "string",
          description: "Optional per-call holder private key override. Usually omitted.",
        },
        holderPublicKey: {
          type: "string",
          description: "Optional per-call holder public key override. Usually omitted.",
        },
        issuerPrivateKey: {
          type: "string",
          description: "Optional per-call issuer private key override. Usually omitted.",
        },
      },
      required: ["metadata"],
    },
  },

  // --------------------- VC: Apply (holder) ---------------------
  {
    name: "zetrix_vc_apply",
    description:
      "Holder applies for a Verifiable Credential — step 1 of the standard VC issuance flow. " +
      "Returns a pending `vcId`. **For most use cases, prefer `zetrix_vc_request_credential`** which runs apply → issue → download in one call. " +
      "Use `zetrix_vc_apply` only when you specifically need to apply without immediately issuing. Maps to POST /cred/v1/vc/apply.",
    inputSchema: {
      type: "object",
      properties: {
        data: {
          type: "array",
          description:
            "List of TemplateMetadataDto — the VC template(s) + claim metadata to apply for. " +
            "`templateId` may be omitted on any item; the configured default template is used as fallback.",
          items: {
            type: "object",
            properties: {
              templateId: {
                type: "string",
                description:
                  "VC template identifier. Optional — omit to use the configured default.",
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
          description: "Optional per-call holder private key override. Usually omitted.",
        },
        holderPublicKey: {
          type: "string",
          description: "Optional per-call holder public key override. Usually omitted.",
        },
      },
      required: ["data"],
    },
  },

  // --------------------- VC: Issue (issuer) ---------------------
  {
    name: "zetrix_vc_issue",
    description:
      "Issuer directly issues a VC to a holder (one call — skips the holder's apply step). " +
      "**For most use cases, prefer `zetrix_vc_request_credential`** which also downloads the final signed VC and handles attribute validation. " +
      "Use this when you specifically need the one-shot issuer-initiated path. Maps to POST /cred/v1/vc/issue.",
    inputSchema: {
      type: "object",
      properties: {
        holderDid: {
          type: "string",
          description: "Optional holder DID override. Omit to use the configured holder.",
        },
        holderPublicKey: {
          type: "string",
          description: "Optional per-call holder public key override. Usually omitted.",
        },
        holderPrivateKey: {
          type: "string",
          description: "Optional per-call holder private key override. Usually omitted.",
        },
        data: {
          type: "array",
          description:
            "List of TemplateMetadataDto — template(s) + claim metadata for the VC. " +
            "`templateId` may be omitted on any item; the configured default template is used as fallback.",
          items: {
            type: "object",
            properties: {
              templateId: {
                type: "string",
                description:
                  "VC template identifier. Optional — omit to use the configured default.",
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
          description: "Optional issuance date (`yyyy-MM-dd`). Note: the BaaS preserves only validFrom/validUntil on issued VCs.",
        },
        expirationDate: {
          type: "string",
          description: "Optional expiration date (`yyyy-MM-dd`). See issuanceDate note.",
        },
        validFrom: { type: "string", description: "Optional validity start (`yyyy-MM-dd`)." },
        validUntil: { type: "string", description: "Optional validity end (`yyyy-MM-dd`)." },
        keyExpiry: { type: "number", description: "Optional key expiry override (default 0)." },
        issuerPrivateKey: {
          type: "string",
          description: "Optional per-call issuer private key override. Usually omitted.",
        },
      },
      required: ["data"],
    },
  },

  // --------------------- VC: Download (holder) ---------------------
  {
    name: "zetrix_vc_download",
    description:
      "Holder downloads an issued VC. **Workflow ordering: download only works AFTER the issuer has processed the application.** " +
      "The BaaS enforces apply → issue → download strictly in order; downloading a `vcId` that is still pending returns `HTTP 400: The VC application has not been issued yet`. " +
      "For end-to-end issuance in a single call use `zetrix_vc_request_credential`, which runs all three steps in the correct order. " +
      "Use `zetrix_vc_download` on its own only when the issue step has already happened out-of-band. " +
      "Set `isIssuer: true` when the issuer (not the holder) is downloading.",
    inputSchema: {
      type: "object",
      properties: {
        vcId: { type: "string", description: "Identifier of the VC to download." },
        holderPrivateKey: {
          type: "string",
          description:
            "Holder Ed25519 private key used to sign `vcId` when `isIssuer` is false. " +
            "Optional per-call override.",
        },
        issuerPrivateKey: {
          type: "string",
          description:
            "Issuer Ed25519 private key used to sign `vcId` when `isIssuer` is true. " +
            "Optional per-call override.",
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
          description:
            "Attribute paths to selectively disclose. Each entry is a **dotted path** into " +
            "`credentialSubject` — e.g. `id`, `mykad.name`, `mykad.icNo`. The path format " +
            "mirrors the VC's own structure (`credentialSubject.<camelCaseTemplateName>.<field>`). " +
            "Pass `[]` to reveal everything (no selective disclosure), or list only the paths " +
            "you want to disclose. The template's `applyFormat[].key` values plus the " +
            "camelCased template name give you the paths: e.g. MyKAD template + `icNo` field → `mykad.icNo`.",
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
            "Optional per-call holder public key override. Usually omitted.",
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
      "`holderPrivateKey` / `ed25519PubKey` args are optional per-call overrides; usually omit them to use the configured holder. " +
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
            "Optional per-call holder public key override. Usually omitted.",
        },
        holderPrivateKey: {
          type: "string",
          description:
            "Optional per-call holder private key override used to sign `blob` when `ed25519SignData` is not provided. Usually omitted.",
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
      "`holderPrivateKey` / `ed25519PubKey` args are optional per-call overrides; usually omit them to use the configured holder. " +
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
            "Optional per-call holder public key override. Usually omitted.",
        },
        holderPrivateKey: {
          type: "string",
          description:
            "Optional per-call holder private key override used to sign the VP blob. Usually omitted.",
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

  // --------------------- VC: Revocation (Flow 3) ---------------------
  {
    name: "zetrix_vc_revoke_create_blob",
    description:
      "Step 1 of 3 in the revocation flow. Issuer requests a revocation blob for a specific vcId. " +
      "Returns `{ blobId, blob }` where `blob` is a hex-encoded protobuf transaction the issuer must sign " +
      "(use `zetrix_vc_revoke` for the one-shot combo). " +
      "Maps to POST /cred/v1/vc/revoke/create-blob.",
    inputSchema: {
      type: "object",
      properties: {
        vcId: { type: "string", description: "The VC to revoke (e.g. did:zid:...)." },
        remark: { type: "string", description: "Optional free-text remark explaining the revocation." },
        issuerAddress: {
          type: "string",
          description:
            "Optional issuer Zetrix address (ZTX3…) override. Omit to use the configured issuer.",
        },
      },
      required: ["vcId"],
    },
  },
  {
    name: "zetrix_vc_revoke_submit",
    description:
      "Step 3 of 3 in the revocation flow. Issuer submits the signed revocation blob. " +
      "Maps to POST /cred/v1/vc/revoke/submit.",
    inputSchema: {
      type: "object",
      properties: {
        blobId: { type: "string", description: "blobId returned from zetrix_vc_revoke_create_blob." },
        signerList: {
          type: "array",
          description:
            "List of { signBlob, publicKey } entries. Typically a single entry: the issuer signing " +
            "the blob returned in step 1.",
          items: {
            type: "object",
            properties: {
              signBlob: { type: "string", description: "Hex signature produced by signing the step-1 blob with issuer's Ed25519 private key." },
              publicKey: { type: "string", description: "Issuer's Zetrix-encoded Ed25519 public key (b001… form)." },
            },
            required: ["signBlob", "publicKey"],
          },
        },
      },
      required: ["blobId", "signerList"],
    },
  },
  {
    name: "zetrix_vc_revoke",
    description:
      "Revoke a VC in one call — runs create-blob → sign → submit in strict order. " +
      "Use this instead of the three individual tools unless you need fine-grained control. " +
      "⚠️ Destructive: revocation is recorded on-chain and cannot be undone — confirm with the user before calling.",
    inputSchema: {
      type: "object",
      properties: {
        vcId: { type: "string", description: "The VC to revoke (e.g. did:zid:...)." },
        remark: { type: "string", description: "Optional free-text remark explaining the revocation." },
        issuerAddress: {
          type: "string",
          description:
            "Optional issuer Zetrix address (ZTX3…) override. Omit to use the configured issuer.",
        },
        issuerPrivateKey: {
          type: "string",
          description: "Optional per-call issuer private key override used to sign the revocation blob. Usually omitted.",
        },
      },
      required: ["vcId"],
    },
  },
  {
    name: "zetrix_vc_revoke_status",
    description:
      "Query the current revocation status of a VC. Read-only; no signing required. " +
      "Maps to POST /cred/v1/vc/revoke/status.",
    inputSchema: {
      type: "object",
      properties: {
        vcId: { type: "string", description: "The VC id to check (e.g. did:zid:...)." },
        issuer: {
          type: "string",
          description: "Optional issuer Zetrix address (ZTX3…) override. Omit to use the configured issuer.",
        },
      },
      required: ["vcId"],
    },
  },

  // --------------------- Full Flow 1 (multi-step VC issuance) ---------------------
  {
    name: "zetrix_vc_create",
    description:
      "Step 3 of the full Flow 1 VC issuance (after apply). Issuer requests the canonical VC payload to " +
      "sign with BBS+ and Ed25519. Returns the BBS+ statements (`bbsBlsBase64`) and the Ed25519 blob " +
      "(`ed25519Blob`). Rarely called directly — use `zetrix_vc_issue` or `zetrix_vc_request_credential` " +
      "instead unless you specifically need the multi-step flow. " +
      "Maps to POST /cred/v1/vc/create.",
    inputSchema: {
      type: "object",
      properties: {
        vcId: { type: "string", description: "vcId returned by the prior zetrix_vc_apply call." },
        data: {
          type: "array",
          description: "List of TemplateMetadataDto (same shape as apply/issue).",
          items: {
            type: "object",
            properties: {
              templateId: { type: "string" },
              passDesignId: { type: "string" },
              metadata: { type: "object", additionalProperties: true },
              tds: { type: "string" },
            },
            required: ["metadata"],
          },
        },
        issuanceDate: { type: "string", description: "yyyy-MM-dd." },
        expirationDate: { type: "string", description: "yyyy-MM-dd." },
        validFrom: { type: "string", description: "yyyy-MM-dd." },
        validUntil: { type: "string", description: "yyyy-MM-dd." },
      },
      required: ["vcId", "data"],
    },
  },
  {
    name: "zetrix_vc_sign_bbs",
    description:
      "Step 4 of Flow 1. Signs the canonicalized VC statements with the issuer's BBS+ keypair. " +
      "Requires the issuer's BBS+ multibase-encoded public/private keys (generated at " +
      "https://identity-sandbox.zetrix.com/). Maps to POST /cred/bbs/vc/sign.",
    inputSchema: {
      type: "object",
      properties: {
        publicKeyMultibase: { type: "string", description: "Issuer BBS+ public key (multibase)." },
        privateKeyMultibase: { type: "string", description: "Issuer BBS+ private key (multibase)." },
        data: {
          type: "array",
          description: "Base64-encoded statements to sign (from zetrix_vc_create response).",
          items: { type: "string" },
        },
      },
      required: ["publicKeyMultibase", "privateKeyMultibase", "data"],
    },
  },
  {
    name: "zetrix_vc_submit",
    description:
      "Step 6 of Flow 1. Submits both signatures (Ed25519 + BBS+) to finalize issuance. " +
      "Maps to POST /cred/v1/vc/submit.",
    inputSchema: {
      type: "object",
      properties: {
        vcId: { type: "string" },
        ed25519PubKey: { type: "string" },
        ed25519SignData: { type: "string" },
        bbsBlsPubKey: { type: "string" },
        bbsBlsSignData: { type: "string" },
        keyExpiry: { type: "number", description: "Default 0 or per-issuer preference." },
      },
      required: ["vcId", "ed25519PubKey", "ed25519SignData", "bbsBlsPubKey", "bbsBlsSignData"],
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
          // Server verifies the signature against the exact JSON bytes of
          // the `data` array as sent on the wire (Jackson insertion order).
          // Matching JSON.stringify(data) reproduces those bytes, so axios
          // and the signer agree on the pre-image.
          const signPayload = JSON.stringify(data);
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

          // Server verifies against the exact JSON bytes of the `data` array
          // as sent on the wire — see `zetrix_vc_request_credential` for details.
          const signPayload = JSON.stringify(data);
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

          // Only forward ed25519PubKey / bbsPublicKey when the caller explicitly
          // supplies them. Auto-deriving them from holder keys caused the
          // server to mis-verify the VC's Ed25519Signature2020 proof (the
          // supplied pubkey was compared against the VC's issuer key instead
          // of the VC's subject key). The Postman reference example sends
          // only `vc` + `revealAttribute`, so we match that unless the caller
          // opts in.
          const resp = await vcClient.createVp({
            vc,
            revealAttribute: args.revealAttribute as string[] | undefined,
            rangeProof: args.rangeProof as RangeProofDto | undefined,
            bbsPublicKey: asEncodedEd25519PubKey(args.bbsPublicKey as string | undefined),
            ed25519PubKey: asEncodedEd25519PubKey(args.ed25519PubKey as string | undefined),
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
            // vp/create returns `blob` as a hex-encoded payload (the
            // canonicalized VP bytes). Detect hex-form and sign raw bytes;
            // otherwise fall back to UTF-8 signing for older responses.
            const looksHex = /^[0-9a-fA-F]+$/.test(blob) && blob.length % 2 === 0;
            const sig = looksHex
              ? await signer.signHex(blob, holderPrivateKey)
              : await signer.sign(blob, holderPrivateKey);
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
          // For vp_submit we still need the holder's encoded pubkey (the server
          // uses it to verify the holder's signature on the VP blob). But we
          // DON'T send it on vp/create — see the zetrix_vp_create handler
          // comment above.
          const ed25519PubKey = await resolveEncodedPublicKey(
            args.ed25519PubKey as string | undefined,
            HOLDER_KEY,
            holderPrivateKey
          );

          // 1. Create the VP blob (do NOT send ed25519PubKey here)
          const created = await vcClient.createVp({
            vc,
            revealAttribute: args.revealAttribute as string[] | undefined,
            rangeProof: args.rangeProof as RangeProofDto | undefined,
            bbsPublicKey: asEncodedEd25519PubKey(args.bbsPublicKey as string | undefined),
          });

          // 2. Sign the blob with the holder's private key. vp/create returns
          // the blob as hex-encoded bytes, so hex-decode before signing.
          const looksHex = /^[0-9a-fA-F]+$/.test(created.blob) && created.blob.length % 2 === 0;
          const { signData } = looksHex
            ? await signer.signHex(created.blob, holderPrivateKey)
            : await signer.sign(created.blob, holderPrivateKey);

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
          // Server returns `verified`; surface as both `verified` and
          // `isVerified` so consumers expecting either field work.
          const verified = resp.verified ?? resp.isVerified;
          return toTextResult({ ...resp, verified, isVerified: verified });
        }

        // --------- Revocation Flow 3 ---------
        case "zetrix_vc_revoke_create_blob": {
          const vcId = requireArg(args.vcId as string | undefined, "vcId");
          const issuerAddress = requireEnv(
            ISSUER_KEY,
            "issuerAddress (or ISSUER_KEY env)",
            args.issuerAddress as string | undefined
          );
          const resp = await vcClient.revokeCreateBlob({
            vcId,
            remark: args.remark as string | undefined,
            issuerAddress,
          });
          return toTextResult(resp);
        }

        case "zetrix_vc_revoke_submit": {
          const blobId = requireArg(args.blobId as string | undefined, "blobId");
          const signerList = args.signerList as RevokeSignerEntry[] | undefined;
          if (!Array.isArray(signerList) || signerList.length === 0) {
            throw new Error("`signerList` must be a non-empty array of { signBlob, publicKey }.");
          }
          const resp = await vcClient.revokeSubmit({ blobId, signerList });
          return toTextResult(resp);
        }

        case "zetrix_vc_revoke": {
          const vcId = requireArg(args.vcId as string | undefined, "vcId");
          const issuerAddress = requireEnv(
            ISSUER_KEY,
            "issuerAddress (or ISSUER_KEY env)",
            args.issuerAddress as string | undefined
          );
          const issuerPrivateKey = requireEnv(
            ISSUER_PRIVATE_KEY,
            "ISSUER_PRIVATE_KEY",
            args.issuerPrivateKey as string | undefined
          );

          // Step 1: request the blob to sign
          const created = await vcClient.revokeCreateBlob({
            vcId,
            remark: args.remark as string | undefined,
            issuerAddress,
          });
          const hexBlob = pick(created.blob, created.ed25519Blob);
          if (!hexBlob) {
            throw new Error(
              `revoke/create-blob returned no blob. Raw response: ${JSON.stringify(created).slice(0, 300)}`
            );
          }

          // Step 2: sign the hex-encoded protobuf blob locally
          const sig = await signer.signHex(hexBlob, issuerPrivateKey);

          // Step 3: submit the revocation
          const submitted = await vcClient.revokeSubmit({
            blobId: created.blobId,
            signerList: [{ signBlob: sig.signData, publicKey: sig.publicKey }],
          });

          return toTextResult({
            vcId,
            issuerAddress,
            blobId: created.blobId,
            submit: submitted,
          });
        }

        case "zetrix_vc_revoke_status": {
          const vcId = requireArg(args.vcId as string | undefined, "vcId");
          const issuer = requireEnv(
            ISSUER_KEY,
            "issuer (or ISSUER_KEY env)",
            args.issuer as string | undefined
          );
          const resp = await vcClient.revokeStatus({ vcId, issuer });
          return toTextResult(resp);
        }

        // --------- Full Flow 1 (vc/create, bbs/sign, vc/submit) ---------
        case "zetrix_vc_create": {
          const vcId = requireArg(args.vcId as string | undefined, "vcId");
          const rawData = args.data as TemplateMetadataDto[] | undefined;
          if (!rawData || !Array.isArray(rawData) || rawData.length === 0) {
            throw new Error("`data` must be a non-empty array of TemplateMetadataDto.");
          }
          const data = applyDefaultTemplateId(rawData);
          const resp = await vcClient.createVc({
            vcId,
            data,
            issuanceDate: args.issuanceDate as string | undefined,
            expirationDate: args.expirationDate as string | undefined,
            validFrom: args.validFrom as string | undefined,
            validUntil: args.validUntil as string | undefined,
          });
          return toTextResult(resp);
        }

        case "zetrix_vc_sign_bbs": {
          const publicKeyMultibase = requireArg(
            args.publicKeyMultibase as string | undefined,
            "publicKeyMultibase"
          );
          const privateKeyMultibase = requireArg(
            args.privateKeyMultibase as string | undefined,
            "privateKeyMultibase"
          );
          const data = args.data as string[] | undefined;
          if (!Array.isArray(data) || data.length === 0) {
            throw new Error("`data` must be a non-empty array of base64 statements.");
          }
          const resp = await vcClient.signVcBbs({ publicKeyMultibase, privateKeyMultibase, data });
          return toTextResult(resp);
        }

        case "zetrix_vc_submit": {
          const vcId = requireArg(args.vcId as string | undefined, "vcId");
          const ed25519PubKey = requireArg(args.ed25519PubKey as string | undefined, "ed25519PubKey");
          const ed25519SignData = requireArg(args.ed25519SignData as string | undefined, "ed25519SignData");
          const bbsBlsPubKey = requireArg(args.bbsBlsPubKey as string | undefined, "bbsBlsPubKey");
          const bbsBlsSignData = requireArg(args.bbsBlsSignData as string | undefined, "bbsBlsSignData");
          const resp = await vcClient.submitVc({
            vcId,
            ed25519PubKey,
            ed25519SignData,
            bbsBlsPubKey,
            bbsBlsSignData,
            keyExpiry: args.keyExpiry as number | undefined,
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
