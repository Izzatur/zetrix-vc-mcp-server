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
import { writeFile, mkdir } from "node:fs/promises";
import { resolve as pathResolve, dirname as pathDirname, isAbsolute } from "node:path";
import { homedir } from "node:os";

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

// Directory where downloaded VCs are written as .json files. When unset,
// defaults to the current working directory the MCP server was launched from.
// Accepts `~` as a shortcut for the user's home directory.
const ZETRIX_VC_DOWNLOAD_DIR = process.env.ZETRIX_VC_DOWNLOAD_DIR;

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
 * Normalise a user-supplied identifier into a canonical Zetrix DID
 * (`did:zid:<rawPubKey>`). Accepts several plausible forms:
 *   - `did:zid:<64-hex>`  → returned as-is
 *   - `<64-hex>`          → prefixed with `did:zid:`
 *   - `b001…<76-hex>`     → stripped + prefixed
 *   - `ZTX3…` address     → REJECTED with a clear error (addresses can't be
 *                           reversed into a pubkey locally; the BaaS expects
 *                           the DID form)
 *
 * Used when the caller has supplied `holderDid` / `HOLDER_DID` (or the
 * issuer equivalent) explicitly — we want to ensure whatever we send
 * outbound is in the `did:zid:` form the BaaS expects.
 */
function normaliseZetrixDid(value: string, role: "holder" | "issuer"): string {
  const v = value.trim();
  if (v.startsWith("did:zid:")) return v.toLowerCase();
  if (/^[0-9a-fA-F]{64}$/.test(v)) return `did:zid:${v.toLowerCase()}`;
  const enc = asEncodedEd25519PubKey(v);
  if (enc) return deriveDidFromEncodedPublicKey(enc);
  if (/^ZTX[A-Za-z0-9]+$/.test(v)) {
    throw new Error(
      `${role}Did cannot be a Zetrix address (${v}). The BaaS expects the DID form 'did:zid:<rawPubKey>'. ` +
        `Either set ${role}Did to 'did:zid:...', or let the tool derive it by providing ${role}PublicKey (b001… form) or ${role}PrivateKey — ` +
        `a ZTX3 address cannot be reversed into a public key locally.`
    );
  }
  throw new Error(
    `Cannot interpret ${role}Did "${v}". Expected 'did:zid:<rawPubKey>' or an encoded/raw public key.`
  );
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
  // Normalise any explicit DID — if someone put a ZTX3 address in
  // HOLDER_DID by mistake, this throws loudly with guidance instead of
  // silently sending the wrong format to the BaaS.
  const explicit = pick(params.didArg, params.didEnv);
  if (explicit) return normaliseZetrixDid(explicit, params.role);

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

/**
 * Expand `~` and `~/...` paths using the current user's home dir.
 */
function expandPath(p: string): string {
  if (p === "~") return homedir();
  if (p.startsWith("~/")) return pathResolve(homedir(), p.slice(2));
  return p;
}

/**
 * Derive a default filename for a downloaded VC. Uses the template type
 * (`MyKAD` → `mykad`) + a short vcId suffix so multiple downloads don't
 * collide and the file is recognisable.
 *
 *   mykad-a14f9f3b2c.json
 */
function defaultVcFilename(vc: { id?: string; type?: string[] }): string {
  const type = Array.isArray(vc.type) ? vc.type.find((t) => t !== "VerifiableCredential") : undefined;
  const slug = (type ?? "vc").toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "") || "vc";
  const id = typeof vc.id === "string" ? vc.id.replace(/^did:zid:/, "").slice(0, 12) : randomUUID().slice(0, 12);
  return `${slug}-${id}.json`;
}

/**
 * Write the downloaded VC to disk as pretty-printed JSON. Resolution order:
 *   1. `outputPath` arg — explicit file path (absolute, or relative to CWD)
 *   2. `outputDir` arg / ZETRIX_VC_DOWNLOAD_DIR env — directory; filename auto-derived
 *   3. CWD + auto-derived filename
 *
 * Returns the absolute path of the written file.
 */
async function writeVcToFile(
  vc: Record<string, unknown>,
  opts: { outputPath?: string; outputDir?: string } = {}
): Promise<string> {
  const explicit = pick(opts.outputPath);
  let target: string;
  if (explicit) {
    const expanded = expandPath(explicit);
    target = isAbsolute(expanded) ? expanded : pathResolve(process.cwd(), expanded);
  } else {
    const dirArg = pick(opts.outputDir) ?? pick(ZETRIX_VC_DOWNLOAD_DIR) ?? process.cwd();
    const expandedDir = expandPath(dirArg);
    const resolvedDir = isAbsolute(expandedDir) ? expandedDir : pathResolve(process.cwd(), expandedDir);
    target = pathResolve(
      resolvedDir,
      defaultVcFilename(vc as { id?: string; type?: string[] })
    );
  }

  await mkdir(pathDirname(target), { recursive: true });
  await writeFile(target, JSON.stringify(vc, null, 2) + "\n", "utf8");
  return target;
}

/**
 * Return today + 1 year as a `yyyy-MM-dd` string — used as the default
 * `validUntil` when the caller doesn't supply one. The BaaS expects
 * date-only format, not ISO-8601 with time.
 */
function defaultValidUntil(): string {
  const d = new Date();
  d.setUTCFullYear(d.getUTCFullYear() + 1);
  return d.toISOString().slice(0, 10);
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
      "End-to-end VC issuance: apply → issue → download, in one call, returning the signed W3C VerifiableCredential.\n" +
      "\n" +
      "★ USE THIS when the user asks to get a credential issued to themselves (the configured holder):\n" +
      "  • 'apply VC for me'\n" +
      "  • 'issue me a VC' / 'issue VC for me'\n" +
      "  • 'create VC for me'\n" +
      "  • 'give me a credential' / 'get me a VC' / 'I want my MyKAD'\n" +
      "\n" +
      "★ DO NOT USE when the user specifies a target different from the configured holder (e.g. 'issue VC to address A' → use `zetrix_vc_issue`), or when they explicitly want only one step (e.g. 'apply only' → use `zetrix_vc_apply`; 'download only' → use `zetrix_vc_download`).\n" +
      "\n" +
      "★ HOW TO CALL: first turn, call with NO arguments (`{}`). The tool returns either the final VC or a `NEXT_STEP_REQUIRED` message listing exactly which claim fields to ask the user for. On the next turn, call again with `metadata` populated using the `key` names the tool listed. Never ask the user about templateId, keys, addresses, or configuration — those are preset.",
    inputSchema: {
      type: "object",
      properties: {
        metadata: {
          type: "object",
          description:
            "Optional. Claim values for the VC (one entry per required template field). " +
            "If you don't know the field names yet, omit this — the tool will call back with the list of required fields, their labels, and types. " +
            "Never ask the user what fields to include; let this tool tell you.",
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
        validUntil: { type: "string", description: "Validity end (`yyyy-MM-dd`). Defaults to one year from today when the user doesn't specify — only pass this if the user explicitly states a different expiry." },
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
        writeFile: {
          type: "boolean",
          description:
            "Whether to save the downloaded VC as a `.json` file to disk. Default: true. " +
            "Set to false if the caller doesn't want a local file (e.g. pure API clients).",
        },
        outputPath: {
          type: "string",
          description:
            "Optional exact file path for the saved VC (e.g. `~/Desktop/mykad.json`). If omitted, a filename is auto-derived and placed in `outputDir` (or the server's CWD).",
        },
        outputDir: {
          type: "string",
          description:
            "Optional directory to save the VC into (e.g. `~/Downloads`). If omitted, uses the configured default or the server's CWD. Ignored when `outputPath` is set.",
        },
      },
      required: [],
    },
  },

  // --------------------- VC: Apply (holder) ---------------------
  {
    name: "zetrix_vc_apply",
    description:
      "Apply for a VC **only** — creates a pending application without issuing. Returns a pending `vcId` in `APPLIED` status; the VC cannot be downloaded until the issuer separately processes the application.\n" +
      "\n" +
      "★ USE THIS when the user explicitly wants the apply step only, without issuance:\n" +
      "  • 'apply VC only, no need to issue'\n" +
      "  • 'just apply, don't issue yet'\n" +
      "  • 'create a VC application'\n" +
      "\n" +
      "★ DO NOT USE when the user says 'apply VC for me' without the 'only' / 'no issue' qualifier — they mean the full flow; use `zetrix_vc_request_credential` instead.",
    inputSchema: {
      type: "object",
      properties: {
        metadata: {
          type: "object",
          description:
            "Shortcut: claim values for a single-template apply. Omit to discover required fields (the tool will return NEXT_STEP_REQUIRED with the list).",
          additionalProperties: true,
        },
        data: {
          type: "array",
          description:
            "Advanced: multi-template apply. Prefer `metadata` for the common single-template case.",
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
        holderPrivateKey: {
          type: "string",
          description: "Optional per-call holder private key override. Usually omitted.",
        },
        holderPublicKey: {
          type: "string",
          description: "Optional per-call holder public key override. Usually omitted.",
        },
      },
      required: [],
    },
  },

  // --------------------- VC: Issue (issuer) ---------------------
  {
    name: "zetrix_vc_issue",
    description:
      "Issuer directly issues a VC to a specific holder DID or address. Returns the signed VC (includes `vc.id`). Does NOT download; if the holder wants the canonical VC later, they call `zetrix_vc_download` with the returned vcId.\n" +
      "\n" +
      "★ USE THIS when the user specifies a target recipient different from the configured holder:\n" +
      "  • 'issue VC to address A'\n" +
      "  • 'issue VC to did:zid:…'\n" +
      "  • 'issue to this holder: <address>'\n" +
      "  • 'issue VC but don't download' (any variant where they want issuance without download)\n" +
      "\n" +
      "★ DO NOT USE when the user just says 'issue me a VC' / 'issue VC for me' without specifying a recipient — that means 'issue to me and complete the flow'; use `zetrix_vc_request_credential` instead.",
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
        metadata: {
          type: "object",
          description:
            "Shortcut: claim values for a single-template issue. Omit to discover required fields (the tool will return NEXT_STEP_REQUIRED with the list).",
          additionalProperties: true,
        },
        data: {
          type: "array",
          description:
            "Advanced: multi-template issue. Prefer `metadata` for the common single-template case.",
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
        issuanceDate: {
          type: "string",
          description: "Optional issuance date (`yyyy-MM-dd`). Note: the BaaS preserves only validFrom/validUntil on issued VCs.",
        },
        expirationDate: {
          type: "string",
          description: "Optional expiration date (`yyyy-MM-dd`). See issuanceDate note.",
        },
        validFrom: { type: "string", description: "Optional validity start (`yyyy-MM-dd`)." },
        validUntil: { type: "string", description: "Validity end (`yyyy-MM-dd`). Defaults to one year from today when the user doesn't specify — only pass this if the user explicitly states a different expiry." },
        keyExpiry: { type: "number", description: "Optional key expiry override (default 0)." },
        issuerPrivateKey: {
          type: "string",
          description: "Optional per-call issuer private key override. Usually omitted.",
        },
      },
      required: [],
    },
  },

  // --------------------- VC: Download (holder) ---------------------
  {
    name: "zetrix_vc_download",
    description:
      "Download a VC that has already been issued, given its `vcId`. Returns the canonical signed W3C VC.\n" +
      "\n" +
      "★ USE THIS when the user wants to retrieve an already-issued VC:\n" +
      "  • 'download the VC for me' / 'download VC <vcId>'\n" +
      "  • 'fetch my VC'\n" +
      "  • 'get the VC for vcId …'\n" +
      "\n" +
      "★ Prerequisite: the VC must already be issued (not in the APPLIED/pending state). If the user asks for a brand-new credential, use `zetrix_vc_request_credential` instead — it runs apply → issue → download in one call.\n" +
      "\n" +
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
        writeFile: {
          type: "boolean",
          description: "Whether to save the downloaded VC as a `.json` file. Default: true.",
        },
        outputPath: {
          type: "string",
          description:
            "Optional exact file path for the saved VC (e.g. `~/Desktop/mykad.json`). If omitted, a filename is auto-derived and placed in `outputDir` (or the server's CWD).",
        },
        outputDir: {
          type: "string",
          description:
            "Optional directory to save the VC into (e.g. `~/Downloads`). If omitted, uses the configured default or the server's CWD. Ignored when `outputPath` is set.",
        },
      },
      required: ["vcId"],
    },
  },

  // --------------------- VP: Create (holder) ---------------------
  {
    name: "zetrix_vp_create",
    description:
      "⚙ LOW-LEVEL BUILDING BLOCK — returns only the unsigned VP blob. Use `zetrix_vp_present` for the full create → sign → submit flow that a user actually wants when they say 'create VP'. " +
      "Use `zetrix_vp_create` only when you're doing custom signing out-of-band and want just the blob.",
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
      "⚙ LOW-LEVEL BUILDING BLOCK — submits an already-signed VP blob. Use `zetrix_vp_present` for the full create → sign → submit flow that a user wants when they say 'create VP'. " +
      "Use `zetrix_vp_submit` only when the VP blob was signed out-of-band.",
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
      "End-to-end VP creation: create blob → sign locally → submit → (optional) cache and return a share uuid. Returns the signed W3C VerifiablePresentation.\n" +
      "\n" +
      "★ USE THIS when the user asks to create / present / make a VP:\n" +
      "  • 'create VP' / 'make a VP' / 'present my VC'\n" +
      "  • 'generate a VP revealing just my name'\n" +
      "  • 'share my VC with a verifier'\n" +
      "\n" +
      "★ You need: a `vc` (typically the one just issued via `zetrix_vc_request_credential`) and a `revealAttribute` list. " +
      "revealAttribute uses dotted paths like `id`, `mykad.name`, `mykad.icNo` (format: `<camelCaseTemplateName>.<field>`). Pass `[]` to reveal everything.\n" +
      "\n" +
      "★ Set `cache: true` to also get a short share uuid the user can send to a verifier.",
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
      "Verify a Verifiable Presentation. Returns whether the VP is valid (`isVerified`) plus the disclosed claims per VC (`vcDetail`).\n" +
      "\n" +
      "★ USE THIS when the user wants to verify a VP:\n" +
      "  • 'verify VP' / 'verify this VP'\n" +
      "  • 'verify VP uuid <id>' / 'verify VP by id' — pass `uuid`\n" +
      "  • 'verify this presentation' — pass `vp`\n" +
      "\n" +
      "★ Accepts EITHER:\n" +
      "  • `vp`: the signed VP object directly (JSON-LD), OR\n" +
      "  • `uuid`: a share-token returned by `zetrix_vp_cache` / `zetrix_vp_present(cache: true)` — the server looks up the cached VP and verifies it.\n" +
      "\n" +
      "Exactly one of `vp` / `uuid` is required.",
    inputSchema: {
      type: "object",
      properties: {
        vp: {
          type: "object",
          description: "Signed VerifiablePresentation to verify. Use this when you have the full VP object.",
          additionalProperties: true,
        },
        uuid: {
          type: "string",
          description:
            "Share uuid from a prior cache (e.g. returned by `zetrix_vp_cache` or `zetrix_vp_present(cache: true)`). " +
            "Use this when the verifier only has the share token, not the full VP.",
        },
        ed25519PubKey: {
          type: "string",
          description: "Optional — expected holder Ed25519 public key.",
        },
        bbsPublicKey: {
          type: "string",
          description: "Optional — expected holder BBS+ public key (for selective disclosure).",
        },
      },
      required: [],
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
          // Treat missing/null metadata as an empty object so the template
          // validation step runs and returns the helpful "required attributes"
          // error listing which fields to ask the user for.
          const rawMetadata = args.metadata;
          const metadata: Record<string, unknown> =
            rawMetadata && typeof rawMetadata === "object" && !Array.isArray(rawMetadata)
              ? (rawMetadata as Record<string, unknown>)
              : {};

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
                  .map((m) => `  - ${m.key}  (label: "${m.attribute}", format: ${m.format})`)
                  .join("\n");
                throw new Error(
                  `NEXT_STEP_REQUIRED: the "${templateName ?? templateId}" template needs these fields before I can issue the VC — ask the user for each value, then retry this tool with \`metadata\` populated using the \`key\` names on the left:\n\n` +
                    `${list}\n\n` +
                    `Example retry:\n` +
                    `  zetrix_vc_request_credential({ metadata: { ${missing.map((m) => `"${m.key}": "<value from user>"`).join(", ")} } })`
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
          // Default validUntil to +1 year when the caller doesn't supply one
          // — VCs without a validity end aren't useful in practice, and the
          // BaaS accepts yyyy-MM-dd format.
          const resolvedValidUntil = pick(args.validUntil as string | undefined) ?? defaultValidUntil();
          const issueResp = await vcClient.issueVc({
            data,
            holderDid,
            issuerPrivateKey,
            issuanceDate: args.issuanceDate as string | undefined,
            expirationDate: args.expirationDate as string | undefined,
            validFrom: args.validFrom as string | undefined,
            validUntil: resolvedValidUntil,
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

          // The BaaS has eventual consistency between issue and download —
          // right after issue returns 200, the VC may not yet be visible to
          // the download endpoint ("The VC application has not been issued
          // yet"). Retry with backoff to absorb that race.
          const downloadWithRetry = async () => {
            const attempts = [0, 500, 1500, 3500, 7000]; // ms between attempts (total ~12.5s)
            let lastErr: unknown = null;
            for (let i = 0; i < attempts.length; i++) {
              if (attempts[i] > 0) await new Promise((r) => setTimeout(r, attempts[i]));
              try {
                return await vcClient.downloadVc({ vcId: applyResp.vcId, signVcId: dlSig });
              } catch (err) {
                lastErr = err;
                const msg = err instanceof Error ? err.message : String(err);
                // Only retry on the specific eventual-consistency error.
                if (!msg.includes("not been issued yet") && !msg.includes("VC_RECORD_NOT_EXIST")) {
                  throw err;
                }
                // Otherwise, fall through and try again.
              }
            }
            throw lastErr;
          };

          try {
            const downloadResp = await downloadWithRetry();
            // Write the VC to a local JSON file for the user to download /
            // see in their filesystem.
            let fileSaved: string | null = null;
            let fileSaveError: string | null = null;
            if (args.writeFile !== false) {
              try {
                fileSaved = await writeVcToFile(
                  downloadResp.vc as unknown as Record<string, unknown>,
                  {
                    outputPath: args.outputPath as string | undefined,
                    outputDir: args.outputDir as string | undefined,
                  }
                );
              } catch (e) {
                fileSaveError = e instanceof Error ? e.message : String(e);
              }
            }
            return toTextResult({
              templateId,
              templateName,
              holderDid,
              apply: applyResp,
              vc: downloadResp.vc,
              vcPassBase64: downloadResp.vcPassBase64,
              downloadExpiryDate: downloadResp.downloadExpiryDate,
              fileSaved,
              ...(fileSaveError ? { fileSaveError } : {}),
            });
          } catch (downloadErr) {
            // Download still failed after all retries — surface the VC from
            // the issue step so the caller has something usable.
            const msg = downloadErr instanceof Error ? downloadErr.message : String(downloadErr);
            let fileSaved: string | null = null;
            if (args.writeFile !== false) {
              try {
                fileSaved = await writeVcToFile(
                  issueResp.vc as unknown as Record<string, unknown>,
                  {
                    outputPath: args.outputPath as string | undefined,
                    outputDir: args.outputDir as string | undefined,
                  }
                );
              } catch { /* ignore — non-fatal */ }
            }
            return toTextResult({
              templateId,
              templateName,
              holderDid,
              apply: applyResp,
              vc: issueResp.vc,
              vcPassBase64: issueResp.vcPassBase64,
              downloadExpiryDate: issueResp.downloadExpiryDate,
              fileSaved,
              warning: `Download step failed even after retries; returning VC from the issue step instead. Download error: ${msg}`,
            });
          }
        }

        case "zetrix_vc_apply": {
          // If called with no data, synthesise a single-item array from the
          // default template so the template-field discovery still works.
          const rawData = Array.isArray(args.data) && args.data.length > 0
            ? (args.data as TemplateMetadataDto[])
            : ([{ metadata: (args.metadata as Record<string, unknown>) ?? {} }] as TemplateMetadataDto[]);
          const data = applyDefaultTemplateId(rawData);
          // Discover required fields when metadata is empty — same pattern as
          // zetrix_vc_request_credential, so the agent can probe.
          const firstMetadata = data[0]?.metadata ?? {};
          if (Object.keys(firstMetadata).length === 0) {
            const tdsAddr = pick(TDS_CONTRACT_ADDRESS);
            if (tdsAddr) {
              try {
                const template = await nodeClient.getTemplateDetail(tdsAddr, data[0].templateId);
                const info = extractTemplateInfo(template.value);
                if (info) {
                  const missing = findMissingRequiredAttributes(firstMetadata, info);
                  if (missing.length > 0) {
                    const list = missing
                      .map((m) => `  - ${m.key}  (label: "${m.attribute}", format: ${m.format})`)
                      .join("\n");
                    throw new Error(
                      `NEXT_STEP_REQUIRED: the "${info.templateName ?? data[0].templateId}" template needs these fields before I can apply for the VC — ask the user for each value, then retry with \`data: [{ metadata: {...} }]\`:\n\n` +
                        `${list}\n\n` +
                        `Example retry:\n` +
                        `  zetrix_vc_apply({ data: [{ metadata: { ${missing.map((m) => `"${m.key}": "<value from user>"`).join(", ")} } }] })`
                    );
                  }
                }
              } catch (e) {
                // If probing fails (e.g. network), fall through; the BaaS will
                // reject an empty metadata and we'll surface that error.
                if (e instanceof Error && e.message.startsWith("NEXT_STEP_REQUIRED")) throw e;
              }
            }
          }
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

          // Accept either the shortcut `metadata` (single-template issue) or
          // the advanced `data` array (multi-template).
          const rawData = Array.isArray(args.data) && args.data.length > 0
            ? (args.data as TemplateMetadataDto[])
            : ([{ metadata: (args.metadata as Record<string, unknown>) ?? {} }] as TemplateMetadataDto[]);
          const data = applyDefaultTemplateId(rawData);

          // Discover required template fields if metadata is empty.
          const firstMetadata = data[0]?.metadata ?? {};
          if (Object.keys(firstMetadata).length === 0) {
            const tdsAddr = pick(TDS_CONTRACT_ADDRESS);
            if (tdsAddr) {
              try {
                const template = await nodeClient.getTemplateDetail(tdsAddr, data[0].templateId);
                const info = extractTemplateInfo(template.value);
                if (info) {
                  const missing = findMissingRequiredAttributes(firstMetadata, info);
                  if (missing.length > 0) {
                    const list = missing
                      .map((m) => `  - ${m.key}  (label: "${m.attribute}", format: ${m.format})`)
                      .join("\n");
                    throw new Error(
                      `NEXT_STEP_REQUIRED: the "${info.templateName ?? data[0].templateId}" template needs these fields before I can issue the VC — ask the user for each value, then retry with \`metadata\` populated:\n\n` +
                        `${list}\n\n` +
                        `Example retry:\n` +
                        `  zetrix_vc_issue({ holderDid: "${holderDid}", metadata: { ${missing.map((m) => `"${m.key}": "<value from user>"`).join(", ")} } })`
                    );
                  }
                }
              } catch (e) {
                if (e instanceof Error && e.message.startsWith("NEXT_STEP_REQUIRED")) throw e;
              }
            }
          }

          const issuerPrivateKey = requireEnv(
            ISSUER_PRIVATE_KEY,
            "ISSUER_PRIVATE_KEY",
            args.issuerPrivateKey as string | undefined
          );
          // Default validUntil to +1 year when not supplied by the caller.
          const resolvedValidUntil = pick(args.validUntil as string | undefined) ?? defaultValidUntil();
          const resp = await vcClient.issueVc({
            holderDid,
            data,
            issuerPrivateKey,
            issuanceDate: args.issuanceDate as string | undefined,
            expirationDate: args.expirationDate as string | undefined,
            validFrom: args.validFrom as string | undefined,
            validUntil: resolvedValidUntil,
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

          // Write the downloaded VC to disk unless explicitly disabled.
          // UI clients (Claude Desktop etc.) can let the user click the path;
          // CLI users just see the file in their cwd.
          let savedPath: string | null = null;
          if (args.writeFile !== false) {
            try {
              savedPath = await writeVcToFile(resp.vc as unknown as Record<string, unknown>, {
                outputPath: args.outputPath as string | undefined,
                outputDir: args.outputDir as string | undefined,
              });
            } catch (e) {
              // File write failure is non-fatal — still return the VC in-band.
              savedPath = null;
              return toTextResult({
                ...resp,
                fileSaved: null,
                fileSaveError: e instanceof Error ? e.message : String(e),
              });
            }
          }
          return toTextResult({ ...resp, fileSaved: savedPath });
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
          const uuid = pick(args.uuid as string | undefined);

          if (!vp && !uuid) {
            throw new Error("Provide either `vp` (the VP object) or `uuid` (a share token from vp_cache).");
          }
          if (vp && uuid) {
            throw new Error("Provide exactly one of `vp` or `uuid`, not both.");
          }

          const resp = uuid
            ? await vcClient.verifyVpByUuid(uuid)
            : await vcClient.verifyVp({
                vp: vp as VerifiablePresentation,
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
