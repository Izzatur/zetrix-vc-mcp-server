/**
 * Thin HTTP client for the Zetrix public node RPC.
 *
 * Used to resolve on-chain template / revocation contract metadata.
 *
 *   UAT:  https://test-node.zetrix.com
 *   Prod: https://node.zetrix.com
 *
 * Only the endpoints needed by the VC flows are wrapped here
 * (currently just `/getAccountMetaData`).
 */

import axios, { AxiosInstance, AxiosError } from "axios";
import type { ZetrixVcNetwork } from "./zetrix-vc-client.js";

export const ZETRIX_NODE_BASE_URLS: Record<ZetrixVcNetwork, string> = {
  uat: "https://test-node.zetrix.com",
  prod: "https://node.zetrix.com",
};

export interface ZetrixNodeClientOptions {
  /** Explicit base URL (e.g. http://localhost:19333). Takes precedence over `network`. */
  baseUrl?: string;
  network?: ZetrixVcNetwork;
  timeoutMs?: number;
}

export interface ZetrixAccountMetadataEntry {
  key: string;
  value: string;
  version?: number;
}

/**
 * Raw `getAccountMetaData` response shape.
 *
 * Zetrix returns `result` as an object keyed by the requested metadata key
 * (e.g. `result["template__did:zid:..."] = { key, value, version }`), rather
 * than a `metadatas[]` array. We expose that as `Record<key, entry>`.
 */
export type GetAccountMetaDataResult = Record<string, ZetrixAccountMetadataEntry>;

export interface TemplateDetailResult {
  address: string;
  key: string;
  templateId: string;
  /** Raw `value` string returned by the node. */
  rawValue: string | null;
  /** `rawValue` parsed as JSON when possible; otherwise `null`. */
  value: unknown;
  version?: number;
  found: boolean;
}

export class ZetrixNodeClient {
  private readonly http: AxiosInstance;
  public readonly baseUrl: string;
  public readonly network: ZetrixVcNetwork | "custom";

  constructor(opts: ZetrixNodeClientOptions = {}) {
    const network = opts.network ?? "uat";
    const baseUrl = opts.baseUrl ?? ZETRIX_NODE_BASE_URLS[network];
    this.baseUrl = baseUrl;
    this.network = opts.baseUrl ? "custom" : network;

    this.http = axios.create({
      baseURL: baseUrl,
      timeout: opts.timeoutMs ?? 30000,
      headers: { Accept: "application/json" },
      validateStatus: () => true,
    });
  }

  /**
   * GET /getAccountMetaData?address=<addr>&key=<key>
   *
   * Returns the full `result` object (normally contains `metadatas[]`). Throws
   * when the node returns a non-zero `error_code`.
   */
  async getAccountMetaData(address: string, key: string): Promise<GetAccountMetaDataResult> {
    try {
      const resp = await this.http.get("/getAccountMetaData", {
        params: { address, key },
      });
      const data = resp.data;
      if (resp.status < 200 || resp.status >= 300) {
        throw new Error(
          `Zetrix node /getAccountMetaData HTTP ${resp.status}: ${safeStringify(data)}`
        );
      }
      if (data && typeof data === "object" && data.error_code !== undefined && data.error_code !== 0) {
        throw new Error(
          `Zetrix node /getAccountMetaData error_code=${data.error_code}: ${data.error_desc ?? "(no description)"}`
        );
      }
      return (data?.result ?? {}) as GetAccountMetaDataResult;
    } catch (err) {
      if (err instanceof Error) {
        const axErr = err as AxiosError;
        if (axErr.isAxiosError && axErr.response) {
          throw new Error(
            `Zetrix node /getAccountMetaData HTTP ${axErr.response.status}: ${safeStringify(axErr.response.data)}`
          );
        }
        throw err;
      }
      throw new Error(String(err));
    }
  }

  /**
   * Look up a VC template by id from the Template Data Store (TDS) contract.
   *
   * Queries `/getAccountMetaData?address=<tdsContract>&key=template__<templateId>`
   * and returns the decoded value.
   */
  async getTemplateDetail(
    tdsContractAddress: string,
    templateId: string
  ): Promise<TemplateDetailResult> {
    const key = `template__${templateId}`;
    const result = await this.getAccountMetaData(tdsContractAddress, key);
    const entry = result[key];
    const rawValue = entry?.value ?? null;
    return {
      address: tdsContractAddress,
      key,
      templateId,
      rawValue,
      value: deepParseJson(rawValue),
      version: entry?.version,
      found: !!entry,
    };
  }
}

/**
 * Parse `value` as JSON and recursively unwrap any nested JSON-in-string fields
 * (the TDS contract stores `applyFormat` and `metadata` as JSON-encoded strings
 * inside the outer JSON object).
 */
function deepParseJson(v: string | null): unknown {
  if (v == null) return null;
  try {
    return unwrapNestedJson(JSON.parse(v));
  } catch {
    return null;
  }
}

function unwrapNestedJson(input: unknown): unknown {
  if (typeof input === "string") {
    // Only try to parse strings that look like JSON objects/arrays.
    const trimmed = input.trim();
    if (
      (trimmed.startsWith("{") && trimmed.endsWith("}")) ||
      (trimmed.startsWith("[") && trimmed.endsWith("]"))
    ) {
      try {
        return unwrapNestedJson(JSON.parse(trimmed));
      } catch {
        return input;
      }
    }
    return input;
  }
  if (Array.isArray(input)) return input.map(unwrapNestedJson);
  if (input && typeof input === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(input as Record<string, unknown>)) {
      out[k] = unwrapNestedJson(val);
    }
    return out;
  }
  return input;
}

function safeStringify(v: unknown): string {
  try {
    return typeof v === "string" ? v : JSON.stringify(v);
  } catch {
    return String(v);
  }
}
