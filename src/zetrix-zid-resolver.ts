/**
 * HTTP client for the Zetrix ZID (DID) Resolver.
 *
 *   UAT:  https://zid-resolver-sandbox.zetrix.com
 *   Prod: https://zid-resolver.zetrix.com
 *
 * Endpoint:
 *   GET /1.0/identifiers/<did>
 *
 * Follows the W3C DID Resolution spec — the response includes the
 * `didDocument` (with `verificationMethod`, `service`, and any permissions
 * the DID exposes) plus `didResolutionMetadata` / `didDocumentMetadata`.
 *
 * Auth: goes through the same AWS API Gateway as the BaaS API, so the
 * `x-api-key` header and (optionally) `Authorization: Bearer <baasKey>` apply.
 */

import axios, { AxiosInstance, AxiosError } from "axios";
import type { ZetrixVcNetwork } from "./zetrix-vc-client.js";

export const ZETRIX_ZID_RESOLVER_BASE_URLS: Record<ZetrixVcNetwork, string> = {
  uat: "https://zid-resolver-sandbox.zetrix.com",
  prod: "https://zid-resolver.zetrix.com",
};

export interface ZetrixZidResolverOptions {
  /** Explicit base URL override; takes precedence over `network`. */
  baseUrl?: string;
  network?: ZetrixVcNetwork;
  /** AWS API Gateway key, sent as `x-api-key`. */
  awsApiKey?: string;
  /** Zetrix BaaS API key, sent as `Authorization: Bearer <key>`. */
  baasApiKey?: string;
  timeoutMs?: number;
}

export class ZetrixZidResolver {
  private readonly http: AxiosInstance;
  public readonly baseUrl: string;
  public readonly network: ZetrixVcNetwork | "custom";

  constructor(opts: ZetrixZidResolverOptions = {}) {
    const network = opts.network ?? "uat";
    const baseUrl = opts.baseUrl ?? ZETRIX_ZID_RESOLVER_BASE_URLS[network];
    this.baseUrl = baseUrl;
    this.network = opts.baseUrl ? "custom" : network;

    const headers: Record<string, string> = {
      Accept: "application/json, application/did+ld+json",
    };
    if (opts.awsApiKey) headers["x-api-key"] = opts.awsApiKey;
    if (opts.baasApiKey) headers["Authorization"] = `Bearer ${opts.baasApiKey}`;

    this.http = axios.create({
      baseURL: baseUrl,
      timeout: opts.timeoutMs ?? 30000,
      headers,
      validateStatus: () => true,
    });
  }

  /**
   * GET /1.0/identifiers/<did>
   *
   * Returns the DID Resolution Result (per https://www.w3.org/TR/did-resolution/).
   * Common top-level keys: `didResolutionMetadata`, `didDocument`,
   * `didDocumentMetadata`. The `didDocument` contains the verification methods,
   * service endpoints and permissions exposed by the DID.
   */
  async resolve(did: string): Promise<unknown> {
    if (!did || typeof did !== "string") {
      throw new Error("`did` must be a non-empty string.");
    }
    if (!did.startsWith("did:")) {
      throw new Error(`Expected a DID starting with 'did:', got "${did}".`);
    }

    const path = `/1.0/identifiers/${encodeURIComponent(did)}`;
    try {
      const resp = await this.http.get(path);
      if (resp.status < 200 || resp.status >= 300) {
        const snippet = typeof resp.data === "string"
          ? resp.data.slice(0, 500)
          : JSON.stringify(resp.data).slice(0, 500);
        throw new Error(
          `Zetrix ZID resolver ${path} failed (HTTP ${resp.status}): ${snippet}`
        );
      }
      return resp.data;
    } catch (err) {
      if (err instanceof Error) {
        const axErr = err as AxiosError;
        if (axErr.isAxiosError && axErr.response) {
          throw new Error(
            `Zetrix ZID resolver ${path} HTTP ${axErr.response.status}: ${safeStringify(axErr.response.data)}`
          );
        }
        throw err;
      }
      throw new Error(String(err));
    }
  }
}

function safeStringify(v: unknown): string {
  try {
    return typeof v === "string" ? v : JSON.stringify(v);
  } catch {
    return String(v);
  }
}
