/**
 * HTTP client for the Zetrix BaaS Verifiable Credentials / Presentations API.
 *
 * Endpoints follow VC_VP_API_REFERENCE.md (myeg-ms-credential service routed
 * through the Zetrix BaaS gateway):
 *
 *   POST /v1/vc/apply       — Holder applies for a VC
 *   POST /v1/vc/issue       — Issuer issues a VC directly to a holder DID
 *   POST /v1/vc/download    — Holder downloads an issued VC
 *   POST /v1/vp/create      — Holder creates a VP blob (pre-sign)
 *   POST /v1/vp/submit      — Holder submits the signed VP blob
 *   POST /v1/vp/cache       — Holder caches a signed VP, receives share uuid
 *   POST /v1/vp/verify      — Verifier validates a VP
 *
 * Authentication:
 *   - AWS API Gateway key — sent as `x-api-key`
 *   - Zetrix BaaS API key — sent as `Authorization: Bearer <key>`
 */

import axios, { AxiosInstance, AxiosError } from "axios";

export type ZetrixVcNetwork = "uat" | "prod";

export const ZETRIX_VC_BASE_URLS: Record<ZetrixVcNetwork, string> = {
  uat: "https://api-sandbox.zetrix.com",
  prod: "https://api.zetrix.com",
};

export interface ZetrixVcClientOptions {
  /** "uat" | "prod", or an explicit base URL. Takes precedence over `network`. */
  baseUrl?: string;
  network?: ZetrixVcNetwork;
  /** AWS API Gateway key, sent as `x-api-key`. */
  awsApiKey?: string;
  /** Zetrix BaaS API key / bearer token, sent as `Authorization: Bearer <key>`. */
  baasApiKey?: string;
  /** Timeout in milliseconds for each request. */
  timeoutMs?: number;
}

export interface ResponseWrapper<T> {
  object: T;
  success: boolean;
  timestamp?: string;
  messages?: Array<{ code?: string | number; message?: string } | string>;
  httpStatus?: string;
}

// ----- Request / Response DTOs (mirroring VC_VP_API_REFERENCE.md) -----

export interface TemplateMetadataDto {
  templateId: string;
  passDesignId?: string;
  metadata: Record<string, unknown>;
  tds?: string;
}

export interface ApplyVcReqDto {
  data: TemplateMetadataDto[];
  signData: string;
  publicKey: string;
}

export interface ApplyVcRespDto {
  vcId: string;
  status: string;
}

export interface IssueDirectVcReqDto {
  issuanceDate?: string;
  expirationDate?: string;
  validFrom?: string;
  validUntil?: string;
  data: TemplateMetadataDto[];
  issuerPrivateKey: string;
  keyExpiry?: number;
  holderDid: string;
}

export interface VerifiableCredential {
  "@context": string[];
  id: string;
  type: string[];
  issuer: string;
  issuanceDate?: string;
  expirationDate?: string;
  validFrom?: string;
  validUntil?: string;
  credentialSubject: Record<string, unknown>;
  proof?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface SubmitVcRespDto {
  vc: VerifiableCredential;
  vcPassBase64?: string[];
  downloadExpiryDate?: string;
}

export interface DownloadVcReqDto {
  vcId: string;
  signVcId: string;
  isIssuer?: boolean;
}

export interface RangeProofDto {
  attribute?: string;
  min?: number;
  max?: number;
  [key: string]: unknown;
}

export interface CreateVpReqDto {
  vc: VerifiableCredential;
  revealAttribute?: string[];
  rangeProof?: RangeProofDto;
  bbsPublicKey?: string;
  ed25519PubKey?: string;
}

export interface CreateVpRespDto {
  blobId: string;
  blob: string;
}

export interface SubmitVpReqDto {
  blobId: string;
  ed25519SignData: string;
  ed25519PubKey: string;
}

export interface VerifiablePresentation {
  "@context": string[];
  type: string[];
  verifiableCredential: VerifiableCredential[];
  proof?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface CacheVpReqDto {
  vp: VerifiablePresentation;
}

export interface CacheVpRespDto {
  uuid: string;
}

export interface VerifyVpReqDto {
  vp: VerifiablePresentation;
  ed25519PubKey?: string;
  bbsPublicKey?: string;
}

export interface VcDetail {
  id: string;
  issuer: string;
  issuanceDate?: string;
  expirationDate?: string;
  validFrom?: string;
  validUntil?: string;
  credentialSubject: Record<string, unknown>;
}

export interface VerifyVpRespDto {
  isVerified: boolean;
  errMsg?: string | null;
  vcDetail?: VcDetail[];
}

// ----- Client -----

export class ZetrixVcClient {
  private readonly http: AxiosInstance;
  public readonly baseUrl: string;
  public readonly network: ZetrixVcNetwork | "custom";

  constructor(opts: ZetrixVcClientOptions = {}) {
    const network = opts.network ?? "uat";
    const baseUrl = opts.baseUrl ?? ZETRIX_VC_BASE_URLS[network];
    this.baseUrl = baseUrl;
    this.network = opts.baseUrl ? "custom" : network;

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json",
    };
    if (opts.awsApiKey) headers["x-api-key"] = opts.awsApiKey;
    if (opts.baasApiKey) headers["Authorization"] = `Bearer ${opts.baasApiKey}`;

    this.http = axios.create({
      baseURL: baseUrl,
      timeout: opts.timeoutMs ?? 30000,
      headers,
      // Don't throw on non-2xx — we surface the ResponseWrapper.messages instead.
      validateStatus: () => true,
    });
  }

  /** POST /v1/vc/apply */
  async applyVc(req: ApplyVcReqDto): Promise<ApplyVcRespDto> {
    return this.post<ApplyVcRespDto>("/v1/vc/apply", req);
  }

  /** POST /v1/vc/issue */
  async issueVc(req: IssueDirectVcReqDto): Promise<SubmitVcRespDto> {
    return this.post<SubmitVcRespDto>("/v1/vc/issue", req);
  }

  /** POST /v1/vc/download */
  async downloadVc(req: DownloadVcReqDto): Promise<SubmitVcRespDto> {
    return this.post<SubmitVcRespDto>("/v1/vc/download", req);
  }

  /** POST /v1/vp/create */
  async createVp(req: CreateVpReqDto): Promise<CreateVpRespDto> {
    return this.post<CreateVpRespDto>("/v1/vp/create", req);
  }

  /** POST /v1/vp/submit */
  async submitVp(req: SubmitVpReqDto): Promise<VerifiablePresentation> {
    return this.post<VerifiablePresentation>("/v1/vp/submit", req);
  }

  /** POST /v1/vp/cache */
  async cacheVp(req: CacheVpReqDto): Promise<CacheVpRespDto> {
    return this.post<CacheVpRespDto>("/v1/vp/cache", req);
  }

  /** POST /v1/vp/verify */
  async verifyVp(req: VerifyVpReqDto): Promise<VerifyVpRespDto> {
    return this.post<VerifyVpRespDto>("/v1/vp/verify", req);
  }

  // ----- internals -----

  private async post<T>(path: string, body: unknown): Promise<T> {
    try {
      const resp = await this.http.post(path, body);
      return this.unwrap<T>(path, resp.status, resp.data);
    } catch (err) {
      throw this.normaliseError(path, err);
    }
  }

  private unwrap<T>(path: string, status: number, data: unknown): T {
    // BaaS responses are ResponseWrapper<T>. If `success === false`, surface
    // the error messages; otherwise return `.object`.
    if (data && typeof data === "object" && "success" in (data as Record<string, unknown>)) {
      const w = data as ResponseWrapper<T>;
      if (w.success === false) {
        const msg = formatMessages(w.messages);
        throw new Error(
          `Zetrix BaaS ${path} failed (HTTP ${status}, httpStatus=${w.httpStatus ?? "?"}): ${msg}`
        );
      }
      return w.object as T;
    }

    // Not wrapped — if HTTP is OK, return raw body; otherwise raise.
    if (status >= 200 && status < 300) {
      return data as T;
    }
    throw new Error(
      `Zetrix BaaS ${path} failed (HTTP ${status}): ${safeStringify(data)}`
    );
  }

  private normaliseError(path: string, err: unknown): Error {
    if (err instanceof Error) {
      const axErr = err as AxiosError;
      if (axErr.isAxiosError && axErr.response) {
        return new Error(
          `Zetrix BaaS ${path} HTTP ${axErr.response.status}: ${safeStringify(axErr.response.data)}`
        );
      }
      return err;
    }
    return new Error(String(err));
  }
}

function formatMessages(
  messages: ResponseWrapper<unknown>["messages"]
): string {
  if (!messages || messages.length === 0) return "no message";
  return messages
    .map((m) => {
      if (typeof m === "string") return m;
      const code = m.code != null ? `[${m.code}] ` : "";
      return `${code}${m.message ?? JSON.stringify(m)}`;
    })
    .join("; ");
}

function safeStringify(v: unknown): string {
  try {
    return typeof v === "string" ? v : JSON.stringify(v);
  } catch {
    return String(v);
  }
}
