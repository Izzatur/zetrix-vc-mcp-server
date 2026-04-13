/**
 * HTTP client for the Zetrix BaaS Verifiable Credentials / Presentations API.
 *
 * Endpoints are routed through the Zetrix BaaS gateway under the `/cred/v1/`
 * prefix (the gateway dispatches to the myeg-ms-credential service internally):
 *
 *   POST /cred/v1/vc/apply       — Holder applies for a VC
 *   POST /cred/v1/vc/issue       — Issuer issues a VC directly to a holder DID
 *   POST /cred/v1/vc/download    — Holder downloads an issued VC
 *   POST /cred/v1/vp/create      — Holder creates a VP blob (pre-sign)
 *   POST /cred/v1/vp/submit      — Holder submits the signed VP blob
 *   POST /cred/v1/vp/cache       — Holder caches a signed VP, receives share uuid
 *   POST /cred/v1/vp/verify      — Verifier validates a VP
 *
 * Note: the local myeg-ms-credential service paths are `/v1/vc/*` and
 * `/v1/vp/*`; the public gateway exposes them under `/cred/v1/*`.
 * Customers always use the `/cred/v1/*` form.
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

// ----- Request / Response DTOs (mirroring the BaaS API contract) -----

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
  /** Actual field returned by the server (some docs call it `isVerified`
   *  but the wire format is `verified`). */
  verified?: boolean;
  /** Back-compat alias — populated from `verified` when present. */
  isVerified?: boolean;
  errMsg?: string | null;
  vcDetail?: VcDetail[] | null;
}

// ----- Full Flow 1 (apply → create → bbs-sign → submit → download) -----

export interface CreateVcReqDto {
  vcId: string;
  issuanceDate?: string;
  expirationDate?: string;
  validFrom?: string;
  validUntil?: string;
  data: TemplateMetadataDto[];
}

/** `/cred/v1/vc/create` response — includes the canonical statements to feed
 *  into BBS+ sign plus the Ed25519 blob to sign. Actual shape observed from
 *  Flow 1 usage; wrapped in `ResponseWrapper` by the server. */
export interface CreateVcRespDto {
  vcId?: string;
  ed25519Blob?: string;             // hex of the JWT/protobuf blob to sign
  bbsBlsBase64?: string[];          // canonicalized statements for BBS+ sign
  [key: string]: unknown;
}

export interface SignBbsReqDto {
  publicKeyMultibase: string;
  privateKeyMultibase: string;
  data: string[];                    // base64 statements
}

export interface SignBbsRespDto {
  signData: string;                  // BBS+ signature
  [key: string]: unknown;
}

export interface SubmitVcFromCreateReqDto {
  vcId: string;
  ed25519PubKey: string;
  ed25519SignData: string;
  bbsBlsPubKey: string;
  bbsBlsSignData: string;
  keyExpiry?: number;
}

// ----- Revocation Flow 3 -----

export interface RevokeCreateBlobReqDto {
  vcId: string;
  remark?: string;
  issuerAddress: string;
}

export interface RevokeCreateBlobRespDto {
  blobId: string;
  blob?: string;                     // hex blob (aliased as ed25519Blob on some versions)
  ed25519Blob?: string;
  [key: string]: unknown;
}

export interface RevokeSignerEntry {
  signBlob: string;
  publicKey: string;
}

export interface RevokeSubmitReqDto {
  blobId: string;
  signerList: RevokeSignerEntry[];
}

export interface RevokeStatusReqDto {
  vcId: string;
  issuer: string;                    // issuer Zetrix address (ZTX3…)
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

  /** POST /cred/v1/vc/apply */
  async applyVc(req: ApplyVcReqDto): Promise<ApplyVcRespDto> {
    return this.post<ApplyVcRespDto>("/cred/v1/vc/apply", req);
  }

  /** POST /cred/v1/vc/issue */
  async issueVc(req: IssueDirectVcReqDto): Promise<SubmitVcRespDto> {
    return this.post<SubmitVcRespDto>("/cred/v1/vc/issue", req);
  }

  /** POST /cred/v1/vc/download */
  async downloadVc(req: DownloadVcReqDto): Promise<SubmitVcRespDto> {
    return this.post<SubmitVcRespDto>("/cred/v1/vc/download", req);
  }

  /** POST /cred/v1/vp/create */
  async createVp(req: CreateVpReqDto): Promise<CreateVpRespDto> {
    return this.post<CreateVpRespDto>("/cred/v1/vp/create", req);
  }

  /** POST /cred/v1/vp/submit */
  async submitVp(req: SubmitVpReqDto): Promise<VerifiablePresentation> {
    return this.post<VerifiablePresentation>("/cred/v1/vp/submit", req);
  }

  /** POST /cred/v1/vp/cache */
  async cacheVp(req: CacheVpReqDto): Promise<CacheVpRespDto> {
    return this.post<CacheVpRespDto>("/cred/v1/vp/cache", req);
  }

  /** POST /cred/v1/vp/verify */
  async verifyVp(req: VerifyVpReqDto): Promise<VerifyVpRespDto> {
    return this.post<VerifyVpRespDto>("/cred/v1/vp/verify", req);
  }

  /**
   * GET /cred/v1/vp/verify?id=<uuid>
   * Back-compat verify using the cache uuid from a prior `/cred/v1/vp/cache`.
   */
  async verifyVpByUuid(uuid: string): Promise<VerifyVpRespDto> {
    try {
      const resp = await this.http.get("/cred/v1/vp/verify", { params: { id: uuid } });
      return this.unwrap<VerifyVpRespDto>("/cred/v1/vp/verify", resp.status, resp.data);
    } catch (err) {
      throw this.normaliseError("/cred/v1/vp/verify", err);
    }
  }

  // --- Full Flow 1 (create / bbs-sign / submit) ---

  /** POST /cred/v1/vc/create — step 3 of the full Flow 1 VC issuance. */
  async createVc(req: CreateVcReqDto): Promise<CreateVcRespDto> {
    return this.post<CreateVcRespDto>("/cred/v1/vc/create", req);
  }

  /** POST /cred/bbs/vc/sign — step 4 of Flow 1, signs with issuer BBS+ key. */
  async signVcBbs(req: SignBbsReqDto): Promise<SignBbsRespDto> {
    return this.post<SignBbsRespDto>("/cred/bbs/vc/sign", req);
  }

  /** POST /cred/v1/vc/submit — step 6 of Flow 1, submits both signatures. */
  async submitVc(req: SubmitVcFromCreateReqDto): Promise<unknown> {
    return this.post<unknown>("/cred/v1/vc/submit", req);
  }

  // --- Revocation Flow 3 ---

  /** POST /cred/v1/vc/revoke/create-blob — returns a hex blob for the issuer to sign. */
  async revokeCreateBlob(req: RevokeCreateBlobReqDto): Promise<RevokeCreateBlobRespDto> {
    return this.post<RevokeCreateBlobRespDto>("/cred/v1/vc/revoke/create-blob", req);
  }

  /** POST /cred/v1/vc/revoke/submit — submits the signed revocation. */
  async revokeSubmit(req: RevokeSubmitReqDto): Promise<unknown> {
    return this.post<unknown>("/cred/v1/vc/revoke/submit", req);
  }

  /** POST /cred/v1/vc/revoke/status — query current revocation status for a vcId. */
  async revokeStatus(req: RevokeStatusReqDto): Promise<unknown> {
    return this.post<unknown>("/cred/v1/vc/revoke/status", req);
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
    // BaaS responses come in a ResponseWrapper shape but the exact fields
    // present vary:
    //   - Error responses:    { messages: [...], httpStatus, success?: false }
    //   - Success responses:  { object: { ... } }   ← no `success` field
    // So we don't rely on `success` — we unwrap whenever `object` is present
    // on a 2xx response, and treat `messages` as an error otherwise.
    if (data && typeof data === "object") {
      const w = data as ResponseWrapper<T> & Record<string, unknown>;

      if (w.success === false) {
        throw new Error(
          `Zetrix BaaS ${path} failed (HTTP ${status}, httpStatus=${w.httpStatus ?? "?"}): ${formatMessages(w.messages)}`
        );
      }

      // Error response without explicit success flag — detect by messages.
      if (
        (status < 200 || status >= 300) &&
        Array.isArray(w.messages) &&
        w.messages.length > 0
      ) {
        throw new Error(
          `Zetrix BaaS ${path} failed (HTTP ${status}): ${formatMessages(w.messages)}`
        );
      }

      // Success: unwrap `object` when present.
      if ("object" in w) {
        return w.object as T;
      }
    }

    // Not wrapped — if HTTP is OK, return raw body; otherwise raise.
    if (status >= 200 && status < 300) {
      return data as T;
    }
    throw new Error(
      `Zetrix BaaS ${path} failed (HTTP ${status}): ${summariseError(data)}`
    );
  }

  private normaliseError(path: string, err: unknown): Error {
    if (err instanceof Error) {
      const axErr = err as AxiosError;
      if (axErr.isAxiosError && axErr.response) {
        return new Error(
          `Zetrix BaaS ${path} HTTP ${axErr.response.status}: ${summariseError(axErr.response.data)}`
        );
      }
      return err;
    }
    return new Error(String(err));
  }
}

/**
 * Produce a short, human-readable summary from a response body. Detects the
 * Cloudflare JS-challenge HTML and returns an actionable hint instead of
 * dumping 500+ chars of raw markup into the error message.
 */
function summariseError(data: unknown): string {
  if (typeof data === "string") {
    const lower = data.toLowerCase();
    if (lower.includes("just a moment") || lower.includes("cf-mitigated")) {
      return (
        "blocked by Cloudflare (JS challenge). Verify AWS_GATEWAY_API_KEY / BAAS_API_KEY " +
          "are set and that your source IP / region isn't blocked by the gateway WAF."
      );
    }
    return data.slice(0, 500);
  }
  return safeStringify(data).slice(0, 500);
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
