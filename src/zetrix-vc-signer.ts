/**
 * Ed25519 signing helpers for Zetrix VC/VP flows.
 *
 * Wraps `zetrix-encryption-nodejs` so we can:
 *  - derive a public key from a private key
 *  - sign arbitrary payloads the BaaS API expects signatures for
 *    (e.g. ApplyVC request body hash, DownloadVC `vcId`, VP blob)
 *
 * The BaaS contract (see VC_VP_API_REFERENCE.md) expects hex-encoded signatures
 * over UTF-8 bytes of the canonicalised payload.
 */

export interface Ed25519Signature {
  signData: string;
  publicKey: string;
}

export class ZetrixVcSigner {
  private encryption: any;
  private KeyPair: any;
  private signature: any;

  private async init(): Promise<void> {
    if (this.encryption) return;
    const mod: any = await import("zetrix-encryption-nodejs");
    this.encryption = mod.default || mod;
    this.KeyPair = this.encryption.keypair;
    this.signature = this.encryption.signature;
  }

  /** Derive the Zetrix-encoded public key from a private key. */
  async getPublicKey(privateKey: string): Promise<string> {
    await this.init();
    return this.KeyPair.getEncPublicKey(privateKey);
  }

  /**
   * Sign the UTF-8 bytes of `payload` with the given Ed25519 private key.
   * Returns hex-encoded `signData` and the derived `publicKey`.
   */
  async sign(payload: string, privateKey: string): Promise<Ed25519Signature> {
    await this.init();
    const bytes = new Uint8Array(Buffer.from(payload, "utf8"));
    const signData: string = this.signature.sign(bytes, privateKey);
    const publicKey: string = this.KeyPair.getEncPublicKey(privateKey);
    return { signData, publicKey };
  }

  /**
   * Sign a JSON object by first stringifying it with stable key ordering.
   * Useful for request-body signatures where the server re-canonicalises.
   */
  async signJson(obj: unknown, privateKey: string): Promise<Ed25519Signature> {
    const payload = stableStringify(obj);
    return this.sign(payload, privateKey);
  }

  /** Verify a signature produced by `sign` against an Ed25519 public key. */
  async verify(payload: string, signData: string, publicKey: string): Promise<boolean> {
    await this.init();
    const bytes = new Uint8Array(Buffer.from(payload, "utf8"));
    return this.signature.verify(bytes, signData, publicKey);
  }
}

/** Deterministic JSON stringify — keys sorted, no insignificant whitespace. */
export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map((v) => stableStringify(v)).join(",") + "]";
  }
  const keys = Object.keys(value as Record<string, unknown>).sort();
  return (
    "{" +
    keys
      .map(
        (k) =>
          JSON.stringify(k) +
          ":" +
          stableStringify((value as Record<string, unknown>)[k])
      )
      .join(",") +
    "}"
  );
}
