/**
 * Ed25519 signing helpers for Zetrix VC/VP flows.
 *
 * Wraps `zetrix-encryption-nodejs` so we can:
 *  - derive a public key from a private key
 *  - derive the holder DID (`did:zid:<raw pubkey>`) from a private/public key
 *  - sign arbitrary payloads the BaaS API expects signatures for
 *    (e.g. ApplyVC request body hash, DownloadVC `vcId`, VP blob)
 *
 * The BaaS contract expects hex-encoded signatures over UTF-8 bytes of the
 * canonicalised payload.
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
   * Derive the holder's DID from a private key.
   *
   *   DID = "did:zid:" + <raw 32-byte Ed25519 public key, hex>
   *
   * The library returns the encoded public key as
   *   b001 <raw-hex:64> <checksum:8>  (76 hex chars total)
   * so we strip the 2-byte prefix and the 4-byte trailing checksum.
   */
  async getDid(privateKey: string): Promise<string> {
    const encoded = await this.getPublicKey(privateKey);
    return deriveDidFromEncodedPublicKey(encoded);
  }

  /**
   * Sign the UTF-8 bytes of `payload` with the given Ed25519 private key.
   * Returns hex-encoded `signData` and the derived `publicKey`.
   *
   * Use this for VC/VP apply/download/vp signing where the signed pre-image
   * is a plain text JSON string, DID string, or similar.
   */
  async sign(payload: string, privateKey: string): Promise<Ed25519Signature> {
    await this.init();
    const bytes = new Uint8Array(Buffer.from(payload, "utf8"));
    const signData: string = this.signature.sign(bytes, privateKey);
    const publicKey: string = this.KeyPair.getEncPublicKey(privateKey);
    return { signData, publicKey };
  }

  /**
   * Sign a hex-encoded blob — i.e. hex-decode the payload first and sign the
   * raw bytes. Used for Zetrix transaction blobs (protobuf-encoded), which is
   * the form returned by `/cred/v1/vc/revoke/create-blob` and similar
   * endpoints. Mirrors the SDK's `_signBlob`:
   *   Buffer.from(blob, 'hex') → Uint8Array → sign.
   */
  async signHex(hexPayload: string, privateKey: string): Promise<Ed25519Signature> {
    await this.init();
    const clean = hexPayload.trim();
    if (!/^[0-9a-fA-F]+$/.test(clean) || clean.length % 2 !== 0) {
      throw new Error(
        `Expected a hex-encoded blob (even-length hex chars), got length ${clean.length}.`
      );
    }
    const bytes = new Uint8Array(Buffer.from(clean, "hex"));
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

  /** Derive the Zetrix account address (ZTX3… form) from an encoded public key (`b001…`). */
  async getAddressFromPublicKey(encodedPublicKey: string): Promise<string> {
    await this.init();
    return this.KeyPair.getAddress(encodedPublicKey);
  }

  /** Derive the Zetrix account address (ZTX3… form) from a private key. */
  async getAddressFromPrivateKey(privateKey: string): Promise<string> {
    await this.init();
    const encPublicKey = this.KeyPair.getEncPublicKey(privateKey);
    return this.KeyPair.getAddress(encPublicKey);
  }
}

/**
 * Convert a Zetrix-encoded Ed25519 public key (76-hex-char `b001…` form) to a
 * holder DID string.
 *
 *   did:zid:<raw pub-key hex, 32 bytes = 64 hex chars>
 *
 * Throws if the input doesn't look like a Zetrix Ed25519 encoded pubkey.
 */
export function deriveDidFromEncodedPublicKey(encodedPublicKey: string): string {
  return `did:zid:${encodedPublicKeyToRaw(encodedPublicKey)}`;
}

/**
 * Strip the Zetrix encoding (2-byte `b001` prefix + 4-byte checksum) from an
 * Ed25519 public key and return the raw 32-byte key as a hex string.
 */
export function encodedPublicKeyToRaw(encodedPublicKey: string): string {
  const enc = encodedPublicKey.trim().toLowerCase();
  if (enc.length !== 76) {
    throw new Error(
      `Cannot derive DID: expected a 76-char Zetrix Ed25519 encoded public key, got length ${enc.length}.`
    );
  }
  if (!enc.startsWith("b001")) {
    throw new Error(
      `Cannot derive DID: expected the Zetrix Ed25519 encoded public key to start with 'b001', got '${enc.slice(0, 4)}'.`
    );
  }
  return enc.slice(4, 4 + 64);
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
