// cryptic-next/lib/rsa.ts

// --- Utilities ---

export function textToBigInt(text: string): bigint {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(text);
  let hex = "0x";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return BigInt(hex);
}

export function bigIntToText(val: bigint): string {
  let hex = val.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  const len = hex.length / 2;
  const u8 = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    u8[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  // Strict decoding: tampered textbook ciphertext almost never decrypts to
  // valid UTF-8, so throwing here lets callers count the segment as failed
  // instead of silently emitting mojibake.
  return new TextDecoder("utf-8", { fatal: true }).decode(u8);
}

export async function sha256(data: string | object): Promise<string> {
  const str = typeof data === "string" ? data : JSON.stringify(data);
  const encoder = new TextEncoder();
  const buffer = await crypto.subtle.digest("SHA-256", encoder.encode(str));
  const u8 = new Uint8Array(buffer);
  let out = "";
  for(let i=0; i<u8.length; i++) {
      out += u8[i].toString(16).padStart(2, "0");
  }
  return out;
}

function base64UrlToBigInt(b64url: string): bigint {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64.padEnd(Math.ceil(b64.length / 4) * 4, "=");
  const binStr = atob(padded);
  let hex = "0x";
  for (let i = 0; i < binStr.length; i++) {
    hex += binStr.charCodeAt(i).toString(16).padStart(2, "0");
  }
  return BigInt(hex);
}

function bigIntToBase64Url(value: bigint): string {
  let hex = value.toString(16);
  if (hex.length % 2) hex = "0" + hex;

  const binary = hex
    .match(/.{1,2}/g)!
    .map((byte) => String.fromCharCode(parseInt(byte, 16)))
    .join("");

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Simple modular exponentiation for "Textbook RSA"
export function modPow(base: bigint, exp: bigint, modulus: bigint): bigint {
  let result = 1n;
  base = base % modulus;
  while (exp > 0n) {
    if (exp % 2n === 1n) result = (result * base) % modulus;
    exp >>= 1n;
    base = (base * base) % modulus;
  }
  return result;
}

// --- Key Management ---

export interface RSAKeyDict {
  public: {
    n: string;
    e: string;
    pem?: string;
  };
  private: {
    d: string;
    n: string;
    e: string;
    p?: string;
    q?: string;
    pem?: string;
  };
  jwk?: JsonWebKey; // Store original JWK for OAEP operations
}

export interface PublicKeyRecord {
  n: string;
  e: string;
  pem?: string;
}

export interface PrivateKeyRecord extends PublicKeyRecord {
  d: string;
  p?: string;
  q?: string;
  jwk?: JsonWebKey;
}

export async function generateRSAKey(modulusLength: number = 2048): Promise<RSAKeyDict> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: modulusLength,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );

  const pubJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const privJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);

  // Export PEMs
  const spki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

  const pubPem = `-----BEGIN PUBLIC KEY-----\n${arrayBufferToBase64(spki).match(/.{1,64}/g)?.join('\n')}\n-----END PUBLIC KEY-----`;
  const privPem = `-----BEGIN PRIVATE KEY-----\n${arrayBufferToBase64(pkcs8).match(/.{1,64}/g)?.join('\n')}\n-----END PRIVATE KEY-----`;

  return {
    public: {
      n: base64UrlToBigInt(pubJwk.n!).toString(),
      e: base64UrlToBigInt(pubJwk.e!).toString(),
      pem: pubPem,
    },
    private: {
      n: base64UrlToBigInt(privJwk.n!).toString(),
      e: base64UrlToBigInt(privJwk.e!).toString(),
      d: base64UrlToBigInt(privJwk.d!).toString(),
      p: privJwk.p ? base64UrlToBigInt(privJwk.p).toString() : undefined,
      q: privJwk.q ? base64UrlToBigInt(privJwk.q).toString() : undefined,
      pem: privPem,
    },
    jwk: privJwk, // Keep private JWK for easy reconstruction
  };
}

// --- Encryption/Decryption ---

export function segmentMessage(msg: string, maxBytes: number): string[] {
  const encoder = new TextEncoder();
  const msgBytes = encoder.encode(msg);
  const decoder = new TextDecoder();
  
  const segments: string[] = [];
  let idx = 0;
  
  while (idx < msgBytes.length) {
    let end = idx + maxBytes;
    if (end > msgBytes.length) end = msgBytes.length;
    
    let chunk = msgBytes.slice(idx, end);
    while (end > idx) {
       try {
           const strictDecoder = new TextDecoder("utf-8", { fatal: true });
           strictDecoder.decode(chunk);
           break; 
       } catch (e) {
           end--;
           chunk = msgBytes.slice(idx, end);
       }
    }
    
    if (end === idx) {
        throw new Error("Segment size too small for UTF-8 characters.");
    }

    segments.push(decoder.decode(chunk));
    idx = end;
  }
  return segments;
}

// Helper to safely convert Uint8Array to Base64
export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  const chunk_size = 0x8000;
  const chunks = [];
  for (let i = 0; i < len; i += chunk_size) {
    const chunk = bytes.subarray(i, i + chunk_size);
    chunks.push(String.fromCharCode.apply(null, chunk as unknown as number[]));
  }
  return btoa(chunks.join(""));
}

export async function encryptSegmentOAEP(
  segment: string, 
  pubKeyJwk: JsonWebKey
): Promise<string> {
  const key = await crypto.subtle.importKey(
    "jwk",
    pubKeyJwk,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"]
  );
  const encoder = new TextEncoder();
  const data = encoder.encode(segment);
  const encrypted = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    key,
    data
  );
  
  return arrayBufferToBase64(encrypted);
}

export function encryptSegmentTextbook(
  segment: string, 
  nStr: string, 
  eStr: string
): string {
  const m = textToBigInt(segment);
  const n = BigInt(nStr);
  const e = BigInt(eStr);
  
  if (m >= n) {
      throw new Error("Segment too large for modulus.");
  }
  const c = modPow(m, e, n);
  return c.toString();
}

export async function decryptSegmentOAEP(
  segmentB64: string, 
  privKeyJwk: JsonWebKey
): Promise<string> {
  const key = await crypto.subtle.importKey(
    "jwk",
    privKeyJwk,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"]
  );
  const encryptedData = Uint8Array.from(atob(segmentB64), c => c.charCodeAt(0));
  
  try {
      const decrypted = await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        key,
        encryptedData
      );
      return new TextDecoder().decode(decrypted);
  } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      return `[Decryption error: ${message}]`;
  }
}

export function decryptSegmentTextbook(
  segmentStr: string, 
  nStr: string, 
  dStr: string
): string {
  try {
      const c = BigInt(segmentStr);
      const n = BigInt(nStr);
      const d = BigInt(dStr);
      const m = modPow(c, d, n);
      return bigIntToText(m);
  } catch (e) {
      return `[Decryption error: ${e}]`;
  }
}

// Extended Euclidean Algorithm for modular inverse
function modInverse(a: bigint, m: bigint): bigint {
  let [old_r, r] = [a, m];
  let [old_s, s] = [1n, 0n];
  
  while (r !== 0n) {
    const quotient = old_r / r;
    [old_r, r] = [r, old_r - quotient * r];
    [old_s, s] = [s, old_s - quotient * s];
  }
  
  if (old_s < 0n) old_s += m;
  return old_s;
}

// Helper to reconstruct JWK from n/e strings (for public key import)
export function dictToPubJwk(n: string, e: string): JsonWebKey {
  return {
    kty: "RSA",
    alg: "RSA-OAEP-256",
    ext: true,
    n: bigIntToBase64Url(BigInt(n)),
    e: bigIntToBase64Url(BigInt(e))
  };
}

export async function pemToRSAKeyDict(pem: string, type: "public"): Promise<PublicKeyRecord>;
export async function pemToRSAKeyDict(pem: string, type: "private"): Promise<PrivateKeyRecord>;
export async function pemToRSAKeyDict(
  pem: string,
  type: "public" | "private"
): Promise<PublicKeyRecord | PrivateKeyRecord> {
  const pemHeader = `-----BEGIN ${type === "public" ? "PUBLIC" : "PRIVATE"} KEY-----`;
  const pemFooter = `-----END ${type === "public" ? "PUBLIC" : "PRIVATE"} KEY-----`;
  const normalizedPem = pem.trim();

  if (!normalizedPem.includes(pemHeader) || !normalizedPem.includes(pemFooter)) {
    throw new Error(`Expected a valid ${type} key PEM block.`);
  }

  const pemContents = normalizedPem
    .substring(
      normalizedPem.indexOf(pemHeader) + pemHeader.length,
      normalizedPem.indexOf(pemFooter)
    )
    .replace(/\s/g, "");
  
  const binaryDerString = atob(pemContents);
  const binaryDer = new Uint8Array(binaryDerString.length);
  for (let i = 0; i < binaryDerString.length; i++) {
    binaryDer[i] = binaryDerString.charCodeAt(i);
  }

  const key = await crypto.subtle.importKey(
    type === "public" ? "spki" : "pkcs8",
    binaryDer.buffer,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    type === "public" ? ["encrypt"] : ["decrypt"]
  );

  const jwk = await crypto.subtle.exportKey("jwk", key);

  if (type === "public") {
    return {
      n: base64UrlToBigInt(jwk.n!).toString(),
      e: base64UrlToBigInt(jwk.e!).toString(),
      pem: normalizedPem,
    };
  } else {
    return {
      n: base64UrlToBigInt(jwk.n!).toString(),
      e: base64UrlToBigInt(jwk.e!).toString(),
      d: base64UrlToBigInt(jwk.d!).toString(),
      p: jwk.p ? base64UrlToBigInt(jwk.p).toString() : undefined,
      q: jwk.q ? base64UrlToBigInt(jwk.q).toString() : undefined,
      pem: normalizedPem,
      jwk,
    };
  }
}

// --- Key input parsing (shared by Encrypt, Decrypt, Sign, Verify) ---

// JSON is tried first: keys exported by this app embed their PEM string
// inside the JSON, so a PEM marker alone doesn't mean the input is a PEM
// block. PEM detection uses includes() so leading whitespace or comment
// lines around a real PEM block don't break it.
export async function parsePublicKeyInput(rawInput: string): Promise<PublicKeyRecord> {
  const trimmed = rawInput.trim();

  let parsed: unknown = null;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    // Not JSON; fall through to PEM handling.
  }

  if (parsed && typeof parsed === "object") {
    if (
      typeof (parsed as PublicKeyRecord).n !== "string" ||
      typeof (parsed as PublicKeyRecord).e !== "string"
    ) {
      throw new Error('Public key JSON needs string values for "n" and "e".');
    }
    return parsed as PublicKeyRecord;
  }

  if (trimmed.includes("-----BEGIN PUBLIC KEY-----")) {
    return pemToRSAKeyDict(trimmed, "public");
  }
  if (trimmed.includes("-----BEGIN")) {
    throw new Error(
      "This looks like a PEM block, but not a public key. Expected -----BEGIN PUBLIC KEY-----."
    );
  }

  throw new Error("Paste the public key as JSON or as a PEM block.");
}

export async function parsePrivateKeyInput(rawInput: string): Promise<PrivateKeyRecord> {
  const trimmed = rawInput.trim();

  let parsed: unknown = null;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    // Not JSON; fall through to PEM handling.
  }

  if (parsed && typeof parsed === "object") {
    if (
      typeof (parsed as PrivateKeyRecord).n !== "string" ||
      typeof (parsed as PrivateKeyRecord).d !== "string"
    ) {
      throw new Error('Private key JSON needs string values for "n" and "d".');
    }
    return parsed as PrivateKeyRecord;
  }

  if (trimmed.includes("-----BEGIN PRIVATE KEY-----")) {
    return pemToRSAKeyDict(trimmed, "private");
  }
  if (trimmed.includes("-----BEGIN")) {
    throw new Error(
      "This looks like a PEM block, but not a private key. Expected -----BEGIN PRIVATE KEY-----."
    );
  }

  throw new Error("Paste the private key as JSON or as a PEM block.");
}

export function dictToPrivJwk(priv: { n: string, e: string, d: string, p?: string, q?: string }): JsonWebKey {
    const n = BigInt(priv.n);
    const e = BigInt(priv.e);
    const d = BigInt(priv.d);

    if (!priv.p || !priv.q) {
        throw new Error("This private key is missing its prime factors (p and q), so it can only be used for textbook RSA.");
    }

    const p = BigInt(priv.p);
    const q = BigInt(priv.q);
    
    // Calculate CRT components
    const dp = d % (p - 1n);
    const dq = d % (q - 1n);
    const qi = modInverse(q, p);
    
    return {
        kty: "RSA",
        alg: "RSA-OAEP-256",
        ext: true,
        n: bigIntToBase64Url(n),
        e: bigIntToBase64Url(e),
        d: bigIntToBase64Url(d),
        p: bigIntToBase64Url(p),
        q: bigIntToBase64Url(q),
        dp: bigIntToBase64Url(dp),
        dq: bigIntToBase64Url(dq),
        qi: bigIntToBase64Url(qi)
    };
}

// --- Digital Signatures (RSA-PSS) ---

export async function signMessage(message: string, privKeyJwk: JsonWebKey): Promise<string> {
    // Import key for signing (PSS)
    // Note: Technically need a separate key usage/alg for signing vs encryption in WebCrypto strict mode usually,
    // but we can re-import the JWK with "sign" usage and "PS256" algorithm.
    const key = await crypto.subtle.importKey(
        "jwk",
        { ...privKeyJwk, alg: "PS256", key_ops: ["sign"] },
        { name: "RSA-PSS", hash: "SHA-256" },
        false,
        ["sign"]
    );
    
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const signature = await crypto.subtle.sign(
        { name: "RSA-PSS", saltLength: 32 },
        key,
        data
    );
    
    // Return hex string for readability
    return Array.from(new Uint8Array(signature))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

export async function verifySignature(message: string, signatureHex: string, pubKeyJwk: JsonWebKey): Promise<boolean> {
    const normalizedSignature = signatureHex.trim();
    if (!/^[0-9a-fA-F]+$/.test(normalizedSignature) || normalizedSignature.length % 2 !== 0) {
        throw new Error("Signature must be a valid hexadecimal string.");
    }

    const key = await crypto.subtle.importKey(
        "jwk",
        { ...pubKeyJwk, alg: "PS256", key_ops: ["verify"] },
        { name: "RSA-PSS", hash: "SHA-256" },
        false,
        ["verify"]
    );
    
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    
    // Convert hex signature back to bytes
    const signatureBytes = new Uint8Array(
        normalizedSignature.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16))
    );

    return await crypto.subtle.verify(
        { name: "RSA-PSS", saltLength: 32 },
        key,
        signatureBytes,
        data
    );
}

// --- Key fingerprints ---

/**
 * Short SHA-256 fingerprint of a public modulus, formatted for reading aloud
 * or comparing over a second channel (80 bits, e.g. "3F9A:0C21:BB04:1D7E:52A8").
 * Two peers seeing the same fingerprint are talking to the same key.
 */
export async function keyFingerprint(modulus: string): Promise<string> {
  const hash = await sha256(modulus);
  return (hash.slice(0, 20).match(/.{4}/g) ?? []).join(":").toUpperCase();
}

// --- Key Naming (Deterministic) ---

const ADJECTIVES = ["Cosmic", "Quantum", "Nebula", "Silent", "Iron", "Crystal", "Void", "Solar", "Lunar", "Cyber", "Hidden", "Golden", "Rapid", "Secret", "Mystic", "Frozen"];
const NOUNS = ["Gate", "Shield", "Key", "Core", "Link", "Protocol", "Vault", "Signal", "Cipher", "Echo", "Prism", "Lock", "Ward", "Node", "Pulse", "Shard"];

export async function generateKeyName(pubKey: RSAKeyDict['public']): Promise<string> {
    // Generate name from hash of public modulus
    const hash = await sha256(pubKey.n);
    // Take first 2 bytes for indices
    const idx1 = parseInt(hash.substring(0, 2), 16) % ADJECTIVES.length;
    const idx2 = parseInt(hash.substring(2, 4), 16) % NOUNS.length;
    const suffix = hash.substring(hash.length - 4).toUpperCase();
    
    return `${ADJECTIVES[idx1]} ${NOUNS[idx2]} [${suffix}]`;
}

// --- Wallet Encryption (Master Password) ---

/** Current PBKDF2 work factor, following OWASP guidance for PBKDF2-HMAC-SHA256. */
export const WALLET_KDF_ITERATIONS = 600_000;
/** Wallets written before the payload carried KDF parameters used this value. */
const LEGACY_KDF_ITERATIONS = 100_000;

interface WalletPayload {
  v?: number;
  kdf?: { name: string; hash: string; iterations: number };
  salt: string;
  iv: string;
  data: string;
}

async function getMasterKey(
  password: string,
  salt: Uint8Array,
  iterations: number
): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits", "deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt as any,
      iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function encryptWalletData(data: unknown, password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await getMasterKey(password, salt, WALLET_KDF_ITERATIONS);

  const enc = new TextEncoder();
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    enc.encode(JSON.stringify(data))
  );

  // The payload records its own KDF parameters so the work factor can be
  // raised in the future without stranding wallets written today.
  const payload: WalletPayload = {
    v: 2,
    kdf: { name: "PBKDF2", hash: "SHA-256", iterations: WALLET_KDF_ITERATIONS },
    salt: arrayBufferToBase64(salt.buffer),
    iv: arrayBufferToBase64(iv.buffer),
    data: arrayBufferToBase64(encrypted)
  };
  return JSON.stringify(payload);
}

export async function decryptWalletData(encryptedJson: string, password: string): Promise<unknown> {
  const payload = JSON.parse(encryptedJson) as WalletPayload;

  // Payloads from before v2 carry no KDF block; they were all written with
  // the legacy iteration count. The bounds check keeps a corrupted or
  // hand-edited payload from turning key derivation into a hang.
  const iterations = payload.kdf?.iterations ?? LEGACY_KDF_ITERATIONS;
  if (!Number.isInteger(iterations) || iterations < 1 || iterations > 5_000_000) {
    throw new Error("Unsupported wallet key derivation parameters.");
  }

  const salt = Uint8Array.from(atob(payload.salt), c => c.charCodeAt(0));
  const iv = Uint8Array.from(atob(payload.iv), c => c.charCodeAt(0));
  const encryptedData = Uint8Array.from(atob(payload.data), c => c.charCodeAt(0));

  const key = await getMasterKey(password, salt, iterations);

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    key,
    encryptedData
  );

  const dec = new TextDecoder();
  return JSON.parse(dec.decode(decrypted));
}

/**
 * True when a stored wallet was encrypted with a weaker work factor than the
 * current default. Callers re-encrypt after a successful unlock, which is the
 * only moment the password is available.
 */
export function walletPayloadNeedsUpgrade(encryptedJson: string): boolean {
  try {
    const payload = JSON.parse(encryptedJson) as WalletPayload;
    return (payload.kdf?.iterations ?? LEGACY_KDF_ITERATIONS) < WALLET_KDF_ITERATIONS;
  } catch {
    return false;
  }
}
