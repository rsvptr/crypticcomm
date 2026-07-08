import { beforeAll, describe, expect, it } from "vitest";
import {
  arrayBufferToBase64,
  bigIntToText,
  decryptSegmentOAEP,
  decryptSegmentTextbook,
  dictToPrivJwk,
  dictToPubJwk,
  encryptSegmentOAEP,
  encryptSegmentTextbook,
  encryptWalletData,
  decryptWalletData,
  generateKeyName,
  generateRSAKey,
  keyFingerprint,
  modPow,
  parsePrivateKeyInput,
  parsePublicKeyInput,
  pemToRSAKeyDict,
  RSAKeyDict,
  segmentMessage,
  sha256,
  textToBigInt,
  WALLET_KDF_ITERATIONS,
  walletPayloadNeedsUpgrade,
} from "./rsa";

// 1024-bit keys keep the suite fast; the math is identical at larger sizes.
let alice: RSAKeyDict;
let mallory: RSAKeyDict;

beforeAll(async () => {
  alice = await generateRSAKey(1024);
  mallory = await generateRSAKey(1024);
}, 30000);

describe("conversions", () => {
  it("round-trips ASCII text through BigInt", () => {
    expect(bigIntToText(textToBigInt("hello, rsa"))).toBe("hello, rsa");
  });

  it("round-trips multibyte text through BigInt", () => {
    expect(bigIntToText(textToBigInt("café € 🔐"))).toBe(
      "café € 🔐"
    );
  });

  it("rejects bytes that are not valid UTF-8", () => {
    // 0x80 is a lone continuation byte; strict decoding must throw so that
    // tampered textbook ciphertext registers as a failure.
    expect(() => bigIntToText(0x80n)).toThrow();
  });

  it("computes modular exponentiation", () => {
    expect(modPow(4n, 13n, 497n)).toBe(445n);
    expect(modPow(7n, 0n, 13n)).toBe(1n);
  });

  it("hashes deterministically", async () => {
    const first = await sha256("crypticcomm");
    const second = await sha256("crypticcomm");
    expect(first).toBe(second);
    expect(first).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("segmentMessage", () => {
  it("splits by byte budget and rejoins losslessly", () => {
    const segments = segmentMessage("abcdef", 2);
    expect(segments).toEqual(["ab", "cd", "ef"]);
    expect(segments.join("")).toBe("abcdef");
  });

  it("never splits a multibyte character", () => {
    const message = "€€€"; // three 3-byte euro signs
    const segments = segmentMessage(message, 4);
    expect(segments.join("")).toBe(message);
    for (const segment of segments) {
      expect(() => new TextDecoder("utf-8", { fatal: true }).decode(
        new TextEncoder().encode(segment)
      )).not.toThrow();
    }
  });

  it("throws when the budget cannot fit one character", () => {
    expect(() => segmentMessage("€", 2)).toThrow();
  });
});

describe("key input parsing", () => {
  it("accepts public key JSON", async () => {
    const parsed = await parsePublicKeyInput(
      JSON.stringify({ n: alice.public.n, e: alice.public.e })
    );
    expect(parsed.n).toBe(alice.public.n);
  });

  it("treats JSON with an embedded PEM field as JSON, not PEM", async () => {
    const parsed = await parsePublicKeyInput(JSON.stringify(alice.public, null, 2));
    expect(parsed.n).toBe(alice.public.n);
  });

  it("parses a public key PEM with surrounding whitespace", async () => {
    const parsed = await parsePublicKeyInput(`\n\n${alice.public.pem}\n`);
    expect(parsed.n).toBe(alice.public.n);
  });

  it("rejects a private PEM pasted into a public key field", async () => {
    await expect(parsePublicKeyInput(alice.private.pem as string)).rejects.toThrow(
      /PUBLIC KEY/
    );
  });

  it("rejects JSON missing required fields", async () => {
    await expect(parsePublicKeyInput(JSON.stringify({ n: alice.public.n }))).rejects.toThrow(
      /"n" and "e"/
    );
    await expect(
      parsePrivateKeyInput(JSON.stringify({ n: alice.private.n, e: alice.private.e }))
    ).rejects.toThrow(/"n" and "d"/);
  });

  it("rejects text that is neither JSON nor PEM", async () => {
    await expect(parsePublicKeyInput("not a key")).rejects.toThrow(/JSON or as a PEM/);
  });

  it("parses the PEMs produced by key generation", async () => {
    const publicRecord = await pemToRSAKeyDict(alice.public.pem as string, "public");
    expect(publicRecord.n).toBe(alice.public.n);

    const privateRecord = await pemToRSAKeyDict(alice.private.pem as string, "private");
    expect(privateRecord.d).toBe(alice.private.d);
    expect(privateRecord.p).toBeDefined();
    expect(privateRecord.q).toBeDefined();
  });
});

describe("OAEP encryption", () => {
  it("round-trips a message", async () => {
    const pubJwk = dictToPubJwk(alice.public.n, alice.public.e);
    const privJwk = dictToPrivJwk(alice.private);
    const ciphertext = await encryptSegmentOAEP("attack at dawn", pubJwk);
    expect(await decryptSegmentOAEP(ciphertext, privJwk)).toBe("attack at dawn");
  });

  it("randomizes: the same plaintext encrypts differently each time", async () => {
    const pubJwk = dictToPubJwk(alice.public.n, alice.public.e);
    const first = await encryptSegmentOAEP("same message", pubJwk);
    const second = await encryptSegmentOAEP("same message", pubJwk);
    expect(first).not.toBe(second);
  });

  it("fails cleanly with the wrong private key", async () => {
    const pubJwk = dictToPubJwk(alice.public.n, alice.public.e);
    const wrongPriv = dictToPrivJwk(mallory.private);
    const ciphertext = await encryptSegmentOAEP("for alice only", pubJwk);
    expect(await decryptSegmentOAEP(ciphertext, wrongPriv)).toMatch(/^\[Decryption error/);
  });

  it("requires prime factors for the private JWK", () => {
    expect(() =>
      dictToPrivJwk({ n: alice.private.n, e: alice.private.e, d: alice.private.d })
    ).toThrow(/prime factors/);
  });
});

describe("textbook RSA", () => {
  it("round-trips a message", () => {
    const ciphertext = encryptSegmentTextbook("plain rsa", alice.public.n, alice.public.e);
    expect(decryptSegmentTextbook(ciphertext, alice.private.n, alice.private.d)).toBe(
      "plain rsa"
    );
  });

  it("is deterministic: the same plaintext always encrypts the same way", () => {
    const first = encryptSegmentTextbook("same message", alice.public.n, alice.public.e);
    const second = encryptSegmentTextbook("same message", alice.public.n, alice.public.e);
    expect(first).toBe(second);
  });

  it("does not silently return the original message for tampered ciphertext", () => {
    const ciphertext = encryptSegmentTextbook("important", alice.public.n, alice.public.e);
    const tampered = (BigInt(ciphertext) + 1n).toString();
    expect(decryptSegmentTextbook(tampered, alice.private.n, alice.private.d)).not.toBe(
      "important"
    );
  });

  it("rejects segments larger than the modulus", () => {
    const huge = "x".repeat(200); // 200 bytes > 128-byte modulus
    expect(() => encryptSegmentTextbook(huge, alice.public.n, alice.public.e)).toThrow(
      /too large/
    );
  });
});

describe("signatures", () => {
  it("verifies a genuine signature and rejects a modified message", async () => {
    const { signMessage, verifySignature } = await import("./rsa");
    const privJwk = dictToPrivJwk(alice.private);
    const pubJwk = dictToPubJwk(alice.public.n, alice.public.e);

    const signature = await signMessage("I approve this", privJwk);
    expect(signature).toMatch(/^[0-9a-f]+$/);
    expect(await verifySignature("I approve this", signature, pubJwk)).toBe(true);
    expect(await verifySignature("I approve this!", signature, pubJwk)).toBe(false);
  });

  it("rejects a signature checked against the wrong key", async () => {
    const { signMessage, verifySignature } = await import("./rsa");
    const signature = await signMessage("mine", dictToPrivJwk(alice.private));
    const wrongPub = dictToPubJwk(mallory.public.n, mallory.public.e);
    expect(await verifySignature("mine", signature, wrongPub)).toBe(false);
  });

  it("rejects malformed hex before verifying", async () => {
    const { verifySignature } = await import("./rsa");
    const pubJwk = dictToPubJwk(alice.public.n, alice.public.e);
    await expect(verifySignature("msg", "not-hex", pubJwk)).rejects.toThrow(/hexadecimal/);
  });
});

describe("wallet encryption", () => {
  it("round-trips data with the right password", async () => {
    const data = [{ id: "1", name: "Test Key" }];
    const encrypted = await encryptWalletData(data, "hunter2hunter2");
    expect(encrypted).not.toContain("Test Key");
    expect(await decryptWalletData(encrypted, "hunter2hunter2")).toEqual(data);
  });

  it("rejects the wrong password", async () => {
    const encrypted = await encryptWalletData({ secret: true }, "correct password");
    await expect(decryptWalletData(encrypted, "wrong password")).rejects.toThrow();
  });

  it("stamps new payloads with their KDF parameters", async () => {
    const encrypted = await encryptWalletData([], "password123");
    const payload = JSON.parse(encrypted);
    expect(payload.v).toBe(2);
    expect(payload.kdf).toEqual({
      name: "PBKDF2",
      hash: "SHA-256",
      iterations: WALLET_KDF_ITERATIONS,
    });
    expect(walletPayloadNeedsUpgrade(encrypted)).toBe(false);
  });

  it("still decrypts legacy payloads and flags them for upgrade", async () => {
    // Recreate the pre-v2 format byte for byte: same AES-GCM layout, the old
    // 100k iteration count, and no kdf block in the JSON.
    const password = "legacy password";
    const data = [{ id: "legacy" }];
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );
    const key = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 100_000, hash: "SHA-256" },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"]
    );
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      new TextEncoder().encode(JSON.stringify(data))
    );
    const legacyJson = JSON.stringify({
      salt: arrayBufferToBase64(salt.buffer),
      iv: arrayBufferToBase64(iv.buffer),
      data: arrayBufferToBase64(encrypted),
    });

    expect(walletPayloadNeedsUpgrade(legacyJson)).toBe(true);
    expect(await decryptWalletData(legacyJson, password)).toEqual(data);
  });

  it("rejects payloads with out-of-range KDF parameters", async () => {
    const encrypted = await encryptWalletData([], "password123");
    const payload = JSON.parse(encrypted);
    payload.kdf.iterations = 50_000_000;
    await expect(decryptWalletData(JSON.stringify(payload), "password123")).rejects.toThrow(
      /derivation/
    );
  });
});

describe("fingerprints and names", () => {
  it("formats fingerprints as five hex groups", async () => {
    const fingerprint = await keyFingerprint(alice.public.n);
    expect(fingerprint).toMatch(/^([0-9A-F]{4}:){4}[0-9A-F]{4}$/);
  });

  it("is deterministic per key and distinct across keys", async () => {
    expect(await keyFingerprint(alice.public.n)).toBe(await keyFingerprint(alice.public.n));
    expect(await keyFingerprint(alice.public.n)).not.toBe(
      await keyFingerprint(mallory.public.n)
    );
  });

  it("derives stable, readable key names", async () => {
    const name = await generateKeyName(alice.public);
    expect(name).toBe(await generateKeyName(alice.public));
    expect(name).toMatch(/^[A-Za-z]+ [A-Za-z]+ \[[0-9A-F]{4}\]$/);
  });
});
