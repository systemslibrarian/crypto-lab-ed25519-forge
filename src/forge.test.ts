import { describe, expect, it } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519.js';
import {
  forgeCofactorSignature,
  generateKeypair,
  signMessage,
  tamperSignature,
  verifySignature,
} from './forge';

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Official RFC 8032 Section 7.1 (Ed25519, pure) Known-Answer Test vectors.
 * A KAT suite is the whole point of a signature demo: if @noble/curves ever
 * regressed, or if someone swapped in a broken implementation, these fixed
 * seed -> public-key -> signature triples would catch it immediately. This is
 * exactly the "Ed25519 test vectors" the deploy is claimed to be gated on.
 * Source: https://www.rfc-editor.org/rfc/rfc8032#section-7.1
 */
const RFC8032_VECTORS = [
  {
    name: 'TEST 1 (empty message)',
    secretKey: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    publicKey: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    message: '',
    signature:
      'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
  },
  {
    name: 'TEST 2 (1-byte message)',
    secretKey: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
    publicKey: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
    message: '72',
    signature:
      '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
  },
  {
    name: 'TEST 3 (2-byte message)',
    secretKey: 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
    publicKey: 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
    message: 'af82',
    signature:
      '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a',
  },
] as const;

describe('RFC 8032 Ed25519 Known-Answer Tests', () => {
  for (const v of RFC8032_VECTORS) {
    describe(v.name, () => {
      const seed = hexToBytes(v.secretKey);
      const msg = hexToBytes(v.message);

      it('derives the exact reference public key from the seed', () => {
        expect(bytesToHex(ed25519.getPublicKey(seed))).toBe(v.publicKey);
      });

      it('produces the exact reference (deterministic) signature', () => {
        // Ed25519 nonces are deterministic, so signing is a KAT, not just a round-trip.
        expect(bytesToHex(ed25519.sign(msg, seed))).toBe(v.signature);
      });

      it('accepts the reference signature and rejects a one-bit-tampered copy', () => {
        // Verify the raw primitive on the exact reference bytes (the message may
        // not be valid UTF-8, so we stay in byte-land here).
        expect(ed25519.verify(hexToBytes(v.signature), msg, hexToBytes(v.publicKey))).toBe(true);
        const bad = tamperSignature(hexToBytes(v.signature));
        expect(ed25519.verify(bad, msg, hexToBytes(v.publicKey))).toBe(false);
      });
    });
  }
});

describe('sign / verify round-trip and forgery rejection', () => {
  it('a freshly generated keypair signs and verifies its own message', () => {
    const kp = generateKeypair();
    expect(kp.privateKey).toHaveLength(32);
    expect(kp.publicKey).toHaveLength(32);
    const { signature } = signMessage('attack at dawn', kp.privateKey);
    expect(signature).toHaveLength(64);
    expect(verifySignature('attack at dawn', signature, kp.publicKey)).toBe(true);
  });

  it('rejects a signature verified against a different message', () => {
    const kp = generateKeypair();
    const { signature } = signMessage('attack at dawn', kp.privateKey);
    expect(verifySignature('attack at dusk', signature, kp.publicKey)).toBe(false);
  });

  it('rejects a signature verified against a different public key', () => {
    const kp = signMessage('hello', generateKeypair().privateKey);
    const other = generateKeypair();
    expect(verifySignature('hello', kp.signature, other.publicKey)).toBe(false);
  });

  it('tamperSignature flips exactly byte 32 and the result no longer verifies', () => {
    const kp = generateKeypair();
    const { signature } = signMessage('deterministic nonce', kp.privateKey);
    const tampered = tamperSignature(signature);
    // Only byte 32 differs.
    let diffs = 0;
    for (let i = 0; i < signature.length; i++) if (signature[i] !== tampered[i]) diffs++;
    expect(diffs).toBe(1);
    expect(tampered[32]).toBe(signature[32] ^ 0x01);
    expect(verifySignature('deterministic nonce', tampered, kp.publicKey)).toBe(false);
  });

  it('tamperSignature throws when the signature is too short to index byte 32', () => {
    expect(() => tamperSignature(new Uint8Array(32))).toThrow();
  });

  it('is deterministic: identical inputs yield identical signatures', () => {
    const kp = generateKeypair();
    const a = signMessage('same input', kp.privateKey).signature;
    const b = signMessage('same input', kp.privateKey).signature;
    expect(bytesToHex(a)).toBe(bytesToHex(b));
  });
});

describe('cofactor / small-subgroup malleability (ZIP215 vs strict RFC 8032)', () => {
  it('forges a signature that ZIP215 accepts but strict RFC 8032 rejects, for every torsion point', () => {
    for (let variant = 1; variant <= 7; variant++) {
      const forgery = forgeCofactorSignature('I never signed this', variant);
      expect(forgery.publicKey).toHaveLength(32);
      expect(forgery.signature).toHaveLength(64);
      // This is the whole point of the exhibit: the two legitimate verification
      // rules disagree on identical bytes.
      expect(forgery.zip215Valid).toBe(true);
      expect(forgery.strictValid).toBe(false);
    }
  });

  it('uses genuinely small-order public keys (order divides cofactor 8)', () => {
    const forgery = forgeCofactorSignature('subgroup', 3);
    const A = ed25519.Point.fromBytes(forgery.publicKey);
    // Multiplying a torsion point by the cofactor 8 yields the identity.
    expect(A.isSmallOrder()).toBe(true);
    expect(A.multiplyUnsafe(8n).is0()).toBe(true);
  });

  it('the forgery is NOT accepted when the public key is a real (prime-order) key', () => {
    // Sanity: the trick only works because the key is small-order. A normal key
    // with the same crafted signature must fail under BOTH rules.
    const forgery = forgeCofactorSignature('control', 2);
    const real = generateKeypair().publicKey;
    expect(ed25519.verify(forgery.signature, forgery.messageBytes, real)).toBe(false);
    expect(
      ed25519.verify(forgery.signature, forgery.messageBytes, real, { zip215: false }),
    ).toBe(false);
  });

  it('a normal honest signature verifies identically under ZIP215 and strict rules', () => {
    // The divergence is specific to malformed/small-order inputs; well-formed
    // signatures must agree, or the demo would be misleading.
    const kp = generateKeypair();
    const { signature, messageBytes } = signMessage('honest', kp.privateKey);
    expect(ed25519.verify(signature, messageBytes, kp.publicKey)).toBe(true);
    expect(ed25519.verify(signature, messageBytes, kp.publicKey, { zip215: false })).toBe(true);
  });
});
