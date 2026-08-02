/**
 * ecdsa.ts — the live contrast to Ed25519's deterministic nonces.
 *
 * The page claims Ed25519's determinism matters because ECDSA with a repeated
 * nonce leaks the private key (the PlayStation 3 / Sony ECDSA break). This
 * module DEMONSTRATES that end to end on real NIST P-256:
 *
 *   Two ECDSA signatures made with the SAME nonce k share the same r. Then
 *       s1 = k⁻¹(z1 + r·d),  s2 = k⁻¹(z2 + r·d)   (mod n)
 *   subtract:
 *       s1 − s2 = k⁻¹(z1 − z2)  ⇒  k = (z1 − z2)·(s1 − s2)⁻¹
 *   and back-substitute:
 *       d = (s1·k − z1)·r⁻¹     (mod n)
 *
 * The recovered d is compared for exact equality against the real private key,
 * and — the acceptance proof — used to sign a brand-new message that the real
 * @noble/curves P-256 verifier accepts against the untouched public key.
 *
 * Ed25519 cannot be attacked this way: its per-signature nonce is derived
 * deterministically from (private key, message), so two signings of different
 * messages never share exploitable nonce structure, and two signings of the
 * SAME message are byte-identical. Both facts are measured, not asserted.
 */

import { p256 } from '@noble/curves/nist.js';
import { ed25519 } from '@noble/curves/ed25519.js';

const N = p256.Point.Fn.ORDER; // the P-256 group order n
const Fn = p256.Point.Fn; // arithmetic mod n (add/sub/mul/inv)

export type EcdsaSig = { r: bigint; s: bigint };

function bytesToBigint(bytes: Uint8Array): bigint {
  let x = 0n;
  for (const b of bytes) x = (x << 8n) | BigInt(b);
  return x;
}

function bigintTo32Bytes(x: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = x;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** bits2int per SEC1/RFC 6979: interpret the hash as an integer, then reduce mod n. */
async function hashToScalar(message: string): Promise<bigint> {
  const data = new TextEncoder().encode(message);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
  return bytesToBigint(digest) % N;
}

/**
 * Raw ECDSA signing with a CALLER-SUPPLIED nonce k — the whole point is to be
 * able to reuse k, which the safe high-level API rightly refuses to allow.
 * r = (k·G).x mod n ; s = k⁻¹(z + r·d) mod n.
 */
export function ecdsaSignWithNonce(z: bigint, d: bigint, k: bigint): EcdsaSig {
  const R = p256.Point.BASE.multiply(Fn.create(k));
  const r = R.toAffine().x % N;
  if (r === 0n) throw new Error('degenerate r=0; pick another nonce');
  const s = Fn.mul(Fn.inv(k), Fn.add(z, Fn.mul(r, d)));
  if (s === 0n) throw new Error('degenerate s=0; pick another nonce');
  return { r, s };
}

/**
 * Recover the private key d from two signatures that reused a nonce (r1 === r2).
 * Returns null if the two r values differ (no shared nonce ⇒ no attack).
 */
export function recoverPrivateKey(
  sig1: EcdsaSig,
  z1: bigint,
  sig2: EcdsaSig,
  z2: bigint,
): { d: bigint; k: bigint } | null {
  if (sig1.r !== sig2.r) return null; // nonces differed ⇒ r differs ⇒ not exploitable
  const sDiff = Fn.sub(sig1.s, sig2.s);
  if (sDiff === 0n) return null;
  const k = Fn.mul(Fn.sub(z1, z2), Fn.inv(sDiff));
  const d = Fn.mul(Fn.sub(Fn.mul(sig1.s, k), z1), Fn.inv(sig1.r));
  return { d, k };
}

export type NonceReuseResult = {
  reuseNonce: boolean;
  /** hex of the real private key that was generated (revealed only to prove the match) */
  realPrivHex: string;
  /** hex of the recovered private key, or null if recovery was not possible */
  recoveredPrivHex: string | null;
  /** did the recovered key exactly equal the real one? */
  keyRecovered: boolean;
  r1Hex: string;
  r2Hex: string;
  /** r1 === r2 (i.e. the nonce was actually reused) */
  sharedNonce: boolean;
  /** a NEW message signed with the recovered key */
  forgedMessage: string;
  /** did the REAL P-256 verifier accept the forgery against the untouched public key? */
  forgeryAccepted: boolean;
};

/**
 * Full attack. Generates a real P-256 keypair, signs two different messages —
 * with the same nonce when `reuseNonce`, otherwise with independent nonces —
 * recovers the private key, and (if recovered) forges a signature on a third
 * message that the real verifier is asked to accept.
 */
export async function runEcdsaNonceReuse(
  msg1: string,
  msg2: string,
  reuseNonce: boolean,
): Promise<NonceReuseResult> {
  // Real P-256 private key d in [1, n).
  const priv = p256.utils.randomSecretKey();
  const pub = p256.getPublicKey(priv, false);
  const d = bytesToBigint(priv) % N || 1n;

  const z1 = await hashToScalar(msg1);
  const z2 = await hashToScalar(msg2);

  // Nonces: reused (k1 === k2) or independent. Rejection-sample into [1, n).
  const freshNonce = (): bigint => {
    let k = 0n;
    do {
      k = bytesToBigint(crypto.getRandomValues(new Uint8Array(32))) % N;
    } while (k === 0n);
    return k;
  };
  const k1 = freshNonce();
  const k2 = reuseNonce ? k1 : freshNonce();

  const sig1 = ecdsaSignWithNonce(z1, d, k1);
  const sig2 = ecdsaSignWithNonce(z2, d, k2);

  const rec = recoverPrivateKey(sig1, z1, sig2, z2);
  const recoveredD = rec?.d ?? null;
  const keyRecovered = recoveredD !== null && recoveredD === d;

  // Acceptance proof: sign a fresh message with the recovered key and hand it to
  // the REAL @noble/curves P-256 verifier against the untouched public key.
  const forgedMessage = 'Transfer $1,000,000 to the attacker.';
  let forgeryAccepted = false;
  if (recoveredD !== null) {
    try {
      const recoveredPriv = bigintTo32Bytes(recoveredD);
      const forgedSig = p256.sign(
        new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(forgedMessage))),
        recoveredPriv,
        { prehash: false },
      );
      forgeryAccepted = p256.verify(
        forgedSig,
        new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(forgedMessage))),
        pub,
        { prehash: false },
      );
    } catch {
      forgeryAccepted = false;
    }
  }

  const toHex = (x: bigint): string => x.toString(16).padStart(64, '0');
  return {
    reuseNonce,
    realPrivHex: toHex(d),
    recoveredPrivHex: recoveredD === null ? null : toHex(recoveredD),
    keyRecovered,
    r1Hex: toHex(sig1.r),
    r2Hex: toHex(sig2.r),
    sharedNonce: sig1.r === sig2.r,
    forgedMessage,
    forgeryAccepted,
  };
}

export type DeterminismResult = {
  sigHex1: string;
  sigHex2: string;
  /** measured byte-for-byte equality of two independent Ed25519 signings */
  identical: boolean;
};

/**
 * Sign the same (message, key) twice with real Ed25519 and MEASURE whether the
 * two 64-byte signatures are byte-for-byte identical. Nothing is asserted from
 * the inputs — the bytes are compared.
 */
export function ed25519SignTwice(message: string, privateKey: Uint8Array): DeterminismResult {
  const msg = new TextEncoder().encode(message);
  const sig1 = ed25519.sign(msg, privateKey);
  const sig2 = ed25519.sign(msg, privateKey);
  const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  const h1 = hex(sig1);
  const h2 = hex(sig2);
  return { sigHex1: h1, sigHex2: h2, identical: h1 === h2 && sig1.length === sig2.length };
}
