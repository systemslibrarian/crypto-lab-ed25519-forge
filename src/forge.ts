import { ed25519, ED25519_TORSION_SUBGROUP } from '@noble/curves/ed25519.js';

export type Keypair = {
	privateKey: Uint8Array;
	publicKey: Uint8Array;
};

export type CofactorForgery = {
	/** A small-order (torsion) public key: point whose order divides the cofactor 8. */
	publicKey: Uint8Array;
	/** A 64-byte signature crafted so R = [S]·B for the chosen scalar S. */
	signature: Uint8Array;
	/** The message the forged signature is presented against. */
	messageBytes: Uint8Array;
	/** Result under noble's default (ZIP215, cofactored) verification — accepts. */
	zip215Valid: boolean;
	/** Result under strict RFC 8032 / NIST 186-5 verification — rejects. */
	strictValid: boolean;
};

export type SignResult = {
	signature: Uint8Array;
	messageBytes: Uint8Array;
};

export function generateKeypair(): Keypair {
	const privateKey = crypto.getRandomValues(new Uint8Array(32));
	const publicKey = ed25519.getPublicKey(privateKey);
	return { privateKey, publicKey };
}

export type ScalarMultStep = {
	/** The step counter after this operation. */
	index: number;
	/** 'double' or 'add' — the double-and-add operation just performed. */
	op: 'start' | 'double' | 'add';
	/** Normalized affine coordinates in [0, 1) for plotting (x/p, y/p). */
	nx: number;
	ny: number;
	/** Whether this is the final point (equals the public key). */
	isFinal: boolean;
};

/**
 * Produces a REAL double-and-add walk of [scalar]·G on the actual Ed25519
 * group, for the animated scalar-multiplication visual. Nothing here is faked:
 * `scalar` is the genuine clamped scalar derived from the seed (the same value
 * @noble uses internally), and every returned point is a true group element
 * computed with noble's point arithmetic. The final point equals the public key.
 *
 * To keep the animation short and legible we walk the top `bits` bits of the
 * scalar (a coarse but honest prefix of the real double-and-add ladder); the
 * caller then jumps to the exact public point as the final frame, so the walk
 * always terminates on the true key.
 *
 * @param privateKey 32-byte seed.
 * @param bits       How many high bits of the scalar to animate (coarse walk).
 */
export function scalarMultPath(privateKey: Uint8Array, bits = 12): ScalarMultStep[] {
	const { scalar } = ed25519.utils.getExtendedPublicKey(privateKey);
	const p = ed25519.Point.Fp.ORDER;
	const publicPoint = ed25519.Point.BASE.multiplyUnsafe(scalar);

	// The clamped Ed25519 scalar always has bit 254 set, so the ladder's leading
	// bit is deterministic. Walk from the most-significant bit downward.
	const topBit = 254;
	const steps: ScalarMultStep[] = [];

	const norm = (point: typeof ed25519.Point.BASE, index: number, op: ScalarMultStep['op']): ScalarMultStep => {
		const { x, y } = point.toAffine();
		return {
			index,
			op,
			nx: Number(x % p) / Number(p),
			ny: Number(y % p) / Number(p),
			isFinal: false,
		};
	};

	// Start at G (the leading 1 bit initializes the accumulator to the base point).
	let acc = ed25519.Point.BASE;
	let index = 0;
	steps.push(norm(acc, index, 'start'));

	const lastBit = Math.max(0, topBit - bits);
	for (let bit = topBit - 1; bit >= lastBit; bit--) {
		acc = acc.double();
		index++;
		steps.push(norm(acc, index, 'double'));
		if ((scalar >> BigInt(bit)) & 1n) {
			acc = acc.add(ed25519.Point.BASE);
			index++;
			steps.push(norm(acc, index, 'add'));
		}
	}

	// Final frame: the true public point. (The coarse walk above shows the
	// mechanism; this guarantees the animation lands on the real key.)
	const finalStep = norm(publicPoint, index + 1, 'add');
	finalStep.isFinal = true;
	steps.push(finalStep);
	return steps;
}

export function signMessage(message: string, privateKey: Uint8Array): SignResult {
	const messageBytes = new TextEncoder().encode(message);
	const signature = ed25519.sign(messageBytes, privateKey);
	return { signature, messageBytes };
}

export function verifySignature(
	message: string,
	signature: Uint8Array,
	publicKey: Uint8Array,
): boolean {
	const messageBytes = new TextEncoder().encode(message);
	return ed25519.verify(signature, messageBytes, publicKey);
}

export function tamperSignature(signature: Uint8Array): Uint8Array {
	if (signature.length <= 32) {
		throw new Error('Signature must be at least 33 bytes to tamper index 32.');
	}

	const tampered = new Uint8Array(signature);
	tampered[32] ^= 0x01;
	return tampered;
}

/**
 * Demonstrates the real cofactor / small-subgroup malleability the README and
 * "Pitfalls & ZIP215" tab describe — without any hand-waving.
 *
 * Ed25519's group has cofactor h = 8, so eight low-order "torsion" points exist
 * whose order divides 8. `ED25519_TORSION_SUBGROUP` enumerates them. We take a
 * NON-identity torsion point as the "public key" A. Because A is small-order,
 * [8]·A = 0, so it vanishes from the *cofactored* verification equation
 *   [8]·(R + [k]·A − [S]·B) == 0
 * that noble uses by default (ZIP215, consensus-critical). We can therefore hand
 * it a signature we NEVER produced with a secret key: pick a scalar S, set
 * R = [S]·B, and the equation collapses to [8]·[k]·A = 0, which holds for any
 * message. ZIP215 verification ACCEPTS it.
 *
 * Strict RFC 8032 / NIST FIPS 186-5 verification (noble's `{ zip215: false }`)
 * explicitly REJECTS small-order public keys, so it returns false. The same
 * bytes, verified two legitimate ways, disagree — exactly the cross-library
 * ambiguity that affected Monero and motivated ZIP-0215.
 *
 * This forges nothing about a real key holder; it shows that accepting
 * small-order keys makes a "signature" a meaningless artifact.
 *
 * @param message   Message the forged signature is presented against.
 * @param variant   Which of the 7 non-identity torsion points to use (1..7).
 */
export function forgeCofactorSignature(message: string, variant = 1): CofactorForgery {
	const idx = ((variant % 8) + 8) % 8 || 1; // 1..7; never the identity (index 0)
	const publicKey = hexToBytes(ED25519_TORSION_SUBGROUP[idx]);

	// Deterministic non-trivial scalar S in [1, L). Derive from the variant so the
	// forgery is reproducible but not a fixed constant.
	const L = ed25519.Point.Fn.ORDER;
	const s = (BigInt(idx) * 0x1000000000000001n) % L || 1n;

	const sBytes = new Uint8Array(32);
	let acc = s;
	for (let i = 0; i < 32; i++) {
		sBytes[i] = Number(acc & 0xffn);
		acc >>= 8n;
	}

	// R = [S]·B, so that R + [k]·A − [S]·B = [k]·A, which clears under cofactor 8.
	const R = ed25519.Point.BASE.multiplyUnsafe(s).toBytes();

	const signature = new Uint8Array(64);
	signature.set(R, 0);
	signature.set(sBytes, 32);

	const messageBytes = new TextEncoder().encode(message);
	const zip215Valid = ed25519.verify(signature, messageBytes, publicKey); // default = ZIP215
	const strictValid = ed25519.verify(signature, messageBytes, publicKey, { zip215: false });

	return { publicKey, signature, messageBytes, zip215Valid, strictValid };
}

function hexToBytes(hex: string): Uint8Array {
	const out = new Uint8Array(hex.length / 2);
	for (let i = 0; i < out.length; i++) {
		out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	}
	return out;
}
