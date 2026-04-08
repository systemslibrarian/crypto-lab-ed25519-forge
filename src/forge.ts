import { ed25519 } from '@noble/curves/ed25519.js';

export type Keypair = {
	privateKey: Uint8Array;
	publicKey: Uint8Array;
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
