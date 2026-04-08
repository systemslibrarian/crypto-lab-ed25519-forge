import './style.css';
import {
	generateKeypair,
	signMessage,
	tamperSignature,
	verifySignature,
} from './forge';
import { mountApp } from './ui';

const phase2Message = 'Hello, Ed25519';
const keypair = generateKeypair();
const signResult = signMessage(phase2Message, keypair.privateKey);
const isValid = verifySignature(phase2Message, signResult.signature, keypair.publicKey);
const tampered = tamperSignature(signResult.signature);
const isTamperedValid = verifySignature(phase2Message, tampered, keypair.publicKey);

console.group('Phase 2 Ed25519 Console Test');
console.log('message:', phase2Message);
console.log('privateKeyLength:', keypair.privateKey.length);
console.log('publicKeyLength:', keypair.publicKey.length);
console.log('signatureLength:', signResult.signature.length);
console.log('verify(original):', isValid);
console.log('verify(tampered):', isTamperedValid);
console.groupEnd();

mountApp();
