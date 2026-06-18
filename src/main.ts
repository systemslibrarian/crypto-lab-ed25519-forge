import './style.css';
import { mountApp } from './ui';

mountApp();

// Dev-only self-test: confirms the crypto primitives round-trip and that a
// tampered signature fails. Stripped from production builds, and dynamically
// imported so @noble/curves never touches the production entry chunk.
if (import.meta.env.DEV) {
  void (async () => {
    const { generateKeypair, signMessage, tamperSignature, verifySignature } = await import(
      './forge'
    );
    const message = 'Hello, Ed25519';
    const keypair = generateKeypair();
    const signResult = signMessage(message, keypair.privateKey);
    const isValid = verifySignature(message, signResult.signature, keypair.publicKey);
    const tampered = tamperSignature(signResult.signature);
    const isTamperedValid = verifySignature(message, tampered, keypair.publicKey);

    console.group('Ed25519 self-test');
    console.log('message:', message);
    console.log('privateKeyLength:', keypair.privateKey.length);
    console.log('publicKeyLength:', keypair.publicKey.length);
    console.log('signatureLength:', signResult.signature.length);
    console.log('verify(original):', isValid);
    console.log('verify(tampered):', isTamperedValid);
    console.groupEnd();
  })();
}
