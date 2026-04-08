# crypto-lab-ed25519-forge

## What It Is

Ed25519 Forge is an interactive browser demo of Ed25519 keypair generation, message signing, and signature verification using the `@noble/curves` library. Ed25519 is an Edwards-curve Digital Signature Algorithm providing 128-bit security equivalent, operating on the twisted Edwards form of Curve25519 over a ~255-bit prime field. It solves the problem of producing compact, deterministic digital signatures: the nonce is derived from the private key and message rather than from a random number generator, eliminating the class of key-exposure failures caused by nonce reuse or weak RNG. The security model assumes the hardness of the elliptic curve discrete logarithm problem on Curve25519.

## When to Use It

- **SSH authentication keys** — Ed25519 is the default key type in OpenSSH since 2014, offering short keys (32-byte public) and fast operations compared to RSA.
- **Protocol message signing with compact signatures** — At 64 bytes per signature with no DER overhead, Ed25519 is well-suited for bandwidth- or storage-constrained protocols like WireGuard and TLS 1.3.
- **Systems requiring deterministic signature output** — Because the nonce is derived from key + message, the same inputs always produce the same signature, simplifying testing and eliminating RNG-dependent failure modes.
- **High-throughput verification workloads** — Ed25519 verification is roughly 2x faster than P-256 ECDSA in practice, making it a strong choice for systems verifying many signatures.
- **Do NOT use Ed25519 for key agreement or encryption** — Ed25519 is a signature scheme; for Diffie-Hellman key exchange on the same curve family, use X25519 instead.

## Live Demo

[https://systemslibrarian.github.io/crypto-lab-ed25519-forge/](https://systemslibrarian.github.io/crypto-lab-ed25519-forge/)

The demo lets you generate an Ed25519 keypair, sign an arbitrary text message, and verify the resulting 64-byte signature. You can also tamper a single bit in the signature (byte index 32, XOR 0x01) and re-verify to observe deterministic failure. All hex displays are uppercase with 4-byte grouping; the private key is truncated to first/last 8 hex characters.

## What Can Go Wrong

- **Cross-library verification disagreement (pre-ZIP215)** — Before ZIP215 standardized Ed25519 verification behavior, different implementations could return conflicting valid/invalid results for the same signature due to inconsistent cofactor handling and small-subgroup point checks. Monero was affected by this ambiguity.
- **Signature malleability from cofactor=8** — The Ed25519 group has cofactor 8, meaning up to 8 equivalent points can represent the same logical value. Without cofactor-aware verification, an attacker can produce a second valid signature from an existing one, which breaks systems that treat signatures as unique identifiers.
- **Clamping errors in custom implementations** — Ed25519 private key processing requires specific bit manipulation (clearing low bits, setting a high bit) of the SHA-512 hash of the seed. Incorrect clamping produces keys that may work locally but fail interoperability or leak information about the scalar.
- **Confusing Ed25519 seed vs. expanded private key** — The 32-byte seed is hashed to produce the 64-byte expanded key; using the raw seed where the expanded key is expected (or vice versa) is a common implementation bug that produces invalid signatures silently.

## Real-World Usage

- **OpenSSH** — Ed25519 has been the default key type since OpenSSH 6.5 (2014), used for both user authentication and host keys.
- **Signal Protocol** — Signal uses Ed25519 (via XEdDSA) for identity keys and signed prekeys in the X3DH key agreement protocol.
- **WireGuard** — Ed25519 is used alongside X25519 for authenticating peers in the Noise protocol framework that WireGuard implements.
- **TLS 1.3** — Ed25519 is a named signature scheme (ed25519 in RFC 8446) for certificate verification and handshake authentication.
- **age encryption tool** — The age file encryption tool uses Ed25519 keys as the identity/recipient system for its public-key encryption mode.

---

"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31
