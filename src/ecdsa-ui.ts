/**
 * ecdsa-ui.ts — DOM wiring for the live ECDSA nonce-reuse exhibit and the
 * measured Ed25519 determinism check. All cryptography lives in ecdsa.ts (pure,
 * node-testable); this file only renders results.
 */

import { runEcdsaNonceReuse, ed25519SignTwice, type NonceReuseResult } from './ecdsa';
import { ed25519 } from '@noble/curves/ed25519.js';

function escapeHtml(s: string): string {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

function trunc(hex: string): string {
  return `${hex.slice(0, 16)}…${hex.slice(-16)}`;
}

function renderEcdsa(out: HTMLElement, r: NonceReuseResult): void {
  const rows = `
    <dl class="ecdsa-rows">
      <div><dt>r from signature #1</dt><dd class="mono">${trunc(r.r1Hex)}</dd></div>
      <div><dt>r from signature #2</dt><dd class="mono">${trunc(r.r2Hex)}</dd></div>
      <div><dt>Shared nonce? (r₁ = r₂)</dt><dd>${r.sharedNonce ? 'YES — nonce reused' : 'no — nonces differ'}</dd></div>
      <div><dt>Real private key d</dt><dd class="mono">${trunc(r.realPrivHex)}</dd></div>
      <div><dt>Recovered d</dt><dd class="mono">${r.recoveredPrivHex ? trunc(r.recoveredPrivHex) : '— (recovery refused)'}</dd></div>
    </dl>`;

  if (r.keyRecovered && r.forgeryAccepted) {
    out.innerHTML = `${rows}
      <p class="ecdsa-verdict leaked" data-verdict="leaked">
        ⚠ Private key RECOVERED — it matches the real key exactly. A fresh message
        (“${escapeHtml(r.forgedMessage)}”) signed with the recovered key was
        <strong>ACCEPTED by the real P-256 verifier</strong> against the untouched
        public key. One nonce slip = total key compromise.
      </p>`;
  } else if (!r.sharedNonce) {
    out.innerHTML = `${rows}
      <p class="ecdsa-verdict safe" data-verdict="safe">
        ✓ Nonces differed, so r₁ ≠ r₂ and there is no shared structure to exploit.
        Recovery is refused and the forgery attempt is <strong>REJECTED</strong>.
        This is exactly the property a deterministic (or simply never-repeating)
        nonce guarantees.
      </p>`;
  } else {
    out.innerHTML = `${rows}
      <p class="ecdsa-verdict safe" data-verdict="error">Unexpected result — recovery did not complete.</p>`;
  }
  out.hidden = false;
}

export function mountEcdsaDemo(): void {
  const reuseBtn = document.querySelector<HTMLButtonElement>('#ecdsa-reuse-btn');
  const controlBtn = document.querySelector<HTMLButtonElement>('#ecdsa-control-btn');
  const out = document.querySelector<HTMLDivElement>('#ecdsa-output');

  const run = async (reuse: boolean): Promise<void> => {
    if (!out) return;
    out.hidden = false;
    out.innerHTML = '<p class="ecdsa-running">Running on real P-256…</p>';
    try {
      const r = await runEcdsaNonceReuse('Pay Alice $10', 'Pay Alice $20', reuse);
      renderEcdsa(out, r);
    } catch (e) {
      out.innerHTML = `<p class="ecdsa-verdict safe">Error: ${escapeHtml((e as Error).message)}</p>`;
    }
  };

  reuseBtn?.addEventListener('click', () => void run(true));
  controlBtn?.addEventListener('click', () => void run(false));

  // Measured Ed25519 determinism.
  const detBtn = document.querySelector<HTMLButtonElement>('#determinism-measure-btn');
  const detOut = document.querySelector<HTMLDivElement>('#determinism-measure-output');
  detBtn?.addEventListener('click', () => {
    if (!detOut) return;
    const priv = ed25519.utils.randomSecretKey();
    const r = ed25519SignTwice('The nonce never repeats.', priv);
    detOut.hidden = false;
    detOut.innerHTML = `
      <dl class="ecdsa-rows">
        <div><dt>Signature #1</dt><dd class="mono">${trunc(r.sigHex1)}</dd></div>
        <div><dt>Signature #2</dt><dd class="mono">${trunc(r.sigHex2)}</dd></div>
      </dl>
      <p class="ecdsa-verdict ${r.identical ? 'safe' : 'leaked'}" data-verdict="${r.identical ? 'identical' : 'differ'}">
        ${r.identical
          ? '✓ IDENTICAL — the two independent signings produced byte-for-byte identical signatures. No RNG was consulted; the nonce is a deterministic function of (key, message).'
          : '⚠ DIFFERENT — signatures diverged, which would indicate a non-deterministic implementation.'}
      </p>`;
  });
}
