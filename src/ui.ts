export function mountApp(): void {
  const root = document.querySelector<HTMLDivElement>('#app');
  if (!root) {
    throw new Error('Missing #app root element');
  }

  root.innerHTML = `
    <main class="lab-shell" aria-live="polite">
      <header class="lab-topbar">
        <a class="portfolio-badge" href="https://systemslibrarian.github.io/crypto-lab/" target="_blank" rel="noreferrer">crypto-lab portfolio</a>
        <button id="theme-toggle" class="theme-toggle" type="button" aria-label="Toggle dark and light mode">☀️ / 🌙</button>
      </header>

      <section class="hero-copy">
        <h1>Ed25519 Forge</h1>
        <p>Interactive key generation, deterministic signing, and verification on Curve25519.</p>
      </section>

      <section class="panel-grid">
        <article class="panel" id="panel-key-forge">
          <h2>Panel A - KEY FORGE</h2>
          <button id="generate-keypair" type="button">Generate Keypair</button>
          <div class="field-stack">
            <label for="private-key-display">Private Key (truncated hex)</label>
            <output id="private-key-display" class="mono block">-</output>
            <small>32-byte private scalar - never fully displayed in UI</small>
          </div>
          <div class="field-stack">
            <label for="public-key-display">Public Key (hex)</label>
            <output id="public-key-display" class="mono block">-</output>
            <button id="copy-public-key" type="button" disabled>Copy Public Key</button>
            <small>32-byte private scalar -> 32-byte compressed point on Curve25519</small>
          </div>
        </article>

        <article class="panel" id="panel-sign">
          <h2>Panel B - SIGN</h2>
          <label for="sign-message">Message</label>
          <textarea id="sign-message" rows="5">The nonce never repeats.</textarea>
          <button id="sign-message-btn" type="button" disabled>Sign Message</button>
          <div class="field-stack">
            <label for="signature-display">Signature (hex)</label>
            <output id="signature-display" class="mono block scroll">-</output>
            <button id="copy-signature" type="button" disabled>Copy Signature</button>
            <small>64 bytes (R: 32 || S: 32)</small>
          </div>
        </article>

        <article class="panel" id="panel-verify">
          <h2>Panel C - VERIFY</h2>
          <label for="verify-public-key">Public Key</label>
          <textarea id="verify-public-key" class="mono" rows="3" placeholder="Hex public key"></textarea>
          <label for="verify-message">Message</label>
          <textarea id="verify-message" rows="4" placeholder="Message to verify"></textarea>
          <label for="verify-signature">Signature</label>
          <textarea id="verify-signature" class="mono" rows="4" placeholder="Hex signature"></textarea>
          <div class="verify-actions">
            <button id="verify-btn" type="button" disabled>Verify ✓</button>
            <button id="tamper-verify-btn" type="button" disabled>Tamper & Verify ✗</button>
          </div>
          <div id="verify-result" class="verify-result neutral">
            Awaiting keypair, signature, and verification input.
          </div>
        </article>
      </section>

      <details class="why-matters" id="why-matters">
        <summary>Why this matters</summary>
        <p>Ed25519 avoids the catastrophic nonce-reuse failures that historically exposed private keys in ECDSA systems.</p>
      </details>
    </main>
  `;

  const themeToggle = document.querySelector<HTMLButtonElement>('#theme-toggle');
  themeToggle?.addEventListener('click', () => {
    const current = document.documentElement.dataset.theme ?? 'dark';
    const nextTheme = current === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = nextTheme;
  });
}
