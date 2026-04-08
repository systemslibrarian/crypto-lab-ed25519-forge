import {
  generateKeypair,
  signMessage,
  tamperSignature,
  verifySignature,
  type Keypair,
} from './forge';

const THEME_STORAGE_KEY = 'ed25519-forge-theme';

function toRawHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('').toUpperCase();
}

function toGroupedHex(bytes: Uint8Array): string {
  const pairs = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0').toUpperCase());
  const grouped: string[] = [];
  for (let i = 0; i < pairs.length; i += 4) {
    grouped.push(pairs.slice(i, i + 4).join(''));
  }
  return grouped.join(' ');
}

function toGroupedHexHtml(bytes: Uint8Array, highlightedByteIndex?: number): string {
  const pairs = Array.from(bytes, (byte, index) => {
    const hex = byte.toString(16).padStart(2, '0').toUpperCase();
    if (index === highlightedByteIndex) {
      return `<span class="tampered-byte">${hex}</span>`;
    }
    return hex;
  });

  const grouped: string[] = [];
  for (let i = 0; i < pairs.length; i += 4) {
    grouped.push(pairs.slice(i, i + 4).join(''));
  }
  return grouped.join(' ');
}

function truncateKeyHex(rawHex: string): string {
  if (rawHex.length <= 16) {
    return rawHex;
  }
  return `${rawHex.slice(0, 8)}...${rawHex.slice(-8)}`;
}

function parseHex(input: string): Uint8Array | null {
  const normalized = input.replace(/[^A-Fa-f0-9]/g, '');
  if (normalized.length === 0 || normalized.length % 2 !== 0) {
    return null;
  }

  const output = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < normalized.length; i += 2) {
    const value = Number.parseInt(normalized.slice(i, i + 2), 16);
    if (Number.isNaN(value)) {
      return null;
    }
    output[i / 2] = value;
  }
  return output;
}

function withCopiedState(button: HTMLButtonElement, baseText: string): void {
  const oldDisabled = button.disabled;
  button.disabled = true;
  button.textContent = 'Copied!';
  setTimeout(() => {
    button.textContent = baseText;
    button.disabled = oldDisabled;
  }, 1500);
}

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

      <section class="info-panel">
        <div class="tabs" role="tablist" aria-label="Ed25519 educational tabs">
          <button class="tab-btn active" data-tab="tab-1" role="tab" aria-selected="true" aria-controls="tab-1">Ed25519 vs ECDSA</button>
          <button class="tab-btn" data-tab="tab-2" role="tab" aria-selected="false" aria-controls="tab-2">The Math</button>
          <button class="tab-btn" data-tab="tab-3" role="tab" aria-selected="false" aria-controls="tab-3">Pitfalls & ZIP215</button>
          <button class="tab-btn" data-tab="tab-4" role="tab" aria-selected="false" aria-controls="tab-4">Where It's Used</button>
        </div>
        <article id="tab-1" class="tab-panel active" role="tabpanel">
          <h3>Ed25519 vs ECDSA</h3>
          <p>Ed25519 derives nonces deterministically from key+message, removing RNG failure as a key-leak vector. It uses cofactor-aware Edwards arithmetic, supports batch verification in many workflows, and typically verifies around 2x faster than P-256 ECDSA in practical libraries. Ed25519 signatures are fixed 64 bytes, unlike DER-encoded ECDSA signatures with variable length.</p>
        </article>
        <article id="tab-2" class="tab-panel" role="tabpanel" hidden>
          <h3>The Math</h3>
          <p>Ed25519 uses a Twisted Edwards curve over the prime field of size roughly 2^255. Private scalars multiply a fixed base point G to get the public key. Scalar multiplication is repeated point addition and doubling.</p>
          <pre class="ascii-diagram">P + Q = R
   P o----\
          \  chord/tangent rule
           \____ o R
          /
   Q o---/</pre>
        </article>
        <article id="tab-3" class="tab-panel" role="tabpanel" hidden>
          <h3>Pitfalls & ZIP215</h3>
          <p>Historically, libraries disagreed on edge-case point validation and cofactor handling. That meant one implementation could accept a signature another rejected. ZIP215 standardized consensus-friendly Ed25519 verification behavior to avoid chain splits and cross-library mismatch hazards seen in ecosystems like Monero. Reference: <a href="https://zips.z.cash/zip-0215" target="_blank" rel="noreferrer">ZIP-0215</a>.</p>
        </article>
        <article id="tab-4" class="tab-panel" role="tabpanel" hidden>
          <h3>Where It's Used</h3>
          <p>Ed25519 appears in Signal, SSH (OpenSSH defaults), TLS 1.3 suites, WireGuard tooling, Zcash contexts, and age. Ethereum account signatures use secp256k1, but neighboring consensus systems often use BLS families.</p>
        </article>
      </section>
    </main>
  `;

  const themeToggle = document.querySelector<HTMLButtonElement>('#theme-toggle');
  const privateKeyDisplay = document.querySelector<HTMLOutputElement>('#private-key-display');
  const publicKeyDisplay = document.querySelector<HTMLOutputElement>('#public-key-display');
  const signatureDisplay = document.querySelector<HTMLOutputElement>('#signature-display');
  const verifyResult = document.querySelector<HTMLDivElement>('#verify-result');

  const generateButton = document.querySelector<HTMLButtonElement>('#generate-keypair');
  const signButton = document.querySelector<HTMLButtonElement>('#sign-message-btn');
  const verifyButton = document.querySelector<HTMLButtonElement>('#verify-btn');
  const tamperVerifyButton = document.querySelector<HTMLButtonElement>('#tamper-verify-btn');
  const copyPublicButton = document.querySelector<HTMLButtonElement>('#copy-public-key');
  const copySignatureButton = document.querySelector<HTMLButtonElement>('#copy-signature');

  const signMessageInput = document.querySelector<HTMLTextAreaElement>('#sign-message');
  const verifyPublicKeyInput = document.querySelector<HTMLTextAreaElement>('#verify-public-key');
  const verifyMessageInput = document.querySelector<HTMLTextAreaElement>('#verify-message');
  const verifySignatureInput = document.querySelector<HTMLTextAreaElement>('#verify-signature');

  if (
    !themeToggle ||
    !privateKeyDisplay ||
    !publicKeyDisplay ||
    !signatureDisplay ||
    !verifyResult ||
    !generateButton ||
    !signButton ||
    !verifyButton ||
    !tamperVerifyButton ||
    !copyPublicButton ||
    !copySignatureButton ||
    !signMessageInput ||
    !verifyPublicKeyInput ||
    !verifyMessageInput ||
    !verifySignatureInput
  ) {
    throw new Error('Expected UI element missing from DOM');
  }

  let activeKeypair: Keypair | null = null;
  let currentSignature: Uint8Array | null = null;

  const setResult = (label: 'VALID' | 'INVALID' | 'NEUTRAL', reason: string): void => {
    verifyResult.classList.remove('valid', 'invalid', 'neutral');
    if (label === 'VALID') {
      verifyResult.classList.add('valid');
      verifyResult.innerHTML = `<strong>VALID</strong> - ${reason}`;
      return;
    }
    if (label === 'INVALID') {
      verifyResult.classList.add('invalid');
      verifyResult.innerHTML = `<strong>INVALID</strong> - ${reason}`;
      return;
    }

    verifyResult.classList.add('neutral');
    verifyResult.textContent = reason;
  };

  const refreshButtons = (): void => {
    signButton.disabled = activeKeypair === null;
    const pub = parseHex(verifyPublicKeyInput.value);
    const sig = parseHex(verifySignatureInput.value);
    const hasMessage = verifyMessageInput.value.trim().length > 0;
    const canVerify = !!pub && !!sig && hasMessage;
    verifyButton.disabled = !canVerify;
    tamperVerifyButton.disabled = !canVerify;
    copyPublicButton.disabled = activeKeypair === null;
    copySignatureButton.disabled = currentSignature === null;
  };

  const initialTheme = localStorage.getItem(THEME_STORAGE_KEY) ?? 'dark';
  document.documentElement.dataset.theme = initialTheme;

  themeToggle?.addEventListener('click', () => {
    const current = document.documentElement.dataset.theme ?? 'dark';
    const nextTheme = current === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = nextTheme;
    localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
  });

  generateButton.addEventListener('click', () => {
    const keypair = generateKeypair();
    activeKeypair = keypair;
    currentSignature = null;

    const privateHexRaw = toRawHex(keypair.privateKey);
    const publicHexRaw = toRawHex(keypair.publicKey);
    privateKeyDisplay.textContent = truncateKeyHex(privateHexRaw);
    publicKeyDisplay.textContent = toGroupedHex(keypair.publicKey);

    verifyPublicKeyInput.value = publicHexRaw;
    verifyMessageInput.value = signMessageInput.value;
    verifySignatureInput.value = '';
    signatureDisplay.textContent = '-';
    setResult('NEUTRAL', 'Keypair generated. Sign a message to verify.');
    refreshButtons();
  });

  signButton.addEventListener('click', () => {
    if (!activeKeypair) {
      setResult('INVALID', 'Generate a keypair before signing.');
      refreshButtons();
      return;
    }

    const message = signMessageInput.value;
    const signed = signMessage(message, activeKeypair.privateKey);
    currentSignature = signed.signature;

    const signatureHexRaw = toRawHex(signed.signature);
    signatureDisplay.textContent = toGroupedHex(signed.signature);
    verifyMessageInput.value = message;
    verifySignatureInput.value = signatureHexRaw;
    setResult('NEUTRAL', 'Signature created. Ready to verify.');
    refreshButtons();
  });

  verifyButton.addEventListener('click', () => {
    const pub = parseHex(verifyPublicKeyInput.value);
    const sig = parseHex(verifySignatureInput.value);
    const msg = verifyMessageInput.value;

    if (!pub || !sig || msg.length === 0) {
      setResult('INVALID', 'Provide valid hex for key/signature and a non-empty message.');
      refreshButtons();
      return;
    }

    const valid = verifySignature(msg, sig, pub);
    signatureDisplay.textContent = toGroupedHex(sig);
    if (valid) {
      setResult('VALID', 'Signature matches message and public key.');
    } else {
      setResult('INVALID', 'Signature does not match the supplied message/public key.');
    }
    refreshButtons();
  });

  tamperVerifyButton.addEventListener('click', () => {
    const pub = parseHex(verifyPublicKeyInput.value);
    const sig = parseHex(verifySignatureInput.value);
    const msg = verifyMessageInput.value;

    if (!pub || !sig || msg.length === 0) {
      setResult('INVALID', 'Cannot tamper: missing or invalid input values.');
      refreshButtons();
      return;
    }

    let tampered: Uint8Array;
    try {
      tampered = tamperSignature(sig);
    } catch {
      setResult('INVALID', 'Cannot tamper: signature must be at least 33 bytes.');
      refreshButtons();
      return;
    }

    const valid = verifySignature(msg, tampered, pub);
    verifySignatureInput.value = toRawHex(tampered);
    signatureDisplay.innerHTML = toGroupedHexHtml(tampered, 32);
    if (!valid) {
      setResult('INVALID', 'Tampered byte at index 32 invalidated the signature.');
    } else {
      setResult('VALID', 'Unexpectedly valid after tampering. Check inputs carefully.');
    }
    refreshButtons();
  });

  copyPublicButton.addEventListener('click', async () => {
    if (!activeKeypair) {
      return;
    }

    await navigator.clipboard.writeText(toRawHex(activeKeypair.publicKey));
    withCopiedState(copyPublicButton, 'Copy Public Key');
  });

  copySignatureButton.addEventListener('click', async () => {
    if (!currentSignature) {
      return;
    }

    await navigator.clipboard.writeText(toRawHex(currentSignature));
    withCopiedState(copySignatureButton, 'Copy Signature');
  });

  signMessageInput.addEventListener('input', () => {
    verifyMessageInput.value = signMessageInput.value;
    refreshButtons();
  });

  verifyPublicKeyInput.addEventListener('input', refreshButtons);
  verifyMessageInput.addEventListener('input', refreshButtons);
  verifySignatureInput.addEventListener('input', refreshButtons);

  const tabButtons = Array.from(document.querySelectorAll<HTMLButtonElement>('.tab-btn'));
  const tabPanels = Array.from(document.querySelectorAll<HTMLElement>('.tab-panel'));
  for (const tabButton of tabButtons) {
    tabButton.addEventListener('click', () => {
      const targetTab = tabButton.dataset.tab;
      if (!targetTab) {
        return;
      }

      for (const button of tabButtons) {
        const selected = button === tabButton;
        button.classList.toggle('active', selected);
        button.setAttribute('aria-selected', selected ? 'true' : 'false');
      }

      for (const panel of tabPanels) {
        const isTarget = panel.id === targetTab;
        panel.classList.toggle('active', isTarget);
        panel.hidden = !isTarget;
      }
    });
  }

  refreshButtons();
}
