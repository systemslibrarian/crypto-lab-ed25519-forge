import {
  generateKeypair,
  signMessage,
  tamperSignature,
  verifySignature,
  type Keypair,
} from './forge';

const THEME_STORAGE_KEY = 'theme';

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
        <button id="theme-toggle" class="theme-toggle" type="button" style="position: absolute; top: 0; right: 0;" aria-label="Switch to light mode">🌙</button>
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
        <p>Most signature schemes require a random nonce per signature. If that RNG fails - even once - your private key is exposed. Ed25519 eliminates this entire class of failure by deriving the nonce deterministically from the private key and message. Sony's PlayStation 3 was broken because their ECDSA implementation used a constant nonce. Ed25519 makes that mistake structurally impossible.</p>
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
          <p>Ed25519 uses deterministic nonces, derived from private key material and message, so nonce RNG failure cannot expose keys the way bad ECDSA nonce generation can. Its group has cofactor = 8, which affects validation rules and small-subgroup edge cases. Ed25519 is commonly batch-verified, often verifies around 2x faster than P-256 ECDSA in practical stacks, and always outputs compact 64-byte signatures (instead of variable-length DER encoding).</p>
        </article>
        <article id="tab-2" class="tab-panel" role="tabpanel" hidden>
          <h3>The Math</h3>
          <p>Ed25519 is built on a Twisted Edwards curve using the form ax^2 + y^2 = 1 + dx^2y^2 over a prime field Fp with about 255 bits. The base point G is fixed; your private scalar multiplies G to produce the public point. Scalar multiplication is repeated point addition and doubling, which is why efficient point formulas matter. The field size drives the Curve25519 naming.</p>
          <pre class="ascii-diagram">P + Q = R
   P o-----\
            \  combine slopes
             \___ o R
             /
   Q o------/</pre>
        </article>
        <article id="tab-3" class="tab-panel" role="tabpanel" hidden>
          <h3>Pitfalls & ZIP215</h3>
          <p>Before ZIP215-aligned behavior, signature acceptance around edge cases and cofactor clearing could vary by library, enabling practical malleability and consensus disagreement risks. Verifying the same signature in two different libraries could produce conflicting outcomes. Monero was impacted by this class of ambiguity. ZIP215 standardized consensus-safe verification behavior so implementations agree. Reference: <a href="https://zips.z.cash/zip-0215" target="_blank" rel="noreferrer">ZIP-0215</a>.</p>
        </article>
        <article id="tab-4" class="tab-panel" role="tabpanel" hidden>
          <h3>Where It's Used</h3>
          <p>Ed25519 appears in Signal, SSH (OpenSSH defaults since 2014), TLS 1.3 deployments, WireGuard tooling, Zcash-related systems, and the age encryption tool. Ethereum account signatures use secp256k1, while consensus-layer cryptography in adjacent ecosystems often involves BLS-style primitives.</p>
        </article>
      </section>

      <section class="related-links" aria-label="Related crypto-lab demos">
        <h3>Explore Related Demos</h3>
        <a href="https://systemslibrarian.github.io/crypto-lab-rsa-forge/" target="_blank" rel="noreferrer">rsa-forge</a>
        <a href="https://systemslibrarian.github.io/crypto-lab-dilithium-seal/" target="_blank" rel="noreferrer">dilithium-seal</a>
        <a href="https://systemslibrarian.github.io/crypto-lab-curve-lens/" target="_blank" rel="noreferrer">curve-lens</a>
        <a href="https://systemslibrarian.github.io/crypto-lab-frost-threshold/" target="_blank" rel="noreferrer">frost-threshold</a>
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

  const syncToggle = (): void => {
    const current = document.documentElement.getAttribute('data-theme') ?? 'dark';
    if (current === 'dark') {
      themeToggle.textContent = '🌙';
      themeToggle.setAttribute('aria-label', 'Switch to light mode');
    } else {
      themeToggle.textContent = '☀️';
      themeToggle.setAttribute('aria-label', 'Switch to dark mode');
    }
  };

  syncToggle();

  themeToggle.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme') ?? 'dark';
    const nextTheme = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', nextTheme);
    localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
    syncToggle();
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
