import type { Keypair } from './forge';

const THEME_STORAGE_KEY = 'theme';

// Lazy-load the crypto module (which pulls in @noble/curves) so it is kept off
// the initial critical path. It is fetched on first interaction intent and
// cached, so the first click resolves instantly.
type ForgeModule = typeof import('./forge');
let forgePromise: Promise<ForgeModule> | null = null;
const loadForge = (): Promise<ForgeModule> => (forgePromise ??= import('./forge'));

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

  const srStatus = document.querySelector<HTMLDivElement>('#sr-status');
  const themeIcon = themeToggle.querySelector<HTMLSpanElement>('.theme-toggle-icon');

  let activeKeypair: Keypair | null = null;
  let currentSignature: Uint8Array | null = null;

  // Concise, screen-reader-only announcer. Avoids reading long hex strings aloud
  // via the output elements' implicit live regions (those are set to aria-live="off").
  const announce = (message: string): void => {
    if (!srStatus) return;
    srStatus.textContent = '';
    // Re-assign on the next frame so repeated identical messages still announce.
    requestAnimationFrame(() => {
      srStatus.textContent = message;
    });
  };

  const setResult = (label: 'VALID' | 'INVALID' | 'NEUTRAL', reason: string): void => {
    verifyResult.classList.remove('valid', 'invalid', 'neutral');
    if (label === 'VALID') {
      verifyResult.classList.add('valid');
      verifyResult.innerHTML = `<span class="result-icon" aria-hidden="true">✓</span><strong>VALID</strong> — ${reason}`;
      announce(`Valid. ${reason}`);
      return;
    }
    if (label === 'INVALID') {
      verifyResult.classList.add('invalid');
      verifyResult.innerHTML = `<span class="result-icon" aria-hidden="true">✗</span><strong>INVALID</strong> — ${reason}`;
      announce(`Invalid. ${reason}`);
      return;
    }

    verifyResult.classList.add('neutral');
    verifyResult.textContent = reason;
    announce(reason);
  };

  const refreshButtons = (): void => {
    signButton.disabled = activeKeypair === null;
    const pubRaw = verifyPublicKeyInput.value.trim();
    const sigRaw = verifySignatureInput.value.trim();
    const pub = parseHex(verifyPublicKeyInput.value);
    const sig = parseHex(verifySignatureInput.value);
    const canVerify = !!pub && !!sig;
    verifyButton.disabled = !canVerify;
    tamperVerifyButton.disabled = !canVerify;
    copyPublicButton.disabled = activeKeypair === null;
    copySignatureButton.disabled = currentSignature === null;

    // Flag malformed-but-non-empty hex so assistive tech reports the field state.
    verifyPublicKeyInput.setAttribute('aria-invalid', pubRaw.length > 0 && !pub ? 'true' : 'false');
    verifySignatureInput.setAttribute('aria-invalid', sigRaw.length > 0 && !sig ? 'true' : 'false');
  };

  const syncToggle = (): void => {
    const current = document.documentElement.getAttribute('data-theme') ?? 'dark';
    const isDark = current === 'dark';
    if (themeIcon) {
      themeIcon.textContent = isDark ? '🌙' : '☀️';
    }
    themeToggle.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
    themeToggle.setAttribute('aria-pressed', isDark ? 'false' : 'true');
  };

  syncToggle();

  themeToggle.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme') ?? 'dark';
    const nextTheme = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', nextTheme);
    localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
    syncToggle();
  });

  generateButton.addEventListener('click', async () => {
    const { generateKeypair } = await loadForge();
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

  signButton.addEventListener('click', async () => {
    if (!activeKeypair) {
      setResult('INVALID', 'Generate a keypair before signing.');
      refreshButtons();
      return;
    }

    const { signMessage } = await loadForge();
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

  verifyButton.addEventListener('click', async () => {
    const pub = parseHex(verifyPublicKeyInput.value);
    const sig = parseHex(verifySignatureInput.value);
    const msg = verifyMessageInput.value;

    if (!pub || !sig) {
      setResult('INVALID', 'Provide valid hex for key/signature.');
      refreshButtons();
      return;
    }

    try {
      const { verifySignature } = await loadForge();
      const valid = verifySignature(msg, sig, pub);
      signatureDisplay.textContent = toGroupedHex(sig);
      if (valid) {
        setResult('VALID', 'Signature matches message and public key.');
      } else {
        setResult('INVALID', 'Signature does not match the supplied message/public key.');
      }
    } catch {
      setResult('INVALID', 'Verification failed: invalid key or signature format.');
    }
    refreshButtons();
  });

  tamperVerifyButton.addEventListener('click', async () => {
    const pub = parseHex(verifyPublicKeyInput.value);
    const sig = parseHex(verifySignatureInput.value);
    const msg = verifyMessageInput.value;

    if (!pub || !sig) {
      setResult('INVALID', 'Cannot tamper: missing or invalid input values.');
      refreshButtons();
      return;
    }

    const { tamperSignature, verifySignature } = await loadForge();

    let tampered: Uint8Array;
    try {
      tampered = tamperSignature(sig);
    } catch {
      setResult('INVALID', 'Cannot tamper: signature must be at least 33 bytes.');
      refreshButtons();
      return;
    }

    try {
      const valid = verifySignature(msg, tampered, pub);
      currentSignature = tampered;
      verifySignatureInput.value = toRawHex(tampered);
      signatureDisplay.innerHTML = toGroupedHexHtml(tampered, 32);
      if (!valid) {
        setResult('INVALID', 'Tampered byte at index 32 invalidated the signature.');
      } else {
        setResult('VALID', 'Unexpectedly valid after tampering. Check inputs carefully.');
      }
    } catch {
      setResult('INVALID', 'Verification failed: invalid key or signature format.');
    }
    refreshButtons();
  });

  copyPublicButton.addEventListener('click', async () => {
    if (!activeKeypair) {
      return;
    }

    try {
      await navigator.clipboard.writeText(toRawHex(activeKeypair.publicKey));
      withCopiedState(copyPublicButton, 'Copy Public Key');
      announce('Public key copied to clipboard.');
    } catch {
      announce('Could not copy: clipboard unavailable.');
    }
  });

  copySignatureButton.addEventListener('click', async () => {
    if (!currentSignature) {
      return;
    }

    try {
      await navigator.clipboard.writeText(toRawHex(currentSignature));
      withCopiedState(copySignatureButton, 'Copy Signature');
      announce('Signature copied to clipboard.');
    } catch {
      announce('Could not copy: clipboard unavailable.');
    }
  });

  signMessageInput.addEventListener('input', () => {
    verifyMessageInput.value = signMessageInput.value;
    refreshButtons();
  });

  verifyPublicKeyInput.addEventListener('input', refreshButtons);
  verifyMessageInput.addEventListener('input', refreshButtons);
  verifySignatureInput.addEventListener('input', refreshButtons);

  // Warm the crypto chunk on first hint of intent (hover/focus) so the first
  // click resolves with no perceptible delay, while keeping it off page load.
  const warm = () => void loadForge();
  generateButton.addEventListener('pointerenter', warm, { once: true });
  generateButton.addEventListener('focus', warm, { once: true });

  const tabButtons = Array.from(document.querySelectorAll<HTMLButtonElement>('.tab-btn'));
  const tabPanels = Array.from(document.querySelectorAll<HTMLElement>('.tab-panel'));

  const activateTab = (tabButton: HTMLButtonElement): void => {
    const targetTab = tabButton.dataset.tab;
    if (!targetTab) return;
    for (const button of tabButtons) {
      const selected = button === tabButton;
      button.classList.toggle('active', selected);
      button.setAttribute('aria-selected', selected ? 'true' : 'false');
      button.setAttribute('tabindex', selected ? '0' : '-1');
    }
    for (const panel of tabPanels) {
      const isTarget = panel.id === targetTab;
      panel.classList.toggle('active', isTarget);
      panel.hidden = !isTarget;
    }
    tabButton.focus();
  };

  for (const tabButton of tabButtons) {
    tabButton.addEventListener('click', () => activateTab(tabButton));

    tabButton.addEventListener('keydown', (e: KeyboardEvent) => {
      const idx = tabButtons.indexOf(tabButton);
      let next = -1;
      if (e.key === 'ArrowRight') next = (idx + 1) % tabButtons.length;
      else if (e.key === 'ArrowLeft') next = (idx - 1 + tabButtons.length) % tabButtons.length;
      else if (e.key === 'Home') next = 0;
      else if (e.key === 'End') next = tabButtons.length - 1;
      if (next >= 0) {
        e.preventDefault();
        activateTab(tabButtons[next]);
      }
    });
  }

  // Set initial tabindex: only active tab is in tab order
  for (const button of tabButtons) {
    button.setAttribute('tabindex', button.classList.contains('active') ? '0' : '-1');
  }

  refreshButtons();
}
