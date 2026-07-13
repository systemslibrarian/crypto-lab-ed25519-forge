import type { Keypair } from './forge';

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

/**
 * Renders a 64-byte Ed25519 signature as grouped hex, wrapping bytes 0–31 (R,
 * the commitment point) and 32–63 (S, the scalar response) in colored spans so
 * the R||S structure is visible. Optionally highlights a single tampered byte.
 * Falls back to plain grouped hex for non-64-byte inputs.
 */
function toSignatureHtml(bytes: Uint8Array, highlightedByteIndex?: number): string {
  const pair = (byte: number, index: number): string => {
    const hex = byte.toString(16).padStart(2, '0').toUpperCase();
    if (index === highlightedByteIndex) {
      return `<span class="tampered-byte">${hex}</span>`;
    }
    return hex;
  };

  const group = (from: number, to: number): string => {
    const cells: string[] = [];
    for (let i = from; i < to; i += 4) {
      let chunk = '';
      for (let j = i; j < Math.min(i + 4, to); j++) chunk += pair(bytes[j], j);
      cells.push(chunk);
    }
    return cells.join(' ');
  };

  if (bytes.length !== 64) {
    return toGroupedHexHtml(bytes, highlightedByteIndex);
  }
  return (
    `<span class="sig-r">${group(0, 32)}</span>` +
    ` <span class="sig-s">${group(32, 64)}</span>`
  );
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
  const privateKeyDisplay = document.querySelector<HTMLOutputElement>('#private-key-display');
  const publicKeyDisplay = document.querySelector<HTMLOutputElement>('#public-key-display');
  const signatureDisplay = document.querySelector<HTMLOutputElement>('#signature-display');
  const verifyResult = document.querySelector<HTMLDivElement>('#verify-result');

  const generateButton = document.querySelector<HTMLButtonElement>('#generate-keypair');
  const signButton = document.querySelector<HTMLButtonElement>('#sign-message-btn');
  const signAgainButton = document.querySelector<HTMLButtonElement>('#sign-again-btn');
  const verifyButton = document.querySelector<HTMLButtonElement>('#verify-btn');
  const tamperVerifyButton = document.querySelector<HTMLButtonElement>('#tamper-verify-btn');
  const copyPublicButton = document.querySelector<HTMLButtonElement>('#copy-public-key');
  const copySignatureButton = document.querySelector<HTMLButtonElement>('#copy-signature');
  const presetWrongKeyButton = document.querySelector<HTMLButtonElement>('#preset-wrong-key');
  const presetWrongMsgButton = document.querySelector<HTMLButtonElement>('#preset-wrong-msg');

  // Determinism demonstrator (Sign panel).
  const determinismBox = document.querySelector<HTMLDivElement>('#determinism-box');
  const determinismSig1 = document.querySelector<HTMLOutputElement>('#determinism-sig-1');
  const determinismSig2 = document.querySelector<HTMLOutputElement>('#determinism-sig-2');
  const determinismVerdict = document.querySelector<HTMLParagraphElement>('#determinism-verdict');

  // Scalar-multiplication canvas (Key Forge panel).
  const scalarCanvas = document.querySelector<HTMLCanvasElement>('#scalarmult-canvas');
  const scalarStatus = document.querySelector<HTMLParagraphElement>('#scalarmult-status');

  const signMessageInput = document.querySelector<HTMLTextAreaElement>('#sign-message');
  const verifyPublicKeyInput = document.querySelector<HTMLTextAreaElement>('#verify-public-key');
  const verifyMessageInput = document.querySelector<HTMLTextAreaElement>('#verify-message');
  const verifySignatureInput = document.querySelector<HTMLTextAreaElement>('#verify-signature');

  if (
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

  let activeKeypair: Keypair | null = null;
  let currentSignature: Uint8Array | null = null;
  // Remembers the last message+signature so "Sign Again" can prove determinism
  // (and detect when the message changed so we can show the contrast instead).
  let lastSignedMessage: string | null = null;
  let lastSignatureHex: string | null = null;
  let scalarAnimHandle = 0;

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
    if (signAgainButton) signAgainButton.disabled = activeKeypair === null || currentSignature === null;
    const pubRaw = verifyPublicKeyInput.value.trim();
    const sigRaw = verifySignatureInput.value.trim();
    const pub = parseHex(verifyPublicKeyInput.value);
    const sig = parseHex(verifySignatureInput.value);
    const canVerify = !!pub && !!sig;
    verifyButton.disabled = !canVerify;
    tamperVerifyButton.disabled = !canVerify;
    copyPublicButton.disabled = activeKeypair === null;
    copySignatureButton.disabled = currentSignature === null;
    if (presetWrongKeyButton) presetWrongKeyButton.disabled = activeKeypair === null || currentSignature === null;
    if (presetWrongMsgButton) presetWrongMsgButton.disabled = activeKeypair === null || currentSignature === null;

    // Flag malformed-but-non-empty hex so assistive tech reports the field state.
    verifyPublicKeyInput.setAttribute('aria-invalid', pubRaw.length > 0 && !pub ? 'true' : 'false');
    verifySignatureInput.setAttribute('aria-invalid', sigRaw.length > 0 && !sig ? 'true' : 'false');
  };

  // Theme toggling is owned by the shared crypto-lab header (#cl-theme-toggle);
  // this lab no longer ships its own toggle button.

  const cssVar = (name: string): string =>
    getComputedStyle(document.documentElement).getPropertyValue(name).trim() || '#888';

  const prefersReducedMotion = (): boolean =>
    window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;

  // Draws one frame of the scalar-multiplication walk: all points visited so far
  // as small dots, the current point emphasized, and (when done) the public
  // point ringed. Points come from real Ed25519 group arithmetic (forge.ts).
  const animateScalarMult = async (privateKey: Uint8Array): Promise<void> => {
    if (!scalarCanvas || !scalarStatus) return;
    const ctx = scalarCanvas.getContext('2d');
    if (!ctx) return;
    if (scalarAnimHandle) {
      clearTimeout(scalarAnimHandle);
      scalarAnimHandle = 0;
    }

    const { scalarMultPath } = await loadForge();
    const path = scalarMultPath(privateKey, 12);
    const W = scalarCanvas.width;
    const H = scalarCanvas.height;
    const pad = 16;
    const px = (nx: number) => pad + nx * (W - 2 * pad);
    const py = (ny: number) => H - pad - ny * (H - 2 * pad);

    const ink = cssVar('--text');
    const muted = cssVar('--text-muted');
    const accent = cssVar('--accent');
    const valid = cssVar('--valid');
    const line = cssVar('--line');

    const draw = (upTo: number): void => {
      ctx.clearRect(0, 0, W, H);
      // Frame.
      ctx.strokeStyle = line;
      ctx.lineWidth = 1;
      ctx.strokeRect(0.5, 0.5, W - 1, H - 1);
      // Visited points as a faint trail.
      for (let i = 0; i <= upTo && i < path.length; i++) {
        const s = path[i];
        ctx.beginPath();
        ctx.arc(px(s.nx), py(s.ny), i === upTo ? 5 : 2.5, 0, Math.PI * 2);
        if (i === upTo) {
          ctx.fillStyle = s.isFinal ? valid : accent;
        } else {
          ctx.fillStyle = muted;
        }
        ctx.fill();
      }
      // Ring the final (public) point once reached.
      const cur = path[Math.min(upTo, path.length - 1)];
      if (cur.isFinal) {
        ctx.beginPath();
        ctx.arc(px(cur.nx), py(cur.ny), 9, 0, Math.PI * 2);
        ctx.strokeStyle = valid;
        ctx.lineWidth = 2;
        ctx.stroke();
      }
      // Label G at the first point.
      const g = path[0];
      ctx.fillStyle = ink;
      ctx.font = '11px ui-monospace, monospace';
      ctx.fillText('G', px(g.nx) + 7, py(g.ny) - 5);
    };

    const label = (s: (typeof path)[number]): string => {
      if (s.op === 'start') return `Step 0: start at base point G.`;
      if (s.isFinal) return `Done: landed on the public point [scalar]·G after ${s.index} operations.`;
      return `Step ${s.index}: ${s.op === 'double' ? 'double (×2)' : 'add G'} — a real point on the group.`;
    };

    if (prefersReducedMotion()) {
      draw(path.length - 1);
      scalarStatus.textContent = label(path[path.length - 1]);
      return;
    }

    let i = 0;
    const tick = (): void => {
      draw(i);
      scalarStatus.textContent = label(path[i]);
      if (i < path.length - 1) {
        i++;
        scalarAnimHandle = window.setTimeout(tick, 180);
      } else {
        scalarAnimHandle = 0;
      }
    };
    tick();
  };

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

    // Reset the determinism demonstrator for the fresh key.
    lastSignedMessage = null;
    lastSignatureHex = null;
    if (determinismBox) determinismBox.hidden = true;
    if (determinismSig1) determinismSig1.textContent = '-';
    if (determinismSig2) determinismSig2.textContent = '-';

    setResult('NEUTRAL', 'Keypair generated. Sign a message to verify.');
    refreshButtons();

    // Animate the real [scalar]·G double-and-add for this key.
    void animateScalarMult(keypair.privateKey);
  });

  const setDeterminismVerdict = (
    state: 'identical' | 'changed' | 'neutral',
    text: string,
  ): void => {
    if (!determinismVerdict) return;
    determinismVerdict.classList.remove('identical', 'changed', 'neutral');
    determinismVerdict.classList.add(state);
    determinismVerdict.textContent = text;
  };

  // Signs once and updates the primary signature display (with R/S coloring).
  const doSign = async (message: string): Promise<Uint8Array> => {
    const { signMessage } = await loadForge();
    const signed = signMessage(message, activeKeypair!.privateKey);
    currentSignature = signed.signature;
    signatureDisplay.innerHTML = toSignatureHtml(signed.signature);
    verifyMessageInput.value = message;
    verifySignatureInput.value = toRawHex(signed.signature);
    return signed.signature;
  };

  signButton.addEventListener('click', async () => {
    if (!activeKeypair) {
      setResult('INVALID', 'Generate a keypair before signing.');
      refreshButtons();
      return;
    }

    const message = signMessageInput.value;
    const sig = await doSign(message);
    const sigHex = toRawHex(sig);

    if (determinismBox) determinismBox.hidden = false;
    if (lastSignedMessage !== null && determinismSig1 && determinismSig2) {
      // We already had a signature: show the before/after contrast.
      const messageChanged = lastSignedMessage !== message;
      determinismSig1.innerHTML = toSignatureHtml(
        (parseHex(lastSignatureHex ?? '') ?? sig),
      );
      determinismSig2.innerHTML = toSignatureHtml(sig);
      if (messageChanged) {
        setDeterminismVerdict(
          'changed',
          'CHANGED — one edit to the message produced a completely different signature. Signing is deterministic per (key, message), not fixed.',
        );
      } else if (lastSignatureHex === sigHex) {
        setDeterminismVerdict(
          'identical',
          'IDENTICAL — same key + same message always yields the same signature (deterministic nonce).',
        );
      } else {
        setDeterminismVerdict('changed', 'DIFFERENT — signatures do not match.');
      }
    } else if (determinismSig1) {
      determinismSig1.innerHTML = toSignatureHtml(sig);
      if (determinismSig2) determinismSig2.textContent = '-';
      setDeterminismVerdict(
        'neutral',
        'Now click "Sign Again" (same message) to watch the bytes stay identical — or edit the message and re-sign to watch them change.',
      );
    }

    lastSignedMessage = message;
    lastSignatureHex = sigHex;
    setResult('NEUTRAL', 'Signature created. Ready to verify.');
    refreshButtons();
  });

  signAgainButton?.addEventListener('click', async () => {
    if (!activeKeypair || currentSignature === null) return;
    const prevHex = lastSignatureHex;
    const message = signMessageInput.value;
    const sig = await doSign(message);
    const sigHex = toRawHex(sig);

    if (determinismBox) determinismBox.hidden = false;
    if (determinismSig1) determinismSig1.innerHTML = toSignatureHtml(parseHex(prevHex ?? '') ?? sig);
    if (determinismSig2) determinismSig2.innerHTML = toSignatureHtml(sig);

    const messageChanged = lastSignedMessage !== null && lastSignedMessage !== message;
    if (messageChanged) {
      setDeterminismVerdict(
        'changed',
        'CHANGED — the message differs from the previous signing, so the signature changed completely. Edit it back and re-sign to see them match again.',
      );
    } else if (prevHex === sigHex) {
      setDeterminismVerdict(
        'identical',
        'IDENTICAL — same key + same message always yields the same signature (deterministic nonce). No RNG is involved.',
      );
      announce('Signed again. The two signatures are byte-for-byte identical.');
    } else {
      setDeterminismVerdict('changed', 'DIFFERENT — signatures unexpectedly do not match.');
    }

    lastSignedMessage = message;
    lastSignatureHex = sigHex;
    setResult('NEUTRAL', 'Signed again. Compare the two signatures above.');
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
      signatureDisplay.innerHTML = toSignatureHtml(sig);
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
      signatureDisplay.innerHTML = toSignatureHtml(tampered, 32);
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

  // --- Verify failure presets: one click pre-fills a failing scenario --------
  presetWrongKeyButton?.addEventListener('click', async () => {
    if (!activeKeypair || currentSignature === null) return;
    const { generateKeypair, verifySignature } = await loadForge();
    // A real, valid signature over the current message, but verified against a
    // DIFFERENT (freshly generated) honest public key — must be INVALID.
    const other = generateKeypair();
    const msg = signMessageInput.value;
    verifyPublicKeyInput.value = toRawHex(other.publicKey);
    verifyMessageInput.value = msg;
    verifySignatureInput.value = toRawHex(currentSignature);
    signatureDisplay.innerHTML = toSignatureHtml(currentSignature);
    const valid = verifySignature(msg, currentSignature, other.publicKey);
    if (valid) {
      setResult('VALID', 'Unexpectedly valid — check inputs.');
    } else {
      setResult(
        'INVALID',
        'Wrong public key: the signature was made by a different key, so verification rejects it. Verification checks the signature against THIS key, not just its shape.',
      );
    }
    refreshButtons();
  });

  presetWrongMsgButton?.addEventListener('click', async () => {
    if (!activeKeypair || currentSignature === null) return;
    const { verifySignature } = await loadForge();
    // The real key + real signature, but a modified message — must be INVALID.
    const original = signMessageInput.value;
    const modified = `${original} (edited)`;
    verifyPublicKeyInput.value = toRawHex(activeKeypair.publicKey);
    verifyMessageInput.value = modified;
    verifySignatureInput.value = toRawHex(currentSignature);
    signatureDisplay.innerHTML = toSignatureHtml(currentSignature);
    const valid = verifySignature(modified, currentSignature, activeKeypair.publicKey);
    if (valid) {
      setResult('VALID', 'Unexpectedly valid — check inputs.');
    } else {
      setResult(
        'INVALID',
        'Modified message: the signature commits to the exact original bytes, so appending " (edited)" makes verification reject it.',
      );
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

  // --- Live cofactor / small-subgroup malleability demo (Pitfalls & ZIP215) ---
  const cofactorRun = document.querySelector<HTMLButtonElement>('#cofactor-run');
  const cofactorPubkey = document.querySelector<HTMLOutputElement>('#cofactor-pubkey');
  const cofactorSig = document.querySelector<HTMLOutputElement>('#cofactor-sig');
  const cofactorZip215 = document.querySelector<HTMLDivElement>('#cofactor-zip215');
  const cofactorStrict = document.querySelector<HTMLDivElement>('#cofactor-strict');
  const cofactorGrid = document.querySelector<HTMLDivElement>('.cofactor-grid');

  if (cofactorRun && cofactorPubkey && cofactorSig && cofactorZip215 && cofactorStrict) {
    let cofactorVariant = 0;

    const setVerdict = (el: HTMLDivElement, valid: boolean): void => {
      const result = el.querySelector<HTMLSpanElement>('.cofactor-result');
      el.classList.remove('neutral', 'valid', 'invalid');
      el.classList.add(valid ? 'valid' : 'invalid');
      if (result) result.textContent = valid ? 'ACCEPTS ✓' : 'REJECTS ✗';
    };

    cofactorRun.addEventListener('click', async () => {
      const { forgeCofactorSignature } = await loadForge();
      // Cycle through the 7 non-identity torsion points so repeated clicks show
      // this is not a single canned example.
      cofactorVariant = (cofactorVariant % 7) + 1;
      const forgery = forgeCofactorSignature('I never signed this', cofactorVariant);

      cofactorPubkey.textContent = toGroupedHex(forgery.publicKey);
      // Reuse the same R/S coloring as the Sign panel so the "R = [S]·B" trick is legible.
      cofactorSig.innerHTML = toSignatureHtml(forgery.signature);
      cofactorGrid?.setAttribute('aria-hidden', 'false');
      setVerdict(cofactorZip215, forgery.zip215Valid);
      setVerdict(cofactorStrict, forgery.strictValid);

      announce(
        `Cofactor demo: ZIP215 ${forgery.zip215Valid ? 'accepts' : 'rejects'}, ` +
          `strict RFC 8032 ${forgery.strictValid ? 'accepts' : 'rejects'} the same bytes.`,
      );
    });
  }

  refreshButtons();
}
