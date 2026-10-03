/**
 * The beginner front-section: keypair -> sign -> change one character -> the
 * check fails. Plain language, no hex on screen until a reader asks for it.
 *
 * It calls the same primitives the panels below call -- generateKeypair,
 * signMessage and verifySignature from ./forge, which are @noble/curves
 * Ed25519 -- so what a newcomer watches here is the real thing, not a
 * narrated animation of it. The only thing this file hides is the notation.
 *
 * The tamper changes exactly one character and flips its CASE, which is
 * deliberate: it makes the point that the signature binds the exact bytes
 * rather than the meaning, and a reader can see at a glance that the sentence
 * still says the same thing.
 *
 * ./forge is imported DYNAMICALLY, the same way ui.ts imports it. A static
 * import here compiles and works and quietly undoes the reason that one is
 * dynamic: it pulls @noble/curves into the production entry chunk, which every
 * visitor downloads before the page paints. Rollup says so out loud --
 * INEFFECTIVE_DYNAMIC_IMPORT -- and this section is the first thing a newcomer
 * meets, so it is the worst place in the lab to add weight before first paint.
 */
type ForgeModule = typeof import('./forge');
let forgePromise: Promise<ForgeModule> | null = null;
const loadForge = (): Promise<ForgeModule> => (forgePromise ??= import('./forge'));

type State = {
  publicKey: Uint8Array | null;
  privateKey: Uint8Array | null;
  signature: Uint8Array | null;
  signedNote: string | null;
};

const el = <T extends HTMLElement>(id: string): T => {
  const node = document.getElementById(id);
  if (!node) throw new Error(`first-look: #${id} is missing from the page`);
  return node as T;
};

const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/**
 * Flip the case of the first letter, and say which one moved. Returns null
 * when the note has no letter to change -- in which case nothing is altered
 * and the reader is told so, rather than the note being silently rewritten.
 */
export function flipOneCharacter(note: string): { changed: string; from: string; to: string } | null {
  for (let i = 0; i < note.length; i += 1) {
    const ch = note[i];
    const lower = ch.toLowerCase();
    const upper = ch.toUpperCase();
    if (lower === upper) continue;
    const swapped = ch === lower ? upper : lower;
    return { changed: note.slice(0, i) + swapped + note.slice(i + 1), from: ch, to: swapped };
  }
  return null;
}

export function mountFirstLook(): void {
  const keysBtn = el<HTMLButtonElement>('fl-keys');
  const signBtn = el<HTMLButtonElement>('fl-sign');
  const checkBtn = el<HTMLButtonElement>('fl-check');
  const tamperBtn = el<HTMLButtonElement>('fl-tamper');
  const note = el<HTMLInputElement>('fl-note');
  const keysStatus = el('fl-keys-status');
  const signStatus = el('fl-sign-status');
  const verdict = el('fl-verdict');
  const bytesPublic = el('fl-bytes-public');
  const bytesSignature = el('fl-bytes-signature');

  const state: State = { publicKey: null, privateKey: null, signature: null, signedNote: null };

  const setVerdict = (kind: 'none' | 'accepted' | 'rejected', text: string): void => {
    verdict.setAttribute('data-verdict', kind);
    verdict.textContent = text;
  };

  keysBtn.addEventListener('click', async () => {
    const { generateKeypair } = await loadForge();
    const pair = generateKeypair();
    state.publicKey = pair.publicKey;
    state.privateKey = pair.privateKey;
    state.signature = null;
    state.signedNote = null;
    keysStatus.textContent =
      'Done. The private key stays in this page and signs; the public key is the one you could publish, and it can only check signatures, never make them.';
    signStatus.textContent = 'Nothing signed yet.';
    bytesPublic.textContent = toHex(pair.publicKey);
    bytesSignature.textContent = '-';
    signBtn.disabled = false;
    checkBtn.disabled = true;
    tamperBtn.disabled = true;
    setVerdict('none', 'Sign the note first.');
  });

  signBtn.addEventListener('click', async () => {
    if (!state.privateKey) return;
    const { signMessage } = await loadForge();
    const text = note.value;
    const result = signMessage(text, state.privateKey);
    state.signature = result.signature;
    state.signedNote = text;
    signStatus.textContent =
      'Signed. Those 64 bytes say that this exact note came from the holder of the private key.';
    bytesSignature.textContent = toHex(result.signature);
    checkBtn.disabled = false;
    tamperBtn.disabled = false;
    setVerdict('none', 'Now check it.');
  });

  /* Both buttons verify the note AS IT STANDS IN THE BOX against the stored
     signature, so a reader who edits the note by hand gets the same honest
     answer the tamper button produces. */
  const check = async (): Promise<void> => {
    if (!state.publicKey || !state.signature) return;
    const { verifySignature } = await loadForge();
    const ok = verifySignature(note.value, state.signature, state.publicKey);
    if (ok) {
      setVerdict('accepted', 'ACCEPTED - this is exactly the note that was signed.');
    } else {
      setVerdict('rejected', 'REJECTED - the note is not the one that was signed.');
    }
  };

  checkBtn.addEventListener('click', () => {
    void check();
  });

  tamperBtn.addEventListener('click', async () => {
    const flip = flipOneCharacter(note.value);
    if (!flip) {
      setVerdict('none', 'This note has no letter to change. Type a word and sign it again.');
      return;
    }
    note.value = flip.changed;
    await check();
    if (verdict.getAttribute('data-verdict') === 'rejected') {
      verdict.textContent = `REJECTED - one character changed ("${flip.from}" became "${flip.to}") and the check fails. The note still reads the same to you; it is not the same bytes.`;
    }
  });
}
