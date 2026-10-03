/**
 * §4.1c for the beginner front-section: replays concrete source patches and
 * records observations only from actual runs.
 *
 * Run: node tools/mutations.mjs            unit + browser mutations
 *      node tools/mutations.mjs --unit-only   unit mutations only (no browser)
 *
 * Each case asserts four things, because a green-then-red pair alone proves
 * nothing: the UNMUTATED baseline passes, the patch anchor is unique and the
 * file actually changed, the BUILT BUNDLE HASH MOVED (a mutation applied to a
 * file the build drops is the same failure one step later and it is quieter),
 * and the named owning test is the one that failed. The source and the bundle
 * are restored and the restore hash is compared.
 */
import { readFileSync, writeFileSync, readdirSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';

const unitOnly = process.argv.includes('--unit-only');
const observations = [];

const cases = [
  // The two verdicts the front-section introduces. One mutation per direction:
  // a check that always passes, and a check that always fails. Either makes the
  // section a narration rather than a demonstration.
  {
    id: 'M1',
    file: 'src/first-look.ts',
    anchor: 'const ok = verifySignature(note.value, state.signature, state.publicKey);',
    replace: 'const ok = verifySignature(note.value, state.signature, state.publicKey) || true;',
    test: 'change one character and the same signature is rejected',
    kind: 'browser',
    why: 'a check that accepts everything still shows ACCEPTED on an untouched note',
  },
  {
    id: 'M2',
    file: 'src/first-look.ts',
    anchor: 'const ok = verifySignature(note.value, state.signature, state.publicKey);',
    replace: 'const ok = verifySignature(note.value, state.signature, state.publicKey) && false;',
    test: 'sign, then check: the untouched note is accepted',
    kind: 'browser',
    why: 'a check that rejects everything still shows REJECTED after the tamper',
  },
  {
    id: 'M3',
    file: 'src/first-look.ts',
    anchor: '    note.value = flip.changed;',
    replace: '    // mutation: compute the flip and never apply it',
    test: 'change one character and the same signature is rejected',
    kind: 'browser',
    why: 'the tamper button could appear to work while changing nothing',
  },
  {
    id: 'M4',
    file: 'src/first-look.ts',
    anchor: '    return { changed: note.slice(0, i) + swapped + note.slice(i + 1), from: ch, to: swapped };',
    replace: '    return { changed: note.toUpperCase(), from: ch, to: swapped };',
    test: 'changes exactly one character and only its case',
    kind: 'unit',
    why: 'rewriting the whole note still rejects, and stops making the point about exact bytes',
  },
  {
    id: 'M5',
    file: 'index.html',
    anchor: '<details class="first-look-bytes">',
    replace: '<details class="first-look-bytes" open>',
    test: 'no hex is on screen until the reader asks for it',
    kind: 'browser',
    why: 'the section is for readers who have not met hex yet',
  },
];

function run(args) {
  const r = spawnSync('npm', args, { encoding: 'utf8', timeout: 240000, env: { ...process.env, CI: '1' } });
  return { status: r.status, output: (r.stdout ?? '') + (r.stderr ?? '') };
}

function hash() {
  return createHash('sha256')
    .update(
      readdirSync('dist/assets')
        .filter((n) => /\.(css|js)$/.test(n))
        .sort()
        .map((n) => readFileSync('dist/assets/' + n))
        .join('\n') + readFileSync('dist/index.html'),
    )
    .digest('hex');
}

function ensureBuild() {
  const r = run(['run', 'build']);
  if (r.status !== 0) throw Error('DOES NOT BUILD: ' + r.output);
  return hash();
}

/* A run can fail for reasons that are not the mutation: no browser, no server,
   no such test. Those are NOT a kill, and reading them as one would report a
   guard that never fired as a guard that works.

   The same applies one step earlier: M1 and M2 keep the verifySignature call in
   the expression rather than replacing it outright, because dropping it leaves
   an unused binding, `tsc` refuses, and the case reports DOES NOT BUILD instead
   of proving anything. */
const nonTestFailure =
  /Executable doesn't exist|browserType\.launch|webServer was not able|Connection refused|ERR_CONNECTION|Cannot find module|No test files found|No tests found/;

let failed = false;
try {
  for (const c of cases.filter((c) => !unitOnly || c.kind === 'unit')) {
    const args =
      c.kind === 'unit'
        ? ['test', '--', '--testNamePattern', c.test]
        : ['run', 'test:a11y', '--', '--grep', c.test];

    const baseline = run(args);
    if (baseline.status !== 0) throw Error(c.id + ' BASELINE BLOCKED: ' + baseline.output);

    const original = readFileSync(c.file, 'utf8');
    if (original.split(c.anchor).length !== 2) throw Error(c.id + ' patch anchor is not unique');
    const before = ensureBuild();

    try {
      const modified = original.replace(c.anchor, c.replace);
      if (modified === original) throw Error(c.id + ' patch did not change the file');
      writeFileSync(c.file, modified);

      const after = ensureBuild();
      if (after === before) throw Error(c.id + ' MUTATED BUNDLE DID NOT CHANGE');

      const r = run(args);
      const killed = r.status !== 0 && !nonTestFailure.test(r.output) && /fail/i.test(r.output);
      observations.push({
        ...c,
        observed: killed ? 'KILLED' : 'NOT PROVEN',
        baselinePassed: true,
        bundleBefore: before,
        bundleMutated: after,
        exitCode: r.status,
      });
      if (!killed) throw Error(c.id + ' was not proven: ' + r.output);
    } finally {
      writeFileSync(c.file, original);
      const restored = ensureBuild();
      if (restored !== before) throw Error(c.id + ' restore hash differs');
    }
    console.log(
      c.id + ' KILLED; baseline passed, build succeeded, bundle changed, "' + c.test + '" failed, source and bundle restored.',
    );
  }
} catch (e) {
  failed = true;
  observations.push({ observed: 'BLOCKED', reason: e.message });
  console.error(e.message);
}

mkdirSync('audits', { recursive: true });
writeFileSync(
  'audits/mutation-observations.json',
  JSON.stringify(
    { scope: unitOnly ? 'unit source mutations only' : 'unit + production-browser source mutations', observations },
    null,
    2,
  ) + '\n',
);
if (failed) process.exitCode = 1;
