import { expect, test } from '@playwright/test';

/**
 * The beginner front-section gates the deploy on its own verdicts, not on the
 * copy around them. Each test drives the real buttons and asserts the verdict
 * the real @noble/curves verifier produced, so a change that makes the check
 * always pass -- or always fail -- turns this red. tools/mutations.mjs replays
 * exactly those two changes against these tests.
 */

const verdict = '#fl-verdict';

test('sign, then check: the untouched note is accepted', async ({ page }) => {
  await page.goto('.');
  await page.locator('#fl-keys').click();
  await page.locator('#fl-sign').click();
  await page.locator('#fl-check').click();

  await expect(page.locator(verdict)).toHaveAttribute('data-verdict', 'accepted');
  await expect(page.locator(verdict)).toContainText(/ACCEPTED/);
});

test('change one character and the same signature is rejected', async ({ page }) => {
  await page.goto('.');
  await page.locator('#fl-keys').click();

  const note = page.locator('#fl-note');
  const before = await note.inputValue();

  await page.locator('#fl-sign').click();
  await page.locator('#fl-tamper').click();

  await expect(page.locator(verdict)).toHaveAttribute('data-verdict', 'rejected');
  await expect(page.locator(verdict)).toContainText(/REJECTED/);

  // Exactly one character moved, and only its case: the note still reads the
  // same, which is the whole point being made.
  const after = await note.inputValue();
  expect(after).not.toBe(before);
  expect(after.length).toBe(before.length);
  expect(after.toLowerCase()).toBe(before.toLowerCase());
  const differing = [...before].filter((ch, i) => ch !== after[i]);
  expect(differing).toHaveLength(1);
});

test('no hex is on screen until the reader asks for it', async ({ page }) => {
  await page.goto('.');
  await page.locator('#fl-keys').click();
  await page.locator('#fl-sign').click();

  // The byte outputs hold real values, and the <details> around them is shut,
  // so nothing in the front-section renders them until it is opened.
  await expect(page.locator('#fl-bytes-public')).toHaveText(/^[0-9a-f]{64}$/);
  await expect(page.locator('#fl-bytes-signature')).toHaveText(/^[0-9a-f]{128}$/);
  await expect(page.locator('#fl-bytes-public')).toBeHidden();

  await page.locator('.first-look-bytes summary').click();
  await expect(page.locator('#fl-bytes-public')).toBeVisible();
});

test('the front-section comes before the working panels', async ({ page }) => {
  await page.goto('.');
  const order = await page.evaluate(() => {
    const first = document.querySelector('#first-look');
    const panels = document.querySelector('.panel-grid');
    if (!first || !panels) return 'missing';
    return first.compareDocumentPosition(panels) & Node.DOCUMENT_POSITION_FOLLOWING
      ? 'front-section first'
      : 'panels first';
  });
  expect(order).toBe('front-section first');
});
