import { expect, test } from '@playwright/test';

/**
 * Functional exhibit tests. These gate the deploy on the live ECDSA
 * nonce-reuse key recovery and the measured Ed25519 determinism check actually
 * WORKING in a real browser — computing their security outcome, not printing a
 * canned string. The ECDSA panel lives in the default-active "Ed25519 vs ECDSA"
 * tab, so no navigation is needed.
 */

test('ECDSA nonce reuse recovers the private key and the real verifier accepts the forgery', async ({
  page,
}) => {
  await page.goto('.');
  await page.locator('#ecdsa-reuse-btn').click();

  const out = page.locator('#ecdsa-output');
  await expect(out).toBeVisible();
  // Wait for the computation to finish (running placeholder → verdict).
  await expect(out.locator('[data-verdict="leaked"]')).toBeVisible({ timeout: 15_000 });
  await expect(out).toContainText(/Private key RECOVERED/i);
  await expect(out).toContainText(/ACCEPTED by the real P-256 verifier/i);
});

test('ECDSA control: fresh nonces leak nothing and the forgery is rejected', async ({ page }) => {
  await page.goto('.');
  await page.locator('#ecdsa-control-btn').click();

  const out = page.locator('#ecdsa-output');
  await expect(out).toBeVisible();
  await expect(out.locator('[data-verdict="safe"]')).toBeVisible({ timeout: 15_000 });
  await expect(out).toContainText(/REJECTED/i);
  // The leaked-key verdict must NOT appear on the control path.
  await expect(out).not.toContainText(/Private key RECOVERED/i);
  await expect(out.locator('[data-verdict="leaked"]')).toHaveCount(0);
});

test('Ed25519 determinism is measured: two signings are byte-for-byte identical', async ({
  page,
}) => {
  await page.goto('.');
  await page.locator('#determinism-measure-btn').click();

  const out = page.locator('#determinism-measure-output');
  await expect(out).toBeVisible();
  await expect(out.locator('[data-verdict="identical"]')).toBeVisible({ timeout: 15_000 });
  await expect(out).toContainText(/IDENTICAL/);
});
