import { expect, test } from '@playwright/test';

for (const width of [1280, 380, 320]) {
  for (const reducedMotion of ['reduce', 'no-preference'] as const) {
    test(`scalar prefix summary is honest at ${width}px with ${reducedMotion} motion`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await page.emulateMedia({ reducedMotion });
      const errors: string[] = [];
      page.on('pageerror', e => errors.push(e.message));
      await page.goto('.');
      await expect(page.locator('.scalarmult-lead')).toContainText('clamped SHA-512 prefix');
      await expect(page.locator('.scalarmult-lead')).toContainText('endpoint jump is not an add G');
      await page.locator('#generate-keypair').click();
      const status = page.locator('#scalarmult-status');
      await expect(status).toContainText('Summary: exact public point', { timeout: 15_000 });
      await expect(status).toContainText('242 bits skipped');
      await expect(status).toContainText('double/add operations displayed');
      await expect(status).not.toContainText('landed on the public point');
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
      expect(errors).toEqual([]);
    });
  }
}
