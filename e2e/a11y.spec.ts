import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are gated on the RFC 8032 Ed25519 Known-Answer
 * tests (Vitest, `npm test` in src/forge.test.ts); this gates them on
 * accessibility the same way. Scans the full page in both themes with every
 * collapsible / hidden region revealed.
 *
 * This lab has one real <details> ("Why this matters") plus a tab group whose
 * inactive panels carry the boolean `hidden` attribute. We open the <details>,
 * un-hide and activate every tab panel, and neutralize animations/transitions
 * so nothing is scanned mid-flight.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function neutralizeMotion(page: Page): Promise<void> {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.waitForTimeout(250);
}

async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    // Open every native <details>.
    for (const details of document.querySelectorAll('details')) {
      (details as HTMLDetailsElement).open = true;
    }
    // Reveal every tab panel (inactive ones carry the boolean `hidden` attr and
    // lack the `active` class) so their contents are scanned too.
    for (const panel of document.querySelectorAll<HTMLElement>('.tab-panel')) {
      panel.hidden = false;
      panel.removeAttribute('hidden');
      panel.classList.add('active');
    }
    // Reveal regions toggled via the boolean `hidden` attribute at runtime
    // (e.g. the Sign panel's determinism demonstrator) so their contrast is
    // scanned too.
    for (const el of document.querySelectorAll<HTMLElement>('[hidden]')) {
      el.removeAttribute('hidden');
    }
    // Exercise the runtime-only verdict color states so their (tinted) text is
    // contrast-checked: the determinism verdict and both cofactor verdicts.
    const detVerdict = document.querySelector('#determinism-verdict');
    if (detVerdict) {
      detVerdict.classList.remove('neutral');
      detVerdict.classList.add('identical');
      detVerdict.textContent = 'IDENTICAL — same key + same message yields the same signature.';
    }
    for (const id of ['#cofactor-zip215', '#cofactor-strict']) {
      const el = document.querySelector(id);
      const res = el?.querySelector('.cofactor-result');
      if (el && res) {
        el.classList.remove('neutral');
        el.classList.add(id.includes('zip') ? 'valid' : 'invalid');
        res.textContent = id.includes('zip') ? 'ACCEPTS' : 'REJECTS';
      }
    }
    // Generic safety net: clear any remaining inline display:none regions.
    for (const el of document.querySelectorAll<HTMLElement>('[style*="display"]')) {
      if (el.style && el.style.display === 'none') el.style.display = '';
    }
  });
}

async function checkGradientContrast(page: Page): Promise<void> {
  const contrast = await page.evaluate(() => {
    function getLum(r: number, g: number, b: number) {
      const a = [r, g, b].map(v => {
        v /= 255;
        return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
      });
      return a[0] * 0.2126 + a[1] * 0.7152 + a[2] * 0.0722;
    }
    function parseRGB(str: string) {
      const m = str.match(/\d+/g);
      return m ? [parseInt(m[0], 10), parseInt(m[1], 10), parseInt(m[2], 10)] : [0,0,0];
    }
    const el = document.querySelector('.cl-hero-desc');
    if (!el) return 0;
    const color = getComputedStyle(el).color;
    const bgStr = getComputedStyle(document.body).backgroundColor;
    const textLum = getLum(...(parseRGB(color) as [number, number, number]));
    const bgLum = getLum(...(parseRGB(bgStr) as [number, number, number]));
    return (Math.max(textLum, bgLum) + 0.05) / (Math.min(textLum, bgLum) + 0.05);
  });
  expect(contrast).toBeGreaterThanOrEqual(4.5);
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

async function runSuite(page: Page): Promise<void> {
  await page.locator('.cl-hero-title').waitFor();
  await checkGradientContrast(page);
  await revealAll(page);
  await neutralizeMotion(page);
  await scan(page);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await runSuite(page);
});

