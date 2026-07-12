import { defineConfig } from 'vitest/config';

// Unit tests live in src/**. The Playwright accessibility suite lives in e2e/
// and is run separately via `npm run test:a11y` — it must NOT be collected by
// Vitest (Playwright's `test`/`expect` are a different runner).
export default defineConfig({
  test: {
    include: ['src/**/*.{test,spec}.ts'],
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
    environment: 'node',
  },
});
