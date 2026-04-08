export function mountApp(): void {
  const root = document.querySelector<HTMLDivElement>('#app');
  if (!root) {
    throw new Error('Missing #app root element');
  }

  root.innerHTML = `
    <main class="phase-banner">
      <h1>Ed25519 Forge</h1>
      <p>Phase 1 complete: Vite scaffolded, noble dependency verified, and project structure prepared.</p>
    </main>
  `;
}
