import { defineConfig, type Plugin } from 'vite';

// Inline the emitted stylesheet into a <style> tag and drop the <link>, so the
// (small) CSS is no longer a render-blocking request on first paint.
function inlineCss(): Plugin {
  return {
    name: 'inline-css',
    apply: 'build',
    enforce: 'post',
    transformIndexHtml(html, ctx) {
      if (!ctx.bundle) return html;
      let out = html;
      const linkRe = /<link[^>]+rel="stylesheet"[^>]*href="([^"]+)"[^>]*>/g;
      for (const match of html.matchAll(linkRe)) {
        const href = match[1];
        const asset = Object.values(ctx.bundle).find(
          (a) => a.type === 'asset' && href.endsWith(a.fileName),
        );
        if (asset && asset.type === 'asset') {
          out = out.replace(match[0], `<style>${asset.source}</style>`);
          delete ctx.bundle[asset.fileName];
        }
      }
      return out;
    },
  };
}

export default defineConfig({
  base: '/crypto-lab-ed25519-forge/',
  plugins: [inlineCss()],
});
