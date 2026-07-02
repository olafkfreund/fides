// Copies Monaco's self-contained AMD build (min/vs) into public/monaco/vs so the
// static export serves it same-origin. The portal runs under a strict CSP
// (script-src 'self'), so Monaco cannot be loaded from its default CDN; loading
// the AMD build at runtime (rather than bundling through webpack) also avoids
// Next's "global CSS can only be imported from layout" restriction.
import { cp, rm, access } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const src = resolve(here, "..", "node_modules", "monaco-editor", "min", "vs");
const dest = resolve(here, "..", "public", "monaco", "vs");

try {
  await access(src);
} catch {
  console.error(`[copy-monaco] source not found: ${src} — is monaco-editor installed?`);
  process.exit(1);
}

await rm(dest, { recursive: true, force: true });
await cp(src, dest, { recursive: true });
console.log(`[copy-monaco] copied Monaco AMD build -> ${dest}`);
