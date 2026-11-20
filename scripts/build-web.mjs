// Copies the browser page and the engine into one flat folder that any static
// host can serve, e.g. as counterroll.dev/check/. Nothing is minified or
// rewritten apart from the import paths.
//
//   node scripts/build-web.mjs [outDir]    (default: web-dist)

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const out = resolve(process.argv[2] || join(root, 'web-dist'));
mkdirSync(out, { recursive: true });

const copy = (from, to, fix = (s) => s) => writeFileSync(join(out, to), fix(readFileSync(join(root, from), 'utf8')));
copy('web/index.html', 'index.html');
copy('web/app.mjs', 'app.mjs', (s) => s.replaceAll("'../src/", "'./"));
for (const f of ['engine.mjs', 'rules.mjs', 'versions.mjs', 'report.mjs']) copy(`src/${f}`, f);
console.log(`Wrote ${out}`);
