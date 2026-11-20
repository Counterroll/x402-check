// Browser front end. Reads only the files the engine can use, runs the same
// checkFiles() as the command line, and renders the result. Nothing leaves the
// page: the Content-Security-Policy sets connect-src 'none'.

import { checkFiles, classify, SKIP_DIRS, summarize } from '../src/engine.mjs';
import { LIMITS, NEXT_STEP, TOOL } from '../src/report.mjs';
import { RULES_AS_OF, SOURCES } from '../src/rules.mjs';

const $ = (id) => document.getElementById(id);
const MAX_BYTES = 64 * 1024 * 1024;

const EXAMPLE = [
  {
    path: 'package-lock.json',
    text: JSON.stringify(
      {
        lockfileVersion: 3,
        packages: {
          'node_modules/@x402/fetch': { version: '2.22.0' },
          'node_modules/@x402/core': { version: '2.25.0' },
          'node_modules/@x402/extensions': { version: '2.29.0' },
        },
      },
      null,
      2,
    ),
  },
  { path: 'src/agent.ts', text: "const client = new x402Client({\n  schemes,\n  spendControls: false,\n});\n" },
];

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  for (const c of children) node.append(c);
  return node;
}

function linkify(text) {
  const frag = document.createDocumentFragment();
  const parts = text.split(/(hello@counterroll\.dev)/);
  for (const p of parts) {
    if (p === 'hello@counterroll.dev') frag.append(el('a', { href: 'mailto:hello@counterroll.dev?subject=Offline%20evaluation' }, p));
    else frag.append(p);
  }
  return frag;
}

function render(result, note) {
  const s = summarize(result);
  $('results').hidden = false;
  const summary = $('summary');
  summary.replaceChildren(
    el('span', { class: 'n-fix' }, `${s.fix} to fix`),
    el('span', { class: 'n-review' }, `${s.review} to review`),
    el('span', { class: 'n-ok' }, `${s.ok} fixed`),
    el('span', { class: 'muted' }, `${s.filesRead} files read, ${s.packages} x402 package entries${note ? ` · ${note}` : ''}`),
  );
  const list = $('findings');
  list.replaceChildren();
  if (!s.packages && !result.findings.length) {
    list.append(el('p', {}, 'No x402 packages or settings were found. Try your project folder, or the lockfile at its root.'));
  }
  for (const f of result.findings.filter((x) => x.level !== 'ok').concat(result.findings.filter((x) => x.level === 'ok'))) {
    const tag = { fix: 'FIX', review: 'REVIEW', ok: 'OK' }[f.level];
    const item = el(
      'div',
      { class: 'finding' },
      el('span', { class: `tag n-${f.level}` }, tag),
      el('span', { class: 'title' }, f.title + (f.package ? ` (${f.package} ${f.version})` : '')),
      el('div', { class: 'where' }, f.line ? `${f.file}:${f.line}` : f.file),
    );
    if (f.snippet) item.append(el('div', { class: 'snippet' }, '> ' + f.snippet));
    item.append(el('div', { class: 'detail' }, f.detail));
    list.append(item);
  }
  for (const e of result.errors) list.append(el('p', { class: 'muted' }, `Could not read ${e.file}: ${e.error}`));
  $('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function readAll(entries) {
  const files = [];
  const errors = [];
  for (const { path, file } of entries) {
    if (!classify(path)) continue;
    if (file.size > MAX_BYTES) {
      errors.push({ file: path, error: 'larger than 64 MB, not read' });
      continue;
    }
    files.push({ path, text: await file.text() });
  }
  return { files, errors };
}

const skipped = (path) => path.split('/').slice(0, -1).some((part) => SKIP_DIRS.has(part));

async function runOn(entries, note) {
  const { files, errors } = await readAll(entries.filter((e) => !skipped(e.path)));
  const result = checkFiles(files);
  result.errors.push(...errors);
  render(result, note);
}

// Drag and drop: walk dropped folders without entering skipped ones.
function walkEntry(entry, prefix, out) {
  return new Promise((resolve) => {
    if (entry.isFile) {
      const path = prefix + entry.name;
      if (!classify(path)) return resolve();
      entry.file((file) => (out.push({ path, file }), resolve()), () => resolve());
    } else if (entry.isDirectory) {
      if (SKIP_DIRS.has(entry.name)) return resolve();
      const reader = entry.createReader();
      const all = [];
      const next = () =>
        reader.readEntries(async (batch) => {
          if (!batch.length) {
            for (const e of all) await walkEntry(e, prefix + entry.name + '/', out);
            return resolve();
          }
          all.push(...batch);
          next();
        }, () => resolve());
      next();
    } else resolve();
  });
}

const drop = $('drop');
drop.addEventListener('dragover', (e) => {
  e.preventDefault();
  drop.classList.add('over');
});
drop.addEventListener('dragleave', () => drop.classList.remove('over'));
drop.addEventListener('drop', async (e) => {
  e.preventDefault();
  drop.classList.remove('over');
  const out = [];
  const items = [...(e.dataTransfer.items || [])];
  const entries = items.map((i) => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);
  if (entries.length) {
    for (const entry of entries) await walkEntry(entry, '', out);
  } else {
    for (const file of e.dataTransfer.files) out.push({ path: file.name, file });
  }
  runOn(out);
});

$('pick-files').addEventListener('change', (e) => {
  runOn([...e.target.files].map((file) => ({ path: file.name, file })));
  e.target.value = '';
});
$('pick-folder').addEventListener('change', (e) => {
  runOn([...e.target.files].map((file) => ({ path: file.webkitRelativePath || file.name, file })));
  e.target.value = '';
});
$('sample').addEventListener('click', () => {
  const result = checkFiles(EXAMPLE);
  render(result, 'example project, not yours');
});

NEXT_STEP.forEach((line, i) => $(`next-${i + 1}`).replaceChildren(linkify(line)));
$('limits').replaceChildren(...LIMITS.map((l) => el('li', {}, l)));
$('as-of').textContent = RULES_AS_OF;
$('source').href = SOURCES.csa;
$('source').textContent = 'Cloud Security Alliance research note, 2026-10-25';
$('tool-version').textContent = TOOL.version;
