// Command-line entry point. Walks a folder read-only, hands the files the
// engine knows how to read to checkFiles(), prints a report and sets the exit
// code. No network, no writes, no dependencies.

import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { checkFiles, classify, SKIP_DIRS } from './engine.mjs';
import { renderJson, renderMarkdown, renderText, TOOL } from './report.mjs';

const MAX_SOURCE_BYTES = 2 * 1024 * 1024;
const MAX_LOCK_BYTES = 64 * 1024 * 1024;
const MAX_FILES = 50000;

const HELP = `${TOOL.name} ${TOOL.version} by ${TOOL.by}

Checks an x402 project for SDK versions with known, publicly reported flaws
and for settings that turn the default spending limit off.

Usage: x402-check [folder] [options]

  folder               Project folder to check (default: current folder)
  --json               Print the result as JSON
  --markdown           Print a Markdown summary (for a pull request comment)
  --all                Also list packages that already have the fixes
  --fail-on <level>    Exit 1 when a finding is at this level or worse:
                       fix (default), review, or never
  --no-color           Plain text output
  -h, --help           Show this help
  -v, --version        Show the version

Exit codes: 0 nothing at the --fail-on level, 1 findings at that level,
2 the checker could not run.

Reads only lockfiles, package manifests and .js/.ts/.py source. Never opens
.env files or keys, makes no network calls and sends nothing anywhere.
`;

export function parseArgs(argv) {
  const opts = { dir: '.', format: 'text', failOn: 'fix', all: false, color: undefined };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') opts.help = true;
    else if (a === '-v' || a === '--version') opts.version = true;
    else if (a === '--json') opts.format = 'json';
    else if (a === '--markdown') opts.format = 'markdown';
    else if (a === '--all') opts.all = true;
    else if (a === '--no-color') opts.color = false;
    else if (a === '--fail-on') {
      const v = argv[++i];
      if (!['fix', 'review', 'never'].includes(v)) throw new Error(`--fail-on takes fix, review or never (got ${v ?? 'nothing'})`);
      opts.failOn = v;
    } else if (a.startsWith('-')) throw new Error(`Unknown option ${a}. Try --help.`);
    else opts.dir = a;
  }
  return opts;
}

export function collectFiles(root) {
  const files = [];
  const skipped = [];
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      skipped.push({ file: relative(root, dir) || '.', error: e.code || 'unreadable' });
      continue;
    }
    for (const ent of entries) {
      const full = join(dir, ent.name);
      // Symbolic links are never followed, so the scan stays inside the folder.
      if (ent.isSymbolicLink()) continue;
      if (ent.isDirectory()) {
        if (!SKIP_DIRS.has(ent.name)) stack.push(full);
        continue;
      }
      if (!ent.isFile()) continue;
      const rel = relative(root, full).split(sep).join('/');
      const kind = classify(rel);
      if (!kind) continue;
      const size = lstatSync(full).size;
      const limit = kind.endsWith('source') ? MAX_SOURCE_BYTES : MAX_LOCK_BYTES;
      if (size > limit) {
        skipped.push({ file: rel, error: `larger than ${Math.round(limit / 1048576)} MB, not read` });
        continue;
      }
      files.push({ path: rel, text: readFileSync(full, 'utf8') });
      if (files.length >= MAX_FILES) {
        skipped.push({ file: '.', error: `stopped after ${MAX_FILES} files` });
        return { files, skipped };
      }
    }
  }
  files.sort((a, b) => a.path.localeCompare(b.path));
  return { files, skipped };
}

export function run(argv, { stdout = process.stdout, stderr = process.stderr, isTTY = process.stdout.isTTY } = {}) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    stderr.write(`${e.message}\n`);
    return 2;
  }
  if (opts.help) return void stdout.write(HELP), 0;
  if (opts.version) return void stdout.write(`${TOOL.version}\n`), 0;

  const root = resolve(opts.dir);
  try {
    if (!lstatSync(root).isDirectory()) throw new Error('not a folder');
  } catch {
    stderr.write(`Cannot check ${opts.dir}: not a readable folder.\n`);
    return 2;
  }
  const { files, skipped } = collectFiles(root);
  const result = checkFiles(files);
  result.errors.push(...skipped);

  if (opts.format === 'json') stdout.write(renderJson(result));
  else if (opts.format === 'markdown') stdout.write(renderMarkdown(result));
  else stdout.write(renderText(result, { color: opts.color ?? (!!isTTY && !process.env.NO_COLOR), showOk: opts.all }));

  if (opts.failOn === 'never') return 0;
  const bad = opts.failOn === 'review' ? ['fix', 'review'] : ['fix'];
  return result.findings.some((f) => bad.includes(f.level)) ? 1 : 0;
}
