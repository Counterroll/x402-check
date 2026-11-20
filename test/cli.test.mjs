import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run } from '../src/cli.mjs';

function project(files) {
  const dir = mkdtempSync(join(tmpdir(), 'x402-check-'));
  for (const [p, text] of Object.entries(files)) {
    mkdirSync(join(dir, p, '..'), { recursive: true });
    writeFileSync(join(dir, p), text);
  }
  return dir;
}

function capture(argv) {
  let out = '';
  let err = '';
  const code = run(argv, { stdout: { write: (s) => (out += s) }, stderr: { write: (s) => (err += s) }, isTTY: false });
  return { code, out, err };
}

const OLD_LOCK = JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/@x402/fetch': { version: '2.22.0' } } });
const NEW_LOCK = JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/@x402/fetch': { version: '2.29.0' } } });

test('exit 1 and a report when something needs fixing', () => {
  const dir = project({ 'package-lock.json': OLD_LOCK });
  try {
    const { code, out } = capture([dir]);
    assert.equal(code, 1);
    assert.match(out, /1 to fix/);
    assert.match(out, /FIX\s+Payment client with no default spending limit \(@x402\/fetch 2\.22\.0\)/);
    assert.match(out, /package-lock\.json/);
    assert.match(out, /not a security audit/);
    assert.match(out, /hello@counterroll\.dev/);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('exit 0 when everything is fixed; --fail-on review and never', () => {
  const dir = project({ 'package-lock.json': NEW_LOCK, 'src/a.ts': 'const c = { allowedAssets: true };\n' });
  try {
    assert.equal(capture([dir]).code, 0);
    assert.equal(capture([dir, '--fail-on', 'review']).code, 1);
    const old = project({ 'package-lock.json': OLD_LOCK });
    assert.equal(capture([old, '--fail-on', 'never']).code, 0);
    rmSync(old, { recursive: true });
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('skips node_modules, .env files, keys and symbolic links', () => {
  const dir = project({
    'package-lock.json': NEW_LOCK,
    'node_modules/dep/index.js': 'const x = { spendControls: false };\n',
    '.env': 'spendControls: false\n',
    'wallet.key': 'spendControls: false\n',
  });
  const outside = project({ 'agent.ts': 'const x = { spendControls: false };\n' });
  try {
    symlinkSync(outside, join(dir, 'linked'));
    const { code, out } = capture([dir, '--json']);
    const r = JSON.parse(out);
    assert.equal(code, 0);
    assert.equal(r.filesRead, 1);
    assert.equal(r.summary.fix, 0);
  } finally {
    rmSync(dir, { recursive: true });
    rmSync(outside, { recursive: true });
  }
});

test('JSON and Markdown output', () => {
  const dir = project({ 'package-lock.json': OLD_LOCK, 'src/agent.ts': 'new x402Client({ schemes, spendControls: false });\n' });
  try {
    const j = JSON.parse(capture([dir, '--json']).out);
    assert.equal(j.tool.name, 'x402-check');
    assert.deepEqual(j.summary, { fix: 2, review: 0, ok: 0, packages: 1, filesRead: 2 });
    const md = capture([dir, '--markdown']).out;
    assert.match(md, /^## x402 setup check/);
    assert.match(md, /\| FIX \| \*\*Spend controls turned off\*\*/);
    assert.match(md, /`src\/agent\.ts:1`/);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('bad arguments and missing folders exit 2', () => {
  assert.equal(capture(['--fail-on', 'sometimes']).code, 2);
  assert.equal(capture(['--nope']).code, 2);
  assert.equal(capture([join(tmpdir(), 'x402-check-does-not-exist')]).code, 2);
  assert.equal(capture(['--help']).code, 0);
});
