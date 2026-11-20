import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkFiles, classify, summarize } from '../src/engine.mjs';
import { compareVersions, goPseudoDate, lowestAllowed } from '../src/versions.mjs';

const levelsFor = (result, pkg) => result.findings.filter((f) => f.package === pkg).map((f) => f.level);
const ids = (result, level) => result.findings.filter((f) => f.level === level).map((f) => f.id);

test('versions compare numerically, prereleases sort first', () => {
  assert.equal(compareVersions('2.22.0', '2.23.0'), -1);
  assert.equal(compareVersions('2.23.0', '2.23.0'), 0);
  assert.equal(compareVersions('2.100.0', '2.23.0'), 1);
  assert.equal(compareVersions('2.23.0-beta.1', '2.23.0'), -1);
  assert.equal(compareVersions('v2.28.0', '2.27.0'), 1);
  assert.equal(compareVersions('2.20', '2.20.0'), 0);
});

test('lowest allowed version of a range', () => {
  assert.equal(lowestAllowed('^2.22.0'), '2.22.0');
  assert.equal(lowestAllowed('~2.23.1'), '2.23.1');
  assert.equal(lowestAllowed('>=2.0 <3'), '2.0.0');
  assert.equal(lowestAllowed('2.x'), '2.0.0');
  assert.equal(lowestAllowed('>=2.20.0,<3'), '2.20.0');
  assert.equal(lowestAllowed('^2.30.0 || ^2.10.0'), '2.10.0');
  assert.equal(lowestAllowed('*'), null);
  assert.equal(lowestAllowed('latest'), null);
  assert.equal(lowestAllowed('workspace:*'), null);
});

test('Go pseudo-version dates', () => {
  assert.equal(goPseudoDate('v0.0.0-20260421184015-dd927a26cfef'), '20260421');
  assert.equal(goPseudoDate('v2.1.4-0.20260901120000-0123456789ab'), '20260901');
  assert.equal(goPseudoDate('v2.28.0'), null);
});

test('only lockfiles, manifests and source are ever read', () => {
  assert.equal(classify('package-lock.json'), 'npm-lock');
  assert.equal(classify('apps/web/pnpm-lock.yaml'), 'pnpm-lock');
  assert.equal(classify('requirements-dev.txt'), 'py-requirements');
  assert.equal(classify('go.mod'), 'go-mod');
  assert.equal(classify('src/agent.ts'), 'js-source');
  assert.equal(classify('agent/main.py'), 'py-source');
  for (const p of ['.env', '.env.local', 'wallet.key', 'id_rsa', 'key.pem', 'types/index.d.ts', 'vendor.min.js', 'README.md', 'config.json']) {
    assert.equal(classify(p), null, p);
  }
});

test('package-lock v3: old client, old core and transitive packages are flagged', () => {
  const lock = JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { dependencies: { '@x402/fetch': '^2.22.0' } },
      'node_modules/@x402/fetch': { version: '2.22.0' },
      'node_modules/@x402/core': { version: '2.25.0' },
      'node_modules/some-agent-kit/node_modules/@x402/axios': { version: '2.10.1' },
      'node_modules/@x402/evm': { version: '2.22.0' },
    },
  });
  const r = checkFiles([{ path: 'package-lock.json', text: lock }]);
  assert.deepEqual(levelsFor(r, '@x402/fetch'), ['fix']);
  assert.deepEqual(levelsFor(r, '@x402/core'), ['fix']);
  assert.deepEqual(levelsFor(r, '@x402/axios'), ['fix']);
  assert.deepEqual(levelsFor(r, '@x402/evm'), []);
  assert.equal(r.packages.length, 4);
});

test('fixed versions pass', () => {
  const lock = JSON.stringify({
    lockfileVersion: 3,
    packages: {
      'node_modules/@x402/fetch': { version: '2.23.0' },
      'node_modules/@x402/core': { version: '2.27.0' },
      'node_modules/@x402/extensions': { version: '2.29.0' },
      'node_modules/@x402/svm': { version: '2.23.0' },
    },
  });
  const r = checkFiles([{ path: 'package-lock.json', text: lock }]);
  assert.deepEqual(summarize(r), { fix: 0, review: 0, ok: 4, packages: 4, filesRead: 1 });
});

test('@x402/svm is only affected from 2.0.0', () => {
  const lock = JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/@x402/svm': { version: '1.9.0' } } });
  assert.deepEqual(levelsFor(checkFiles([{ path: 'package-lock.json', text: lock }]), '@x402/svm'), ['ok']);
});

test('package-lock v1 nested dependencies', () => {
  const lock = JSON.stringify({
    lockfileVersion: 1,
    dependencies: { agentkit: { version: '1.0.0', dependencies: { '@x402/fetch': { version: '2.1.0' } } } },
  });
  assert.deepEqual(levelsFor(checkFiles([{ path: 'package-lock.json', text: lock }]), '@x402/fetch'), ['fix']);
});

test('pnpm lockfiles v5, v6 and v9', () => {
  const v9 = "lockfileVersion: '9.0'\n\npackages:\n\n  '@x402/fetch@2.21.0':\n    resolution: {integrity: sha512-x}\n\n  '@x402/core@2.28.0':\n    resolution: {integrity: sha512-y}\n";
  const v6 = "lockfileVersion: '6.0'\n\npackages:\n\n  /@x402/axios@2.20.0:\n    resolution: {integrity: sha512-x}\n";
  const v5 = 'lockfileVersion: 5.4\n\npackages:\n\n  /@x402/extensions/2.22.0:\n    resolution: {integrity: sha512-x}\n';
  const r = checkFiles([
    { path: 'a/pnpm-lock.yaml', text: v9 },
    { path: 'b/pnpm-lock.yaml', text: v6 },
    { path: 'c/pnpm-lock.yaml', text: v5 },
  ]);
  assert.deepEqual(levelsFor(r, '@x402/fetch'), ['fix']);
  assert.deepEqual(levelsFor(r, '@x402/core'), ['ok']);
  assert.deepEqual(levelsFor(r, '@x402/axios'), ['fix']);
  assert.deepEqual(levelsFor(r, '@x402/extensions'), ['fix']);
  assert.equal(r.findings.find((f) => f.package === '@x402/fetch').line, 5);
});

test('yarn classic and berry lockfiles', () => {
  const classic = '# yarn lockfile v1\n\n"@x402/fetch@^2.20.0":\n  version "2.20.3"\n  resolved "https://registry.yarnpkg.com/x"\n';
  const berry = '__metadata:\n  version: 8\n\n"@x402/core@npm:^2.27.0":\n  version: 2.27.1\n  resolution: "@x402/core@npm:2.27.1"\n';
  const r = checkFiles([
    { path: 'yarn.lock', text: classic },
    { path: 'svc/yarn.lock', text: berry },
  ]);
  assert.deepEqual(levelsFor(r, '@x402/fetch'), ['fix']);
  assert.deepEqual(levelsFor(r, '@x402/core'), ['ok']);
});

test('bun.lock', () => {
  const bun = '{\n  "lockfileVersion": 1,\n  "packages": {\n    "@x402/fetch": ["@x402/fetch@2.22.0", "", {}, "sha512-x"],\n  }\n}\n';
  assert.deepEqual(levelsFor(checkFiles([{ path: 'bun.lock', text: bun }]), '@x402/fetch'), ['fix']);
});

test('package.json alone: a range that allows unfixed versions is a review item', () => {
  const pkg = JSON.stringify({ dependencies: { '@x402/fetch': '^2.20.0', '@x402/extensions': '^2.23.0' } }, null, 2);
  const r = checkFiles([{ path: 'package.json', text: pkg }]);
  assert.deepEqual(levelsFor(r, '@x402/fetch'), ['review']);
  assert.deepEqual(levelsFor(r, '@x402/extensions'), ['ok']);
});

test('package.json range is ignored when a lockfile says what is installed', () => {
  const pkg = JSON.stringify({ dependencies: { '@x402/fetch': '^2.20.0' } });
  const lock = JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/@x402/fetch': { version: '2.28.0' } } });
  const r = checkFiles([
    { path: 'packages/agent/package.json', text: pkg },
    { path: 'package-lock.json', text: lock },
  ]);
  assert.deepEqual(levelsFor(r, '@x402/fetch'), ['ok']);
});

test('legacy v1 packages are review items, not claimed uncapped', () => {
  const lock = JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/x402-fetch': { version: '1.2.0' }, 'node_modules/x402': { version: '1.2.0' } } });
  const r = checkFiles([{ path: 'package-lock.json', text: lock }]);
  assert.deepEqual(levelsFor(r, 'x402-fetch'), ['review']);
  assert.match(r.findings.find((f) => f.package === 'x402-fetch').detail, /maxValue/);
  assert.deepEqual(levelsFor(r, 'x402'), ['review']);
});

test('Python: requirements, poetry, uv, Pipfile.lock and pyproject', () => {
  const r = checkFiles([
    { path: 'requirements.txt', text: '# agents\nrequests==2.32.0\nx402==2.19.0 ; python_version >= "3.10"\n' },
    { path: 'svc1/poetry.lock', text: '[[package]]\nname = "x402"\nversion = "2.20.0"\ndescription = ""\n' },
    { path: 'svc2/uv.lock', text: 'version = 1\n\n[[package]]\nname = "x402"\nversion = "2.18.1"\nsource = { registry = "https://pypi.org/simple" }\n' },
    { path: 'svc3/Pipfile.lock', text: JSON.stringify({ default: { x402: { version: '==2.25.0' } } }) },
  ]);
  const levels = r.findings.filter((f) => f.package === 'x402').map((f) => `${f.file}:${f.level}`);
  assert.deepEqual(levels.sort(), ['requirements.txt:fix', 'svc1/poetry.lock:ok', 'svc2/uv.lock:fix', 'svc3/Pipfile.lock:ok'].sort());

  const py = checkFiles([{ path: 'pyproject.toml', text: '[project]\ndependencies = [\n  "x402>=2.0",\n  "httpx",\n]\n' }]);
  assert.deepEqual(levelsFor(py, 'x402'), ['review']);
  const poetry = checkFiles([{ path: 'pyproject.toml', text: '[tool.poetry.dependencies]\npython = "^3.11"\nx402 = "^2.21"\n' }]);
  assert.deepEqual(levelsFor(poetry, 'x402'), ['ok']);
});

test('Go modules: old path, pre-fix pseudo-version, current path', () => {
  const gomod = [
    'module example.com/agent',
    '',
    'go 1.24',
    '',
    'require (',
    '\tgithub.com/coinbase/x402/go v0.0.0-20260421184015-dd927a26cfef',
    '\tgithub.com/x402-foundation/x402/go v0.0.0-20260701000000-0123456789ab // indirect',
    ')',
    '',
    'require github.com/x402-foundation/x402/go/v2 v2.28.0',
  ].join('\n');
  const r = checkFiles([{ path: 'go.mod', text: gomod }]);
  assert.deepEqual(levelsFor(r, 'github.com/coinbase/x402/go'), ['fix']);
  assert.deepEqual(levelsFor(r, 'github.com/x402-foundation/x402/go'), ['fix']);
  assert.deepEqual(levelsFor(r, 'github.com/x402-foundation/x402/go/v2'), ['ok']);
});

test('code settings that switch the limit off', () => {
  const ts = [
    "import { x402Client } from '@x402/core/client';",
    'const client = new x402Client({',
    '  schemes,',
    '  spendControls: false,',
    '});',
    'const wide = { maxAmountPerPayment: false, allowedAssets: true };',
    'client.setSpendControls(false);',
    'const cfg = { paymentRequirementsSelector: pickCheapest };',
    'const json = {"spendControls": false};',
  ].join('\n');
  const r = checkFiles([{ path: 'src/agent.ts', text: ts }]);
  assert.deepEqual(ids(r, 'fix'), ['SPEND-CONTROLS-OFF', 'PER-PAYMENT-CAP-OFF', 'SPEND-CONTROLS-OFF', 'SPEND-CONTROLS-OFF']);
  assert.deepEqual(ids(r, 'review'), ['ANY-ASSET-ALLOWED', 'CUSTOM-SELECTOR']);
  assert.equal(r.findings[0].line, 4);
});

test('mentions in comments, strings and neutral values are not flagged', () => {
  const ts = [
    '// spendControls: false would be bad here',
    ' * Pass `spendControls: false` to disable',
    "console.warn('do not set spendControls: false');",
    'const msg = "maxAmountPerPayment: false removes the cap";',
    'const cfg = { paymentRequirementsSelector: undefined, spendControls: { maxAmountPerPayment: "$5" } };',
  ].join('\n');
  assert.equal(checkFiles([{ path: 'a.ts', text: ts }]).findings.length, 0);
});

test('Python code settings', () => {
  const py = [
    'from x402 import x402Client',
    'client = x402Client(spend_controls=False)',
    'client.set_spend_controls(False)',
    'controls = {"max_amount_per_payment": False, "allowed_assets": True}',
    'cfg = Config(payment_requirements_selector=None)',
    'cfg2 = Config(payment_requirements_selector=my_picker)',
    '# spend_controls=False in a comment',
  ].join('\n');
  const r = checkFiles([{ path: 'agent.py', text: py }]);
  assert.deepEqual(ids(r, 'fix'), ['SPEND-CONTROLS-OFF', 'SPEND-CONTROLS-OFF', 'PER-PAYMENT-CAP-OFF']);
  assert.deepEqual(ids(r, 'review'), ['ANY-ASSET-ALLOWED', 'CUSTOM-SELECTOR']);
});

test('broken files are reported, not fatal', () => {
  const r = checkFiles([{ path: 'package-lock.json', text: '{not json' }]);
  assert.deepEqual(r.errors, [{ file: 'package-lock.json', error: 'not valid JSON' }]);
});

test('files the checker does not handle are ignored even if passed in', () => {
  const r = checkFiles([{ path: '.env', text: 'PRIVATE_KEY=0xabc\nspendControls: false' }]);
  assert.equal(r.filesRead, 0);
  assert.equal(r.findings.length, 0);
});
