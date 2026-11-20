// The checker itself. Pure: it takes file paths and their text and returns
// findings. It never touches the file system, the network or a clock, so the
// same code runs in the command-line tool and in the browser page.

import {
  CODE_PATTERNS,
  GO_FIX_DATE,
  GO_MODULES,
  NPM_ADVISORIES,
  NPM_LEGACY,
  PYPI_ADVISORIES,
  RULES_AS_OF,
  SOURCES,
} from './rules.mjs';
import { goPseudoDate, isBefore, lowestAllowed, parseVersion } from './versions.mjs';

export const LEVELS = ['fix', 'review', 'ok'];

// Folders never entered: installed dependencies, build output, virtualenvs.
export const SKIP_DIRS = new Set([
  'node_modules', '.git', '.hg', '.svn', 'dist', 'build', 'out', '.next', '.nuxt', '.svelte-kit', '.turbo',
  '.cache', 'coverage', '.venv', 'venv', 'env', '__pycache__', 'site-packages', 'vendor', 'target', '.terraform',
]);

const NPM_NAMES = new Set([...NPM_ADVISORIES.map((a) => a.package), ...NPM_LEGACY.map((l) => l.package)]);
const isNpmTarget = (name) => NPM_NAMES.has(name) || /^@x402\//.test(name);
const PY_NAMES = new Set(PYPI_ADVISORIES.map((a) => a.package));
const normPy = (n) => n.toLowerCase().replace(/[-_.]+/g, '-');

const LOCKFILES = {
  'package-lock.json': 'npm-lock',
  'npm-shrinkwrap.json': 'npm-lock',
  'pnpm-lock.yaml': 'pnpm-lock',
  'yarn.lock': 'yarn-lock',
  'bun.lock': 'bun-lock',
  'poetry.lock': 'toml-lock',
  'uv.lock': 'toml-lock',
  'pdm.lock': 'toml-lock',
  'Pipfile.lock': 'pipfile-lock',
  'go.mod': 'go-mod',
};
const MANIFESTS = { 'package.json': 'npm-manifest', 'pyproject.toml': 'py-manifest' };
const JS_EXT = /\.(?:[cm]?js|[cm]?ts|jsx|tsx)$/;
const PY_EXT = /\.py$/;

const base = (p) => p.split(/[\\/]/).pop();
const dirOf = (p) => {
  const i = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\'));
  return i < 0 ? '.' : p.slice(0, i);
};

// What kind of file this is, or null if the checker never reads it. Only
// these kinds are ever opened; .env files, keys and everything else are not.
export function classify(path) {
  const b = base(path);
  if (LOCKFILES[b]) return LOCKFILES[b];
  if (MANIFESTS[b]) return MANIFESTS[b];
  if (/^requirements.*\.(?:txt|in)$/i.test(b)) return 'py-requirements';
  if (/\.d\.[cm]?ts$/.test(b) || /\.min\.js$/.test(b)) return null;
  if (JS_EXT.test(b)) return 'js-source';
  if (PY_EXT.test(b)) return 'py-source';
  return null;
}

// ---------------------------------------------------------------- parsers
// Each returns [{ eco, name, version, exact, line }]. `exact` is true for an
// installed version from a lockfile and false for a declared range.

function lineOf(text, index) {
  let n = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}

function findLine(text, needle) {
  const i = text.indexOf(needle);
  return i < 0 ? undefined : lineOf(text, i);
}

function parseNpmLock(text) {
  const out = [];
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    return { deps: out, error: 'not valid JSON' };
  }
  if (data.packages && typeof data.packages === 'object') {
    for (const [key, info] of Object.entries(data.packages)) {
      const idx = key.lastIndexOf('node_modules/');
      if (idx < 0 || !info || typeof info.version !== 'string') continue;
      const name = key.slice(idx + 'node_modules/'.length);
      if (isNpmTarget(name)) out.push({ eco: 'npm', name, version: info.version, exact: true, line: findLine(text, `"${key}"`) });
    }
  } else if (data.dependencies) {
    const walk = (deps) => {
      for (const [name, info] of Object.entries(deps || {})) {
        if (!info || typeof info !== 'object') continue;
        if (isNpmTarget(name) && typeof info.version === 'string')
          out.push({ eco: 'npm', name, version: info.version, exact: true, line: findLine(text, `"${name}"`) });
        walk(info.dependencies);
      }
    };
    walk(data.dependencies);
  }
  return { deps: out };
}

const NPM_NAME_RE = '(@x402\\/[a-z0-9._-]+|x402(?:-fetch|-axios)?)';

function parsePnpmLock(text) {
  const out = [];
  // v5: /@x402/fetch/2.22.0:  v6: /@x402/fetch@2.22.0:  v9: '@x402/fetch@2.22.0':
  const re = new RegExp(`^ {2}['"]?\\/?${NPM_NAME_RE}[@/](\\d+\\.\\d+\\.\\d+[^:'"(\\s]*)`, 'gm');
  for (const m of text.matchAll(re)) out.push({ eco: 'npm', name: m[1], version: m[2], exact: true, line: lineOf(text, m.index) });
  return { deps: out };
}

function parseYarnLock(text) {
  const out = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (!l || /^\s/.test(l) || l.startsWith('#') || !l.trimEnd().endsWith(':')) continue;
    // Header: "@x402/fetch@^2.20.0", "@x402/fetch@npm:^2.20.0":
    const names = new Set();
    for (const spec of l.slice(0, -1).split(',')) {
      const s = spec.trim().replace(/^"|"$/g, '');
      const at = s.lastIndexOf('@');
      if (at > 0) names.add(s.slice(0, at));
    }
    const name = [...names].find(isNpmTarget);
    if (!name) continue;
    for (let j = i + 1; j < lines.length && /^\s/.test(lines[j]); j++) {
      const v = lines[j].match(/^\s+version:?\s+"?([^"\s]+)"?/);
      if (v) {
        out.push({ eco: 'npm', name, version: v[1], exact: true, line: j + 1 });
        break;
      }
    }
  }
  return { deps: out };
}

function parseBunLock(text) {
  const out = [];
  const re = new RegExp(`"${NPM_NAME_RE}@(\\d+\\.\\d+\\.\\d+[^"]*)"`, 'g');
  const seen = new Set();
  for (const m of text.matchAll(re)) {
    const k = m[1] + '@' + m[2];
    if (seen.has(k)) continue;
    seen.add(k);
    out.push({ eco: 'npm', name: m[1], version: m[2], exact: true, line: lineOf(text, m.index) });
  }
  return { deps: out };
}

function parseNpmManifest(text) {
  const out = [];
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    return { deps: out, error: 'not valid JSON' };
  }
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    for (const [name, range] of Object.entries(data[field] || {})) {
      if (isNpmTarget(name)) out.push({ eco: 'npm', name, version: String(range), exact: false, line: findLine(text, `"${name}"`) });
    }
  }
  return { deps: out };
}

function parseTomlLock(text) {
  const out = [];
  const re = /^\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"/gm;
  for (const m of text.matchAll(re)) {
    if (PY_NAMES.has(normPy(m[1]))) out.push({ eco: 'pypi', name: normPy(m[1]), version: m[2], exact: true, line: lineOf(text, m.index) });
  }
  return { deps: out };
}

function parsePipfileLock(text) {
  const out = [];
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    return { deps: out, error: 'not valid JSON' };
  }
  for (const section of ['default', 'develop']) {
    for (const [name, info] of Object.entries(data[section] || {})) {
      if (!PY_NAMES.has(normPy(name)) || !info || typeof info.version !== 'string') continue;
      out.push({ eco: 'pypi', name: normPy(name), version: info.version.replace(/^==/, ''), exact: true, line: findLine(text, `"${name}"`) });
    }
  }
  return { deps: out };
}

const PY_REQ_RE = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*((?:===?|~=|>=|<=|!=|<|>)[^;#\s]+(?:\s*,\s*(?:===?|~=|>=|<=|!=|<|>)[^;#\s,]+)*)?/;

function pyDep(name, spec, line) {
  const exact = /^===?\s*\d/.test(spec || '') && !/,/.test(spec);
  return { eco: 'pypi', name: normPy(name), version: exact ? spec.replace(/^===?\s*/, '') : spec || '', exact, line };
}

function parsePyRequirements(text) {
  const out = [];
  text.split(/\r?\n/).forEach((l, i) => {
    if (/^\s*(?:#|-)/.test(l)) return;
    const m = l.match(PY_REQ_RE);
    if (m && PY_NAMES.has(normPy(m[1]))) out.push(pyDep(m[1], (m[2] || '').replace(/\s+/g, ''), i + 1));
  });
  return { deps: out };
}

function parsePyproject(text) {
  const out = [];
  text.split(/\r?\n/).forEach((l, i) => {
    // PEP 621: "x402>=2.20.0",   Poetry: x402 = "^2.20" / x402 = { version = "^2.20" }
    for (const m of l.matchAll(/["']([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*([<>=!~][^"';]*)?["']/g)) {
      if (PY_NAMES.has(normPy(m[1]))) out.push(pyDep(m[1], (m[2] || '').replace(/\s+/g, ''), i + 1));
    }
    const p = l.match(/^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*(?:"([^"]*)"|\{[^}]*version\s*=\s*"([^"]*)")/);
    if (p && PY_NAMES.has(normPy(p[1]))) out.push({ eco: 'pypi', name: normPy(p[1]), version: p[2] ?? p[3] ?? '', exact: false, line: i + 1 });
  });
  return { deps: out };
}

function parseGoMod(text) {
  const out = [];
  const lines = text.split(/\r?\n/);
  let inRequire = false;
  lines.forEach((raw, i) => {
    const l = raw.replace(/\/\/.*$/, '').trim();
    if (/^require\s*\($/.test(l)) return void (inRequire = true);
    if (inRequire && l === ')') return void (inRequire = false);
    const m = inRequire ? l.match(/^(\S+)\s+(\S+)/) : l.match(/^require\s+(\S+)\s+(\S+)/);
    if (m && GO_MODULES.some((g) => g.module === m[1])) out.push({ eco: 'go', name: m[1], version: m[2], exact: true, line: i + 1 });
  });
  return { deps: out };
}

const PARSERS = {
  'npm-lock': parseNpmLock,
  'pnpm-lock': parsePnpmLock,
  'yarn-lock': parseYarnLock,
  'bun-lock': parseBunLock,
  'npm-manifest': parseNpmManifest,
  'toml-lock': parseTomlLock,
  'pipfile-lock': parsePipfileLock,
  'py-requirements': parsePyRequirements,
  'py-manifest': parsePyproject,
  'go-mod': parseGoMod,
};

// ---------------------------------------------------------------- checks

function judgeNpmOrPy(dep, advisories, legacy) {
  const results = [];
  const lg = legacy.find((l) => l.package === dep.name);
  if (lg) {
    results.push({ level: lg.level, id: 'LEGACY-V1', title: lg.title, detail: lg.detail, fixed: null });
    return results;
  }
  const advs = advisories.filter((a) => a.package === dep.name);
  if (!advs.length) return results;
  const shown = dep.exact ? dep.version : lowestAllowed(dep.version);
  for (const a of advs) {
    if (!shown || !parseVersion(shown)) {
      results.push({
        level: 'review',
        id: a.id,
        title: `${a.title}: version could not be read`,
        detail: `The checker could not tell which version "${dep.version}" means. The fix is in ${a.fixed}. ${a.detail}`,
        fixed: a.fixed,
        source: a.source,
      });
      continue;
    }
    const affected = isBefore(shown, a.fixed) && !(a.introduced && isBefore(shown, a.introduced));
    if (!affected) {
      results.push({ level: 'ok', id: a.id, title: `${a.title}: fixed`, detail: `${dep.version} includes the fix (${a.fixed}).`, fixed: a.fixed, source: a.source });
    } else if (dep.exact) {
      results.push({ level: 'fix', id: a.id, title: a.title, detail: `${dep.version} is older than the fix in ${a.fixed}. ${a.detail}`, fixed: a.fixed, source: a.source });
    } else {
      results.push({
        level: 'review',
        id: a.id,
        title: `${a.title}: your declared range allows unfixed versions`,
        detail:
          `"${dep.version}" allows versions older than ${a.fixed}, and no lockfile in the scan says which version is installed. ` +
          `Raise the lower bound to ${a.fixed}. ${a.detail}`,
        fixed: a.fixed,
        source: a.source,
      });
    }
  }
  return results;
}

function judgeGo(dep) {
  const rule = GO_MODULES.find((g) => g.module === dep.name);
  if (!rule) return [];
  if (rule.ok) return [{ level: 'ok', id: 'GO-MODULE', title: 'Go x402 module: current path', detail: `${dep.version} is on the current module path; every version published there is from after the August 2026 fix.`, fixed: null }];
  if (rule.always) return [{ level: rule.level, id: 'GO-MODULE', title: rule.title, detail: rule.detail, fixed: null, source: 'csa' }];
  const d = goPseudoDate(dep.version);
  if (d && d < GO_FIX_DATE) return [{ level: rule.level, id: 'GO-MODULE', title: rule.title, detail: rule.detail, fixed: null, source: 'csa' }];
  if (d) return [{ level: 'ok', id: 'GO-MODULE', title: 'Go x402 module: published after the fix date', detail: `${dep.version} was published after 2026-08-18.`, fixed: null }];
  return [{ level: 'review', id: 'GO-MODULE', title: 'Go x402 module: check the release date', detail: `The checker could not date ${dep.version}. The Go fix shipped on 2026-08-18; move to github.com/x402-foundation/x402/go/v2.`, fixed: null }];
}

// Where the quoted string that position `at` sits in was opened, or -1 when
// `at` is not inside a string. Used to skip log messages and help text that
// mention a setting. A heuristic: strings that span lines are not tracked.
function openQuoteBefore(line, at) {
  let open = -1;
  for (let i = 0; i < at; i++) {
    const ch = line[i];
    if (ch === '\\') {
      i++;
      continue;
    }
    if (open >= 0) {
      if (ch === line[open]) open = -1;
    } else if (ch === '"' || ch === "'" || ch === '`') open = i;
  }
  return open;
}

// A match inside a string counts only when the string is just the option name
// used as a quoted key, as in {"spendControls": false}.
function isQuotedKey(line, m) {
  const open = openQuoteBefore(line, m.index);
  if (open < 0) return true;
  const name = m[0].match(/^[A-Za-z_]+/);
  return open === m.index - 1 && !!name && line[m.index + name[0].length] === line[open];
}

function scanSource(path, text, lang) {
  const out = [];
  const patterns = CODE_PATTERNS.filter((p) => p.langs.includes(lang));
  if (!patterns.length) return out;
  // Cheap pre-filter: only files that mention one of the option names.
  if (!/spendControls|SpendControls|spend_controls|maxAmountPerPayment|max_amount_per_payment|allowedAssets|allowed_assets|equirementsSelector|requirements_selector/.test(text)) return out;
  const lines = text.split(/\r?\n/);
  lines.forEach((l, i) => {
    const t = l.trim();
    if (t.startsWith('//') || t.startsWith('*') || t.startsWith('/*') || t.startsWith('#')) return;
    for (const p of patterns) {
      const m = p.re.exec(l);
      if (m && isQuotedKey(l, m)) out.push({ level: p.level, id: p.id, title: p.title, detail: p.detail, file: path, line: i + 1, snippet: t.slice(0, 160) });
    }
  });
  return out;
}

/**
 * @param {{path: string, text: string}[]} files
 * @returns {{findings: object[], packages: object[], filesRead: number, errors: object[], rulesAsOf: string, sources: object}}
 */
export function checkFiles(files) {
  const deps = [];
  const findings = [];
  const errors = [];
  let filesRead = 0;
  for (const f of files) {
    const kind = classify(f.path);
    if (!kind || typeof f.text !== 'string') continue;
    filesRead++;
    if (kind === 'js-source' || kind === 'py-source') {
      findings.push(...scanSource(f.path, f.text, kind === 'js-source' ? 'js' : 'py'));
      continue;
    }
    const { deps: found, error } = PARSERS[kind](f.text);
    if (error) errors.push({ file: f.path, error });
    for (const d of found) deps.push({ ...d, file: f.path, dir: dirOf(f.path) });
  }

  // A declared range is only a guess at what is installed. Drop it when any
  // lockfile in the scan already says which version of that package is used.
  const locked = new Set(deps.filter((d) => d.exact).map((d) => `${d.eco}:${d.name}`));
  const used = deps.filter((d) => d.exact || !locked.has(`${d.eco}:${d.name}`));

  // One entry per package, version and file.
  const seen = new Set();
  const packages = [];
  for (const d of used) {
    const key = `${d.eco}:${d.name}:${d.version}:${d.file}`;
    if (seen.has(key)) continue;
    seen.add(key);
    packages.push({ eco: d.eco, name: d.name, version: d.version, exact: d.exact, file: d.file, line: d.line });
    const judged =
      d.eco === 'npm' ? judgeNpmOrPy(d, NPM_ADVISORIES, NPM_LEGACY) : d.eco === 'pypi' ? judgeNpmOrPy(d, PYPI_ADVISORIES, []) : judgeGo(d);
    for (const j of judged) findings.push({ ...j, package: d.name, version: d.version, file: d.file, line: d.line });
  }

  const rank = (l) => LEVELS.indexOf(l);
  findings.sort((a, b) => rank(a.level) - rank(b.level) || a.file.localeCompare(b.file) || (a.line || 0) - (b.line || 0));
  return { findings, packages, filesRead, errors, rulesAsOf: RULES_AS_OF, sources: SOURCES };
}

export function summarize(result) {
  const count = (lvl) => result.findings.filter((f) => f.level === lvl).length;
  return { fix: count('fix'), review: count('review'), ok: count('ok'), packages: result.packages.length, filesRead: result.filesRead };
}
