// Minimal version handling for the version strings the checker meets:
// npm semver (2.23.0, 2.23.0-beta.1), PyPI (2.20, 2.20.0.post1) and Go
// (v2.28.0, v0.0.0-20260421184015-dd927a26cfef). Pure functions, no I/O.

export function parseVersion(v) {
  if (typeof v !== 'string') return null;
  const m = v.trim().replace(/^v/, '').match(/^(\d+)(?:\.(\d+))?(?:\.(\d+))?(.*)$/);
  if (!m) return null;
  const rest = m[4] || '';
  // A leading "-" marks an npm/Go prerelease; Python ".postN" sorts after the
  // release and is treated as equal to it here (only release boundaries matter).
  const pre = /^-[0-9A-Za-z.-]+/.test(rest) ? rest.slice(1).split('+')[0] : '';
  return { major: +m[1], minor: +(m[2] || 0), patch: +(m[3] || 0), pre };
}

export function compareVersions(a, b) {
  const x = typeof a === 'string' ? parseVersion(a) : a;
  const y = typeof b === 'string' ? parseVersion(b) : b;
  if (!x || !y) return NaN;
  for (const k of ['major', 'minor', 'patch']) {
    if (x[k] !== y[k]) return x[k] < y[k] ? -1 : 1;
  }
  if (x.pre === y.pre) return 0;
  if (!x.pre) return 1;
  if (!y.pre) return -1;
  return x.pre < y.pre ? -1 : 1;
}

export function isBefore(version, fixed) {
  return compareVersions(version, fixed) < 0;
}

// Lowest version an npm range or Python specifier allows, or null when it
// cannot be told (`*`, `latest`, git URLs, `<3`, unions we do not model).
export function lowestAllowed(range) {
  if (typeof range !== 'string') return null;
  let r = range.trim();
  if (r === '' || r === '*' || r === 'latest' || /^[a-z]+:/i.test(r) || r.includes('/')) return null;
  if (r.includes('||')) {
    const parts = r.split('||').map((p) => lowestAllowed(p)).filter(Boolean);
    if (!parts.length) return null;
    return parts.sort(compareVersions)[0];
  }
  // Take the first comparator: ">=2.1.0 <3" -> ">=2.1.0"; "x402>=2.0,<3" -> ">=2.0".
  r = r.split(/[\s,]+/)[0];
  const m = r.match(/^(\^|~=|~|>=|==|===|=)?\s*v?(\d+(?:\.(?:\d+|x|\*))*(?:-[0-9A-Za-z.-]+)?)$/);
  if (!m) return null;
  const parts = m[2].split('.');
  const nums = parts.map((p) => (p === 'x' || p === '*' ? '0' : p));
  while (nums.length < 3) nums.push('0');
  return nums.slice(0, 3).join('.') + (m[2].includes('-') ? m[2].slice(m[2].indexOf('-')) : '');
}

// Go pseudo-versions carry a UTC timestamp: v0.0.0-20260421184015-dd927a26cfef
// or v1.2.4-0.20260421184015-dd927a26cfef. Returns "YYYYMMDD" or null.
export function goPseudoDate(v) {
  const m = typeof v === 'string' && v.match(/(?:^|[-.])(\d{14})-[0-9a-f]{12}(?:\+incompatible)?$/);
  return m ? m[1].slice(0, 8) : null;
}
