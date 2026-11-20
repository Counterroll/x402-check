// Turns a checkFiles() result into text, Markdown or JSON. Pure.

import { summarize } from './engine.mjs';

export const TOOL = { name: 'x402-check', version: '0.1.0', by: 'Counterroll' };

export const LIMITS = [
  'This is a configuration check, not a security audit. It reads version numbers and searches for a few known settings, so it can miss problems and can flag code that is fine.',
  'It reads only lockfiles, package manifests and .js/.ts/.py source. It never opens .env files or keys, makes no network calls and sends nothing anywhere.',
];

// The one place Counterroll is mentioned. Keep it short and true: Counterroll
// does not move money, and the offer is an offline evaluation.
export const NEXT_STEP = [
  'This check shows how your client is configured. It cannot show whether a limit actually held when a payment went out, or why one was refused.',
  'Counterroll records each approve or refuse decision as a signed record anyone can verify offline, without trusting us. It does not move money.',
  'To see that for your own setup, ask about an offline evaluation: hello@counterroll.dev',
];

const LABEL = { fix: 'FIX', review: 'REVIEW', ok: 'OK' };

function where(f) {
  return f.line ? `${f.file}:${f.line}` : f.file;
}

export function renderText(result, { color = false, showOk = false } = {}) {
  const c = (code, s) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const tint = { fix: (s) => c('31;1', s), review: (s) => c('33;1', s), ok: (s) => c('32', s) };
  const s = summarize(result);
  const out = [];
  out.push(c('1', `${TOOL.name} ${TOOL.version}`) + c('2', ` · by ${TOOL.by} · rules as of ${result.rulesAsOf}`));
  out.push('');
  out.push(`Read ${s.filesRead} file${s.filesRead === 1 ? '' : 's'}. Found ${s.packages} x402 package entr${s.packages === 1 ? 'y' : 'ies'}.`);
  if (!s.packages && !result.findings.length) {
    out.push('No x402 packages or settings were found. If you expected some, run the checker from your project root.');
  }
  out.push(
    `${tint.fix(`${s.fix} to fix`)}, ${tint.review(`${s.review} to review`)}, ${tint.ok(`${s.ok} fixed`)}.`,
  );
  const shown = result.findings.filter((f) => showOk || f.level !== 'ok');
  for (const f of shown) {
    out.push('');
    const pkg = f.package ? ` (${f.package} ${f.version})` : '';
    out.push(`${tint[f.level](LABEL[f.level].padEnd(6))} ${c('1', f.title)}${pkg}`);
    out.push(c('2', `       ${where(f)}`));
    if (f.snippet) out.push(c('2', `       > ${f.snippet}`));
    out.push(wrap(f.detail, 7));
  }
  if (!showOk && s.ok) out.push('', c('2', `${s.ok} fixed item${s.ok === 1 ? '' : 's'} hidden. Use --all to list them.`));
  for (const e of result.errors) out.push('', c('33', `Could not read ${e.file}: ${e.error}`));
  out.push('', c('2', 'Sources: ' + Object.values(result.sources).join(' ')));
  out.push('', c('2', LIMITS.join(' ')));
  out.push('', NEXT_STEP.join('\n'));
  return out.join('\n') + '\n';
}

function wrap(text, indent, width = 96) {
  const words = text.split(/\s+/);
  const lines = [];
  let line = '';
  for (const w of words) {
    if (line && (line + ' ' + w).length > width - indent) {
      lines.push(line);
      line = w;
    } else line = line ? line + ' ' + w : w;
  }
  if (line) lines.push(line);
  return lines.map((l) => ' '.repeat(indent) + l).join('\n');
}

const mdEscape = (s) => String(s).replace(/[|`]/g, (ch) => '\\' + ch);

export function renderMarkdown(result) {
  const s = summarize(result);
  const out = [];
  out.push(`## x402 setup check`);
  out.push('');
  out.push(`${s.fix} to fix, ${s.review} to review, ${s.ok} fixed. Read ${s.filesRead} files; found ${s.packages} x402 package entries. Rules as of ${result.rulesAsOf}.`);
  const shown = result.findings.filter((f) => f.level !== 'ok');
  if (shown.length) {
    out.push('', '| Level | Finding | Where |', '| --- | --- | --- |');
    for (const f of shown) {
      const pkg = f.package ? ` (${f.package} ${f.version})` : '';
      out.push(`| ${LABEL[f.level]} | **${mdEscape(f.title)}**${mdEscape(pkg)}<br>${mdEscape(f.detail)} | \`${mdEscape(where(f))}\` |`);
    }
  }
  out.push('', `<sub>${LIMITS.join(' ')} Sources: ${Object.values(result.sources).join(' ')}</sub>`);
  out.push('', NEXT_STEP.join(' '));
  out.push('', `<sub>${TOOL.name} ${TOOL.version} by ${TOOL.by}</sub>`);
  return out.join('\n') + '\n';
}

export function renderJson(result) {
  return JSON.stringify({ tool: TOOL, summary: summarize(result), ...result, limits: LIMITS }, null, 2) + '\n';
}
