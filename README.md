# x402-check

A free, offline check of an x402 project. It flags:

1. **x402 SDK versions with publicly reported flaws.** It reads your lockfiles
   (including transitive dependencies) and flags versions older than the fixes
   described in the Cloud Security Alliance research note of 2026-10-25.
2. **Settings that turn the default spending limit off**, such as
   `spendControls: false`, `maxAmountPerPayment: false`, `allowedAssets: true`
   and custom payment pickers, in JavaScript, TypeScript and Python.
3. **Legacy x402 v1 packages**, which did not receive the 2026 fixes.

It is by Counterroll. It is not affiliated with the x402 Foundation or Coinbase.

## What it never does

- It reads only lockfiles, package manifests and `.js`/`.ts`/`.py` source.
  It never opens `.env` files, keys or wallets.
- It makes no network calls, collects nothing and sends nothing anywhere.
- It never signs or sends a payment.
- It does not follow symbolic links or enter `node_modules`, virtualenvs or
  build output.
- It has no dependencies.

## Run it

From your project folder, with Node 18 or later:

```sh
npx github:Counterroll/x402-check .
```

Or clone this repository and run `node bin/x402-check.mjs path/to/your/project`.

| Option | Meaning |
| --- | --- |
| `--json` | Print the result as JSON |
| `--markdown` | Print a Markdown summary, for a pull request comment |
| `--all` | Also list packages that already have the fixes |
| `--fail-on fix\|review\|never` | When to exit 1 (default `fix`) |
| `--no-color` | Plain text |

Exit codes: `0` nothing at the `--fail-on` level, `1` findings at that level,
`2` the checker could not run. That makes it usable as a CI step, for example
in GitHub Actions:

```yaml
- uses: actions/setup-node@v4
  with:
    node-version: 22
- run: npx --yes github:Counterroll/x402-check . --markdown >> "$GITHUB_STEP_SUMMARY"
- run: npx --yes github:Counterroll/x402-check .
```

### In the browser

`web/index.html` runs the same engine in the page. Serve this folder with any
static server and open `/web/index.html`, or build a flat copy for a static
host:

```sh
node scripts/build-web.mjs web-dist
```

The page's Content-Security-Policy sets `connect-src 'none'`, so the browser
itself blocks any network request from the page after it loads.

## What it checks, exactly

| Package | Flagged when | Why |
| --- | --- | --- |
| `@x402/fetch`, `@x402/axios` | before 2.23.0 | No default spending limit: the server chose amount, token, recipient and network |
| `@x402/extensions` | before 2.23.0 | Sign-In-With-X signed a domain taken from the 402 response |
| `@x402/svm` | 2.0.0 to 2.22.x | Solana token approval accepted as a payment |
| `@x402/core` | before 2.27.0 | "Separate payment bypass" (no public description) |
| Python `x402` | before 2.20.0 | Same client and Sign-In-With-X flaws |
| Go `github.com/coinbase/x402/go` | any version | Old path, last published 2026-04-21, before the fix |
| Go `github.com/x402-foundation/x402/go` | pseudo-version dated before 2026-08-18 | Published before the Go fix |
| `x402-fetch`, `x402-axios`, `x402` (npm v1) | any version | Legacy; its only limit is `maxValue` (100000 atomic units by default) against any token |

How the boundaries were checked (2026-11-20): every `@x402/*` 2.23.0 release
on npm is dated 2026-08-18, `@x402/core` 2.27.0 is dated 2026-09-22, and the
PyPI release of Python `x402` on 2026-08-18 is 2.20.0. The `spendControls`
option and its `"$1"` default were read from the published `@x402/core` 2.23.0
code; the Python names from `x402` 2.20.0. The Go module proxy lists no
version of `github.com/x402-foundation/x402/go/v2` before v2.28.0. No CVE or
GitHub advisory existed for these flaws when the rules were written. All rules
are in `src/rules.mjs`.

Lockfiles read: `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`
(v5, v6, v9), `yarn.lock` (classic and Berry), `bun.lock`, `poetry.lock`,
`uv.lock`, `pdm.lock`, `Pipfile.lock`, `go.mod`. Manifests (`package.json`,
`pyproject.toml`, `requirements*.txt`) are used only when no lockfile in the
scan says which version is installed; a range that allows an unfixed version
is a review item, not a fix item.

## Limits

This is a configuration check, not a security audit. It reads version numbers
and searches for a few known settings, so it can miss problems (for example a
cap set in a way it does not recognise, or a Go client's settings) and can flag
code that is fine. Go source is not scanned for settings yet.

It shows how a client is configured. It cannot show whether a limit actually
held when a payment went out, or why one was refused. Counterroll records each
approve or refuse decision as a signed record anyone can verify offline. It
does not move money. To ask about an offline evaluation of your own setup:
hello@counterroll.dev

## Licence

MIT. See `LICENSE`.

## Tests

```sh
node --test test/*.test.mjs
```
