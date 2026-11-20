// Known problems the checker looks for. Pure data: no I/O.
//
// Every version boundary below was checked on 2026-11-20 against public
// registry release dates (npm, PyPI, proxy.golang.org) and, for the spend
// control option names, against the published package code itself
// (@x402/core 2.23.0 type definitions; Python x402 2.20.0 source).
// The flaw descriptions come from the Cloud Security Alliance research note of
// 2026-10-25, which summarises a review by V12. No CVE or GitHub advisory
// existed for these flaws when this file was written.

export const RULES_AS_OF = '2026-11-20';

export const SOURCES = {
  csa: 'https://labs.cloudsecurityalliance.org/research/csa-research-note-x402-agent-payment-sdk-flaws-20261025-csa/',
};

const CLIENT_CAP_FLAW =
  'Before the August 2026 fix, the client paid whatever the server asked for: it took the first payment option offered, ' +
  'and the server chose the amount, token, recipient and network. A hostile or compromised API could ask an auto-paying ' +
  'agent for its whole balance. The fix added a default cap of $1 per payment and a US-dollar stablecoin allowlist.';

const SIWX_FLAW =
  'Before the August 2026 fix, Sign-In-With-X copied the domain and URI from the 402 response into the message it signed, ' +
  'without checking them against the site the client contacted. A malicious server could relay another site\'s login ' +
  'challenge and reuse the signature.';

// npm packages from the x402 v2 SDK.
export const NPM_ADVISORIES = [
  {
    id: 'X402-2026-08-CLIENT-CAP',
    package: '@x402/fetch',
    fixed: '2.23.0',
    level: 'fix',
    title: 'Payment client with no default spending limit',
    detail: CLIENT_CAP_FLAW,
    source: 'csa',
  },
  {
    id: 'X402-2026-08-CLIENT-CAP',
    package: '@x402/axios',
    fixed: '2.23.0',
    level: 'fix',
    title: 'Payment client with no default spending limit',
    detail: CLIENT_CAP_FLAW,
    source: 'csa',
  },
  {
    id: 'X402-2026-08-SIWX-DOMAIN',
    package: '@x402/extensions',
    fixed: '2.23.0',
    level: 'fix',
    title: 'Sign-In-With-X signs a domain the server chose',
    detail: SIWX_FLAW + ' Code that calls createSIWxPayload directly must now pass the 402 response URL.',
    source: 'csa',
  },
  {
    id: 'X402-2026-08-SVM-APPROVE',
    package: '@x402/svm',
    introduced: '2.0.0',
    fixed: '2.23.0',
    level: 'fix',
    title: 'Solana token approval accepted as a payment',
    detail:
      'The Solana "exact" verifier did not check the instruction type, so a token approval could pass as a transfer and a ' +
      'facilitator could report a payment as valid when no tokens moved. This mainly affects servers and facilitators ' +
      'that accept Solana payments.',
    source: 'csa',
  },
  {
    id: 'X402-2026-09-CORE-BYPASS',
    package: '@x402/core',
    fixed: '2.27.0',
    level: 'fix',
    title: 'Payment bypass fixed in @x402/core 2.27.0',
    detail:
      'The CSA note lists a "separate payment bypass" fixed in @x402/core 2.27.0 (September 2026) and gives no further ' +
      'description.',
    source: 'csa',
  },
];

// Legacy x402 v1 npm packages. They still work, but they did not receive the
// August 2026 changes. Their clients' only built-in limit is `maxValue`,
// default BigInt(0.1 * 10 ** 6) atomic units, compared against whatever token
// the server names (checked in x402-fetch 1.2.0 and x402-axios 1.2.1).
const LEGACY_CLIENT_DETAIL =
  'This is a legacy x402 v1 package. It did not receive the August 2026 changes (no $1 default cap and no stablecoin ' +
  'allowlist). Its only built-in limit is maxValue, which defaults to 100000 atomic units (US$0.10 if the token is USDC) ' +
  'and is compared against whatever token the server names, not checked against a list of tokens you accept.';

export const NPM_LEGACY = [
  { package: 'x402-fetch', level: 'review', title: 'Legacy x402 v1 payment client', detail: LEGACY_CLIENT_DETAIL },
  { package: 'x402-axios', level: 'review', title: 'Legacy x402 v1 payment client', detail: LEGACY_CLIENT_DETAIL },
  {
    package: 'x402',
    level: 'review',
    title: 'Legacy x402 v1 package',
    detail:
      'The "x402" npm package is the legacy v1 SDK (last published April 2026). It did not receive the August or ' +
      'September 2026 fixes. Moving to the @x402/* v2 packages is the supported path.',
  },
];

export const PYPI_ADVISORIES = [
  {
    id: 'X402-2026-08-CLIENT-CAP',
    package: 'x402',
    fixed: '2.20.0',
    level: 'fix',
    title: 'Python x402 client with no default spending limit, and the Sign-In-With-X flaw',
    detail:
      CLIENT_CAP_FLAW +
      ' The same release fixed the Sign-In-With-X domain flaw. 2.20.0 is the release PyPI lists for 2026-08-18, the date ' +
      'the CSA note gives for the Python fix.',
    source: 'csa',
  },
];

// Go. The Go client was fixed in the release of 2026-08-18 (CSA note), but no
// version number is published for it. What can be said from the Go module
// proxy: the old path github.com/coinbase/x402/go was last published as a
// pseudo-version on 2026-04-21, and every published version of
// github.com/x402-foundation/x402/go/v2 is v2.28.0 (2026-09-29) or later.
export const GO_FIX_DATE = '20260818';

export const GO_MODULES = [
  {
    module: 'github.com/coinbase/x402/go',
    level: 'fix',
    title: 'Go x402 module from the old path, published before the August 2026 fix',
    detail:
      'The github.com/coinbase/x402/go path was last published on 2026-04-21, before the Go client fix of 2026-08-18. ' +
      'The module now lives at github.com/x402-foundation/x402/go/v2.',
    always: true,
  },
  {
    module: 'github.com/x402-foundation/x402/go',
    level: 'fix',
    title: 'Go x402 module published before the August 2026 fix',
    detail:
      'This version of the Go module was published before the Go client fix of 2026-08-18. Move to ' +
      'github.com/x402-foundation/x402/go/v2.',
    byPseudoDate: true,
  },
  {
    module: 'github.com/x402-foundation/x402/go/v2',
    ok: true,
  },
];

// Settings in code that switch the default spending limit off or widen it.
// `fix` = the limit is off; `review` = worth a look, may be intended.
export const CODE_PATTERNS = [
  {
    id: 'SPEND-CONTROLS-OFF',
    langs: ['js'],
    re: /\bspendControls[\"']?\s*:\s*false\b/,
    level: 'fix',
    title: 'Spend controls turned off',
    detail:
      'spendControls: false disables every client spend control: any token, any amount. A hostile API can then ask ' +
      'for the full balance of any token the wallet holds.',
  },
  {
    id: 'SPEND-CONTROLS-OFF',
    langs: ['js'],
    re: /\.setSpendControls\(\s*false\s*\)/,
    level: 'fix',
    title: 'Spend controls turned off',
    detail: 'setSpendControls(false) disables every client spend control: any token, any amount.',
  },
  {
    id: 'SPEND-CONTROLS-OFF',
    langs: ['py'],
    re: /\bspend_controls\s*=\s*False\b|["']spend_controls["']\s*:\s*False\b|\.set_spend_controls\(\s*False\s*\)/,
    level: 'fix',
    title: 'Spend controls turned off',
    detail: 'spend_controls=False disables every client spend control: any token, any amount.',
  },
  {
    id: 'PER-PAYMENT-CAP-OFF',
    langs: ['js'],
    re: /\bmaxAmountPerPayment[\"']?\s*:\s*false\b/,
    level: 'fix',
    title: 'Per-payment cap turned off',
    detail: 'maxAmountPerPayment: false removes the per-payment cap on recognised stablecoins.',
  },
  {
    id: 'PER-PAYMENT-CAP-OFF',
    langs: ['py'],
    re: /["']max_amount_per_payment["']\s*:\s*False\b|\bmax_amount_per_payment\s*=\s*False\b/,
    level: 'fix',
    title: 'Per-payment cap turned off',
    detail: 'max_amount_per_payment: False removes the per-payment cap on recognised stablecoins.',
  },
  {
    id: 'ANY-ASSET-ALLOWED',
    langs: ['js'],
    re: /\ballowedAssets[\"']?\s*:\s*true\b/,
    level: 'review',
    title: 'Any token accepted',
    detail:
      'allowedAssets: true lets the client pay in any token the server names. The dollar cap still applies to ' +
      'recognised stablecoins, but other tokens have no cap unless you set one per asset.',
  },
  {
    id: 'ANY-ASSET-ALLOWED',
    langs: ['py'],
    re: /["']allowed_assets["']\s*:\s*True\b|\ballowed_assets\s*=\s*True\b/,
    level: 'review',
    title: 'Any token accepted',
    detail:
      'allowed_assets: True lets the client pay in any token the server names. Tokens that are not recognised ' +
      'stablecoins have no cap unless you set one per asset.',
  },
  {
    id: 'CUSTOM-SELECTOR',
    langs: ['js'],
    re: /\bpaymentRequirementsSelector[\"']?\s*(?::|=(?!=))(?!\s*(?:undefined|null)\b)/,
    level: 'review',
    title: 'Custom payment picker',
    detail:
      'A custom paymentRequirementsSelector decides which of the server\'s payment options to sign. The CSA note ' +
      'recommends checking that custom pickers cannot choose an option your limits would refuse.',
  },
  {
    id: 'CUSTOM-SELECTOR',
    langs: ['py'],
    re: /\bpayment_requirements_selector\s*=(?!=)(?!\s*None\b)/,
    level: 'review',
    title: 'Custom payment picker',
    detail:
      'A custom payment_requirements_selector decides which of the server\'s payment options to sign. Check that it ' +
      'cannot choose an option your limits would refuse.',
  },
];
