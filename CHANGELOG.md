# Changelog for scure-bip39

## 2.4.0 (2026-08-27)

- Reject ill-formed Unicode (unpaired UTF-16 surrogates) in mnemonics, passphrases and wordlist entries with a `TypeError`, instead of silently encoding them as U+FFFD replacement characters; well-formed input (including U+FFFD itself and paired surrogates) is unaffected
- Improve tests

## 2.3.0 (2026-08-08)

- Rewrite package: the logic is now declared in scure-bip39 instead of `@scure/base` dependency, which was removed.
- Upgrade noble-hashes to 2.3.0.

## 2.2.0 (2026-04-21)

* **April 2026 self-audit** (all files): no major issues found
  * Audited for spec compliance and security
* Fix all Byte Array types, to ensure proper work in both TypeScript 5.6 & TypeScript 5.9+
  * TS 5.6 has `Uint8Array`, while TS 5.9+ made it generic `Uint8Array<ArrayBuffer>`
  * This creates incompatibility of code between versions
  * Previously, it was hard to use and constantly emitted errors similar to `TS2345`
  * See [typescript#62240](https://github.com/microsoft/TypeScript/issues/62240) for more context
* Fix compilation issues on TypeScript v6
* Improve tree-shaking, reduce bundle sizes
* Fix `wordlists/traditional-chinese.js`: it was exported incorrectly
* Wordlists: add PURE annotations to improve tree-shaking
* Wordlists: freeze the arrays to improve security

### New Contributors
* @Yvem made their first contribution in https://github.com/paulmillr/scure-bip39/pull/26
* @rikublock made their first contribution in https://github.com/paulmillr/scure-bip39/pull/29

*(We're skipping v2.1, to align with other noble / scure packages)*

## 2.0.1 (2025-10-07)

- `.js` extension must be used for all modules
    - Old: `@scure/bip39/wordlists/english`
    - New: `@scure/bip39/wordlists/english.js`
    - This simplifies working in browsers natively without transpilers
    - This was planned for [2.0.0](https://github.com/paulmillr/scure-bip39/releases/tag/2.0.0), but was accidentally left out
- Improve typescript autocompletion for imported submodules
- Upgrade noble-hashes to [2.0.1](https://github.com/paulmillr/noble-hashes/releases/tag/2.0.1)
- Upgrade noble-curves to [2.0.1](https://github.com/paulmillr/noble-curves/releases/tag/2.0.1)

## 2.0.0 (2025-08-25)

- The package is now ESM-only. ESM can finally be loaded from common.js on node v20.19+
    - Node v20.19 is now the minimum required version
    - Package imports now work correctly in bundler-less environments, such as browsers
    - Reduces npm package size (traffic consumed): 92KB => 78KB
    - Reduces unpacked npm size (on-disk space): 384KB => 201KB
- Make bundle sizes smaller, compared to v1.x
- Upgrade to noble v2
- Add `mnemonicToSeedWebcrypto`, which uses built-in / native / WebCrypto method - useful for React Native and similar slow environments
- Upgrade typescript compilation env to ts5.9 and es2022

## 1.6.0 (2025-04-24)

- Bump hashes to [v1.8.0](https://github.com/paulmillr/noble-hashes/releases/tag/1.8.0), base to [v1.2.5](https://github.com/paulmillr/scure-base/releases/tag/1.2.5)
- Standalone build files are now attested, check out README for verification instructions

## 1.5.4 (2025-01-18)

Small update of scure-base to 1.2.4, to explicitly ensure broken 1.2.2 (and 1.2.3) is not used

## 1.5.3 (2025-01-18)

- Small update of scure-base to 1.2.3, to explicitly ensure broken 1.2.2 is not used

## 1.5.2 (2025-01-18)

- Use typescript verbatimModuleSyntax to support future node.js type stripping

## 1.5.1 (2025-01-03)

* Bump noble-curves to [1.8.0](https://github.com/paulmillr/noble-curves/releases/tag/1.8.0) and noble-hashes to [1.7.0](https://github.com/paulmillr/noble-hashes/releases/tag/1.7.0)
* Use typescript isolatedDeclarations to improve docs
* Publish to JSR

## 1.5.0 (2024-11-23)

- Refactor: remove backticks to be parser-friendly
- Bump hashes to [v1.6.0](https://github.com/paulmillr/noble-hashes/releases/tag/1.6.0), base to [1.2](https://github.com/paulmillr/scure-base/releases/tag/1.2.0)

## 1.4.0 (2024-09-03)

* Bump noble-hashes to [v1.5.0](https://github.com/paulmillr/noble-hashes/releases/tag/1.5.0)
* add `"sideEffects": false` to package.json by @tmm in https://github.com/paulmillr/scure-bip39/pull/22
* Improve typescript compatibility by emitting separate types for cjs / esm

### New Contributors
* @tmm made their first contribution in https://github.com/paulmillr/scure-bip39/pull/22

## 1.3.0 (2024-03-24)

Update noble-hashes [to v1.4](https://github.com/paulmillr/noble-hashes/releases/tag/1.4.0), adding support for Big-Endian platforms.

## 1.2.2 (2023-12-14)

* Add Portuguese wordlist by @mikeobank in https://github.com/paulmillr/scure-bip39/pull/19
* Improve tree-shaking by @jeetiss in https://github.com/paulmillr/scure-bip39/pull/16

### New Contributors
* @jeetiss made their first contribution in https://github.com/paulmillr/scure-bip39/pull/16
* @mikeobank made their first contribution in https://github.com/paulmillr/scure-bip39/pull/20

## 1.2.1 (2023-06-26)

The package is now hybrid common.js + ESM.

## 1.2.0 (2023-03-22)

- Update [noble-hashes to 1.3](https://github.com/paulmillr/noble-hashes/releases/tag/1.3.0)

## 1.1.0 (2022-06-12)

- Update dependencies
- Remove viral `esModuleInterop` option from typescript compiling

## 1.0.0 (2022-02-17)

First stable post-audit release

## 0.1.3 (2021-12-25)

- Initial release
