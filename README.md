# scure-bip39

Secure, audited & minimal implementation of BIP39 mnemonic phrases.

Developed for
[js-ethereum-cryptography](https://github.com/ethereum/js-ethereum-cryptography). Check out [scure-bip32](https://github.com/paulmillr/scure-bip32) if you need
hierarchical deterministic wallets ("HD Wallets").

The library has been audited by Cure53 on Jan 5, 2022. Check out the audit [PDF](./audit/2022-01-05-cure53-audit-nbl2.pdf) & [URL](https://cure53.de/pentest-report_hashing-libs.pdf). Before the audit it was called `micro-base39`.

## Usage

> npm install @scure/bip39

Or

> yarn add @scure/bip39

## API

This submodule contains the word lists defined by BIP39 for Czech, English, French, Italian, Japanese, Korean, Simplified and Traditional Chinese, and Spanish. These are not imported by default, as that would increase bundle sizes too much. Instead, you should import and use them explicitly.

To import a particular wordlist, use:

```typescript
import { wordlist } from '@scure/bip39/wordlists/english';
import { wordlist as spanish } from '@scure/bip39/wordlists/spanish';
```

```typescript
function generateMnemonic(wordlist: string[], strength?: number): string;
function mnemonicToEntropy(mnemonic: string, wordlist: string[]): Uint8Array;
function entropyToMnemonic(entropy: Uint8Array, wordlist: string[]): string;
function validateMnemonic(mnemonic: string, wordlist: string[]): boolean;
function mnemonicToSeed(mnemonic: string, passphrase?: string): Promise<Uint8Array>;
function mnemonicToSeedSync(mnemonic: string, passphrase?: string): Uint8Array;
```

All wordlists:

```typescript
import { wordlist } from '@scure/bip39/wordlists/czech';
import { wordlist } from '@scure/bip39/wordlists/english';
import { wordlist } from '@scure/bip39/wordlists/french';
import { wordlist } from '@scure/bip39/wordlists/italian';
import { wordlist } from '@scure/bip39/wordlists/japanese';
import { wordlist } from '@scure/bip39/wordlists/korean';
import { wordlist } from '@scure/bip39/wordlists/simplified-chinese';
import { wordlist } from '@scure/bip39/wordlists/spanish';
import { wordlist } from '@scure/bip39/wordlists/traditional-chinese';
```

## License

[MIT License](./LICENSE)

Copyright (c) 2022 Patricio Palladino, Paul Miller (paulmillr.com)
