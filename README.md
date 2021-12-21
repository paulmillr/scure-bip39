# micro-bip39

Create BIP39 mnemonic phrases with minimum dependencies.

Developed for, and then extracted from
[js-ethereum-cryptography](https://github.com/ethereum/js-ethereum-cryptography). The source code is the same,
the files have been copied for convenience.

## Usage

> npm install micro-bip39

Or, `yarn add micro-bip39`

## API

To import a particular wordlist, use:

```
import { wordlist } from 'micro-bip39/wordlists/english';
import { wordlist as spanish } from 'micro-bip39/wordlists/spanish';
```

```typescript
function generateMnemonic(wordlist: string[], strength?: number): string;
function mnemonicToEntropy(mnemonic: string, wordlist: string[]): Uint8Array;
function entropyToMnemonic(entropy: Uint8Array, wordlist: string[]): string;
function validateMnemonic(mnemonic: string, wordlist: string[]): boolean;
function mnemonicToSeed(mnemonic: string, passphrase?: string): Promise<Uint8Array>;
function mnemonicToSeedSync(mnemonic: string, passphrase?: string): Uint8Array;
```

## License

[MIT License](./LICENSE)

Copyright (c) 2021 Patricio Palladino, Paul Miller, ethereum-cryptography contributors
