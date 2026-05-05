import { deepStrictEqual } from './assert.ts';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { countSequenceInHeapStream } from './heap-scanner.ts';
import { validateMnemonic, validateMnemonicFromBytes, entropyToMnemonicBytes, generateEntropyBytes } from '../src/index.ts';
import { wordlist } from '../src/wordlists/english.ts';

describe('Mnemonic Memory Security Checks', () => {
  // This test suite demonstrates that JavaScript Strings (immutable) 
  // persist in the V8 heap even after they are no longer needed, 
  // as they cannot be explicitly zeroed or cleared.

  should('String Validation API: demonstrates that strings persist in memory after use', async () => {
    // 1. Define mnemonic as a string literal. 
    // Literals are interned and persist in the V8 heap indefinitely.
    const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    let mnemonicString = MNEMONIC;

    // 2. Verify it is present in the heap initially
    const countBefore = await countSequenceInHeapStream(MNEMONIC);
    deepStrictEqual(countBefore > 0, true, 'Mnemonic string should be found in heap initially');

    // 3. Validate using the string-based API
    const isValid = validateMnemonic(mnemonicString, wordlist);
    deepStrictEqual(isValid, true, 'Mnemonic should be valid');

    // 4. Assigning to empty string doesn't zero the original memory (immutable strings)
    mnemonicString = "";

    // 5. Count after - it persists because we cannot clear it manually
    const countAfter = await countSequenceInHeapStream(MNEMONIC);
    deepStrictEqual(countAfter > 0, true, 'Mnemonic string should still be found in heap after validation (leaked)');
  });

  should('Byte-based API: demonstrates that memory can be explicitly cleared', async () => {
    // 1. Create mnemonic as Uint8Array (mutable)
    // We generate it randomly to ensure it's not in any source code constants.
    const entropy = generateEntropyBytes(128);
    const mnemonic = entropyToMnemonicBytes(entropy, wordlist);

    // 2. Validate using the byte-based API
    const isValid = validateMnemonicFromBytes(mnemonic, wordlist);
    deepStrictEqual(isValid, true, 'Mnemonic should be valid');

    // Copy pattern before zeroing
    const pattern = Array.from(mnemonic);

    // 3. Explicitly zero the memory
    // We also verify the buffer content manually to prove it's zeroed.
    deepStrictEqual(mnemonic.some(b => b !== 0), true, 'Buffer should contain data before zeroing');

    let fillCalled = false;
    const originalFill = mnemonic.fill;
    mnemonic.fill = function (value: number) {
      fillCalled = true;
      return originalFill.apply(this, [value] as any);
    };

    mnemonic.fill(0);

    deepStrictEqual(fillCalled, true, 'mnemonic.fill(0) should have been called');
    deepStrictEqual(mnemonic.every(b => b === 0), true, 'Buffer should be physically all zeros');

    // 4. Verify that the sensitive data never leaked to the V8 heap.
    // Unlike strings, byte-based mnemonics live in a separate memory area (Buffer/ArrayBuffer).
    // This check ensures that the validation process did not leave any traces on the js heap.
    const countAfter = await countSequenceInHeapStream(pattern);
    deepStrictEqual(countAfter === 0, true, 'Mnemonic content should never leak to the V8 heap');
  });
});

should.runWhen(import.meta.url);
