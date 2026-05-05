import { deepStrictEqual } from './assert.ts';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { countSequenceInHeapStream } from './heap-scanner.ts';
import { validateMnemonic, validateMnemonicFromBytes } from '../src/index.ts';
import { wordlist } from '../src/wordlists/english.ts';

describe('Mnemonic Memory Security Audit', () => {
  // This test suite demonstrates that JavaScript Strings (immutable) 
  // persist in the V8 heap even after they are no longer needed, 
  // as they cannot be explicitly zeroed or cleared.

  should('String Validation API: demonstrates that strings PERSIST in memory after use', async () => {
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
    deepStrictEqual(countAfter > 0, true, 'Mnemonic string should STILL be found in heap after validation (leaked)');
  });
});

should.runWhen(import.meta.url);
