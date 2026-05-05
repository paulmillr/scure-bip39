import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual } from './assert.ts';
import { countSequenceInHeapStream } from './heap-scanner.ts';

/**
 * Heap Scanner Validation Test (libqc)
 *
 * This test ensures that our memory scanner is functional in the Node.js environment.
 */
describe('Heap Scanner Verification', () => {
  should('correctly identify an intentional global leak in Node.js', async () => {
    const id = Math.random().toString(36).substring(7);
    const secret = 'LEAK_DETECT_TEST_' + id;
    const sequence = Array.from(secret).map(c => c.charCodeAt(0));

    // 1. Inject into global scope
    (global as any).EXPECTED_LEAK = secret;

    // 2. Verify it's found
    const count = await countSequenceInHeapStream(sequence);
    deepStrictEqual(count > 0, true);

    // Cleanup
    delete (global as any).EXPECTED_LEAK;
  });

  should('correctly identify an intentional Uint8Array leak in Node.js', async () => {
    const secret = 'BYTE_LEAK_TEST_123';
    const bytes = new TextEncoder().encode(secret);

    // 1. Inject as a string
    (global as any).EXPECTED_BYTE_LEAK = secret;

    // 2. Verify it's found using the Uint8Array
    const count = await countSequenceInHeapStream(bytes);
    deepStrictEqual(count > 0, true);

    // Cleanup
    delete (global as any).EXPECTED_BYTE_LEAK;
  });

  should('correctly confirm absence after cleanup', async () => {
    // Helper to avoid keeping the secret string in the local stack of the test function
    const leakAndGetSequence = () => {
      const id = Math.random().toString(36).substring(7);
      const secret = 'LEAK_ABSENCE_TEST_' + id;
      (global as any).TEMP_LEAK = secret;
      return Array.from(secret).map(c => c.charCodeAt(0));
    };

    const sequence = leakAndGetSequence();

    // 1. Verify it's there first
    const countBefore = await countSequenceInHeapStream(sequence);
    deepStrictEqual(countBefore > 0, true);

    // 2. Clear reference
    (global as any).TEMP_LEAK = null;
    delete (global as any).TEMP_LEAK;

    // 3. Scanner should now find nothing
    const countAfter = await countSequenceInHeapStream(sequence);

    deepStrictEqual(countAfter, 0);
  });

  should('correctly confirm absence after fill(0) cleanup on Uint8Array', async () => {
    const bytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x12, 0x34, 0x56, 0x78]);
    const pattern = Array.from(bytes);

    (global as any).EXPECTED_BYTE_LEAK_ZERO = bytes;

    // Zero out the array
    bytes.fill(0);

    // Verify it's not found
    const count = await countSequenceInHeapStream(pattern);
    deepStrictEqual(count, 0);

    delete (global as any).EXPECTED_BYTE_LEAK_ZERO;
  });
});

should.runWhen(import.meta.url);
