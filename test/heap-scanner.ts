import * as v8 from 'v8';

/**
 * Scans the V8 heap for a specific sequence of bytes by pulling it as a live stream.
 * getHeapSnapshot() triggers a full Garbage Collection before taking the snapshot.
 */
export async function countSequenceInHeapStream(
  sequence: number[] | Uint8Array | string
): Promise<number> {
  return new Promise((resolve, reject) => {
    let occurrences = 0;

    const bytes = typeof sequence === 'string' 
      ? Array.from(sequence).map(c => c.charCodeAt(0)) 
      : Array.from(sequence);
    
    // We use Uint32Array for the pattern to ensure that the secret bytes 
    // are not stored contiguously in the JS heap (they will be padded by zeros).
    // This prevents the scanner from finding its own search pattern.
    const rawPattern = new Uint32Array(bytes);
    
    // KMP Failure Function (Partial Match Table)
    const computeKMPTable = (pattern: Uint32Array): number[] => {
      const table = new Array<number>(pattern.length).fill(0);
      let j = 0;
      for (let i = 1; i < pattern.length; i++) {
        while (j > 0 && pattern[i] !== pattern[j]) {
          j = table[j - 1];
        }
        if (pattern[i] === pattern[j]) {
          j++;
        }
        table[i] = j;
      }
      return table;
    };
    
    const rawKMPTable = computeKMPTable(rawPattern);
    let rawMatchIndex = 0;

    // We trigger the snapshot after preparing our patterns and tables.
    // getHeapSnapshot triggers a full gc.
    const snapshot = v8.getHeapSnapshot();

    snapshot.on('data', (chunk: Buffer) => {
      for (let i = 0; i < chunk.length; i++) {
        const byte = chunk[i];

        // Match raw using KMP
        while (rawMatchIndex > 0 && byte !== rawPattern[rawMatchIndex]) {
          rawMatchIndex = rawKMPTable[rawMatchIndex - 1];
        }
        if (byte === rawPattern[rawMatchIndex]) {
          rawMatchIndex++;
          if (rawMatchIndex === rawPattern.length) {
            occurrences++;
            rawMatchIndex = rawKMPTable[rawMatchIndex - 1];
          }
        }
      }
    });

    snapshot.on('end', () => resolve(occurrences));
    snapshot.on('error', reject);
  });
}

/**
 * Validates if the scanner can find a given pattern in memory.
 */
export async function verifyScannerFunctionality(
  pattern: string | Uint8Array,
  expectPresent: boolean
): Promise<void> {
  const sequence =
    typeof pattern === 'string'
      ? Array.from(pattern).map(c => c.charCodeAt(0))
      : Array.from(pattern);
  const count = await countSequenceInHeapStream(sequence);
  const found = count > 0;

  if (found !== expectPresent) {
    const patternStr =
      typeof pattern === 'string' ? pattern : `Uint8Array(${pattern.length})`;
    const errorMsg = `Scanner validation failed: Expected presence: ${expectPresent}, but found: ${found} (count: ${count}). Pattern: ${patternStr}`;
    throw new Error(errorMsg);
  }
}
