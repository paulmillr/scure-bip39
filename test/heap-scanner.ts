import * as v8 from 'v8';

/**
 * Scans the V8 heap for a specific sequence of bytes by pulling it as a live stream.
 * getHeapSnapshot() triggers a full Garbage Collection before taking the snapshot.
 */
export async function countSequenceInHeapStream(
  sequence: number[] | Uint8Array | string
): Promise<number> {
  const snapshot = v8.getHeapSnapshot();

  return new Promise((resolve, reject) => {
    let occurrences = 0;

    const bytes = typeof sequence === 'string' 
      ? Array.from(sequence).map(c => c.charCodeAt(0)) 
      : Array.from(sequence);
    const rawPattern = Buffer.from(bytes);
    const decimalPattern = Buffer.from(bytes.join(','));
    const hexPattern = Buffer.from(
      bytes.map(b => b.toString(16).padStart(2, '0')).join('')
    );

    // KMP Failure Function (Partial Match Table)
    const computeKMPTable = (pattern: Buffer): number[] => {
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
    const decimalKMPTable = computeKMPTable(decimalPattern);
    const hexKMPTable = computeKMPTable(hexPattern);

    let rawMatchIndex = 0;
    let decimalMatchIndex = 0;
    let hexMatchIndex = 0;

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

        // Match decimal using KMP
        while (
          decimalMatchIndex > 0 &&
          byte !== decimalPattern[decimalMatchIndex]
        ) {
          decimalMatchIndex = decimalKMPTable[decimalMatchIndex - 1];
        }
        if (byte === decimalPattern[decimalMatchIndex]) {
          decimalMatchIndex++;
          if (decimalMatchIndex === decimalPattern.length) {
            occurrences++;
            decimalMatchIndex = decimalKMPTable[decimalMatchIndex - 1];
          }
        }

        // Match hex using KMP
        while (hexMatchIndex > 0 && byte !== hexPattern[hexMatchIndex]) {
          hexMatchIndex = hexKMPTable[hexMatchIndex - 1];
        }
        if (byte === hexPattern[hexMatchIndex]) {
          hexMatchIndex++;
          if (hexMatchIndex === hexPattern.length) {
            occurrences++;
            hexMatchIndex = hexKMPTable[hexMatchIndex - 1];
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
    const errorMsg = `Scanner Validation FAILED: Expected presence: ${expectPresent}, but found: ${found} (count: ${count}). Pattern: ${patternStr}`;
    throw new Error(errorMsg);
  }
}
