/*! scure-bip39 - MIT License (c) 2022 Patricio Palladino, Paul Miller (paulmillr.com) */
import assert from '@noble/hashes/_assert';
import { pbkdf2, pbkdf2Async } from '@noble/hashes/pbkdf2';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { randomBytes } from '@noble/hashes/utils';
import { utils as baseUtils } from '@scure/base';

// Normalization replaces equivalent sequences of characters
// so that any two texts that are equivalent will be reduced
// to the same sequence of code points, called the normal form of the original text.
function nfkd(str: string) {
  if (typeof str !== 'string') throw new TypeError(`Invalid mnemonic type: ${typeof str}`);
  return str.normalize('NFKD');
}

function normalize(str: string) {
  const norm = nfkd(str);
  const words = norm.split(' ');
  if (![12, 15, 18, 21, 24].includes(words.length)) throw new Error('Invalid mnemonic');
  return { nfkd: norm, words };
}

function assertEntropy(entropy: Uint8Array) {
  assert.bytes(entropy, 16, 20, 24, 28, 32);
}

/**
 * Generate x random words. Uses Cryptographically-Secure Random Number Generator.
 * @param wordlist imported wordlist for specific language
 * @param strength mnemonic strength 128-256 bits
 * @example
 * generateMnemonic(wordlist, 128)
 * // 'legal winner thank year wave sausage worth useful legal winner thank yellow'
 */
export function generateMnemonic(wordlist: string[], strength: number = 128): Uint8Array {
  assert.number(strength);
  if (strength % 32 !== 0 || strength > 256) throw new TypeError('Invalid entropy');
  return entropyToMnemonic(randomBytes(strength / 8), wordlist);
}

const calcChecksum = (entropy: Uint8Array) => {
  // Checksum is ent.length/4 bits long
  const bitsLeft = 8 - entropy.length / 4;
  // Zero rightmost "bitsLeft" bits in byte
  // For example: bitsLeft=4 val=10111101 -> 10110000
  return new Uint8Array([(sha256(entropy)[0] >> bitsLeft) << bitsLeft]);
};

function getCoder(wordlist: string[]) {
  if (!Array.isArray(wordlist) || wordlist.length !== 2 ** 11 || typeof wordlist[0] !== 'string')
    throw new Error('Worlist: expected array of 2048 strings');
  wordlist.forEach((i) => {
    if (typeof i !== 'string') throw new Error(`Wordlist: non-string element: ${i}`);
  });
  return baseUtils.chain(
    baseUtils.checksum(1, calcChecksum),
    baseUtils.radix2(11, true),
    baseUtils.alphabet(wordlist)
  );
}

/**
 * Reversible: Converts mnemonic string to raw entropy in form of byte array.
 * @param mnemonic 12-24 words
 * @param wordlist imported wordlist for specific language
 * @example
 * const mnem = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
 * mnemonicToEntropy(mnem, wordlist)
 * // Produces
 * new Uint8Array([
 *   0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
 *   0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f
 * ])
 */
export function mnemonicToEntropy(mnemonic: string | Uint8Array, wordlist: string[]): Uint8Array {
  let entropy;
  if (typeof mnemonic === 'string') {
    const { words } = normalize(mnemonic);
    entropy = getCoder(wordlist).decode(words);
  } else {
    // expected intanceOf Uint8Array when used with eth-hd-keyring
    entropy = getCoder(wordlist).decode(
      Array.from(new Uint16Array(mnemonic.buffer)).map((i) => wordlist[i])
    );
  }
  assertEntropy(entropy);
  return entropy;
}

/**
 * Reversible: Converts raw entropy in form of byte array to mnemonic string.
 * @param entropy byte array
 * @param wordlist imported wordlist for specific language
 * @returns 12-24 words
 * @example
 * const ent = new Uint8Array([
 *   0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
 *   0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f
 * ]);
 * entropyToMnemonic(ent, wordlist);
 * // 'legal winner thank year wave sausage worth useful legal winner thank yellow'
 */
export function entropyToMnemonic(entropy: Uint8Array, wordlist: string[]): Uint8Array {
  assertEntropy(entropy);
  const words = getCoder(wordlist).encode(entropy);
  const indices = words.map((word) => wordlist.indexOf(word));
  const uInt8ArrayOfMnemonic = new Uint8Array(new Uint16Array(indices).buffer);
  return uInt8ArrayOfMnemonic;
}

/**
 * Validates mnemonic for being 12-24 words contained in `wordlist`.
 */
export function validateMnemonic(mnemonic: string | Uint8Array, wordlist: string[]): boolean {
  try {
    mnemonicToEntropy(mnemonic, wordlist);
  } catch (e) {
    return false;
  }
  return true;
}

const salt = (passphrase: string) => nfkd(`mnemonic${passphrase}`);

/**
 * Irreversible: Uses KDF to derive 64 bytes of key data from mnemonic + optional password.
 * @param mnemonic 12-24 words
 * @param passphrase string that will additionally protect the key
 * @returns 64 bytes of key data
 * @example
 * const mnem = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
 * await mnemonicToSeed(mnem, 'password');
 * // new Uint8Array([...64 bytes])
 */
export function mnemonicToSeed(mnemonic: string, passphrase = '') {
  return pbkdf2Async(sha512, normalize(mnemonic).nfkd, salt(passphrase), { c: 2048, dkLen: 64 });
}

/**
 * Irreversible: Uses KDF to derive 64 bytes of key data from mnemonic + optional password.
 * @param mnemonic 12-24 words
 * @param passphrase string that will additionally protect the key
 * @returns 64 bytes of key data
 * @example
 * const mnem = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
 * mnemonicToSeedSync(mnem, 'password');
 * // new Uint8Array([...64 bytes])
 */
export function mnemonicToSeedSync(
  mnemonic: string | Uint8Array,
  wordlist: string[],
  passphrase = ''
) {
  let mnemonicUint8Array;
  if (typeof mnemonic === 'string') {
    mnemonicUint8Array = new TextEncoder().encode(normalize(mnemonic).nfkd);
  } else {
    mnemonicUint8Array = new TextEncoder().encode(
      Array.from(new Uint16Array(mnemonic.buffer))
        .map((i) => wordlist[i])
        .join(' ')
    );
  }
  return pbkdf2(sha512, mnemonicUint8Array, salt(passphrase), { c: 2048, dkLen: 64 });
}
