/*! scure-bip39 - MIT License (c) 2022 Patricio Palladino, Paul Miller (paulmillr.com) */
import { pbkdf2, pbkdf2Async } from '@noble/hashes/pbkdf2.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { abytes, anumber, randomBytes, type TArg, type TRet } from '@noble/hashes/utils.js';
import { pbkdf2 as pbkdf2web, sha512 as sha512web } from '@noble/hashes/webcrypto.js';
import { utils as baseUtils } from '@scure/base';

// Japanese wordlist
// The canonical BIP-39 Japanese wordlist starts with あいこくしん.
// Use that sentinel so generated phrases use U+3000 ideographic spaces.
const isJapanese = (wordlist: string[]) => wordlist[0] === '\u3042\u3044\u3053\u304f\u3057\u3093';

// Normalization replaces equivalent sequences of characters
// so that any two texts that are equivalent will be reduced
// to the same sequence of code points, called the normal form of the original text.
// https://tonsky.me/blog/unicode/#why-is-a----
// BIP-39 requires UTF-8 NFKD for localized wordlists and mnemonic sentences.
// It also applies NFKD to the "mnemonic" + passphrase salt.
function nfkd(str: string) {
  if (typeof str !== 'string') throw new TypeError('invalid mnemonic type: ' + typeof str);
  return str.normalize('NFKD');
}

// BIP-39 mnemonics are consumed in NFKD form.
// They must contain 12, 15, 18, 21, or 24 words before checksum validation.
function normalize(str: string) {
  const norm = nfkd(str);
  const words = norm.split(' ');
  if (![12, 15, 18, 21, 24].includes(words.length)) throw new Error('Invalid mnemonic');
  return { nfkd: norm, words };
}

// BIP-39 entropy payloads are 128-256 bits in 32-bit increments, i.e. 16/20/24/28/32 bytes.
function aentropy(ent: TArg<Uint8Array>) {
  abytes(ent);
  if (![16, 20, 24, 28, 32].includes(ent.length)) throw new RangeError('invalid entropy length');
}

/**
 * Generate x random words. Uses Cryptographically-Secure Random Number Generator.
 * @param wordlist - Imported wordlist for a specific language.
 * @param strength - Mnemonic strength, from 128 to 256 bits.
 * @returns 12-24 word mnemonic phrase.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Generate a new English mnemonic.
 * ```ts
 * import { generateMnemonic } from '@scure/bip39';
 * import { wordlist } from '@scure/bip39/wordlists/english.js';
 * const mnemonic = generateMnemonic(wordlist, 128);
 * // 'legal winner thank year wave sausage worth useful legal winner thank yellow'
 * ```
 */
export function generateMnemonic(wordlist: string[], strength: number = 128): string {
  anumber(strength);
  if (strength % 32 !== 0 || strength > 256) throw new RangeError('Invalid entropy');
  return entropyToMnemonic(randomBytes(strength / 8), wordlist);
}

const calcChecksum = (entropy: TArg<Uint8Array>) => {
  // Checksum is ent.length/4 bits long
  const bitsLeft = 8 - entropy.length / 4;
  // Zero rightmost "bitsLeft" bits in byte
  // For example: bitsLeft=4 val=10111101 -> 10110000
  return new Uint8Array([(sha256(entropy)[0]! >> bitsLeft) << bitsLeft]);
};

function getCoder(wordlist: string[]) {
  if (!Array.isArray(wordlist) || wordlist.length !== 2048 || typeof wordlist[0] !== 'string')
    throw new TypeError('Wordlist: expected array of 2048 strings');
  wordlist.forEach((i) => {
    if (typeof i !== 'string') throw new TypeError('wordlist: non-string element: ' + i);
  });
  // BIP-39 appends checksum bits to entropy.
  // It then splits the bitstream into 11-bit indexes for a 2048-word list.
  return baseUtils.chain(
    baseUtils.checksum(1, calcChecksum),
    baseUtils.radix2(11, true),
    baseUtils.alphabet(wordlist)
  );
}

/**
 * Reversible: Converts mnemonic string to raw entropy in form of byte array.
 * @param mnemonic - 12-24 words.
 * @param wordlist - Imported wordlist for a specific language.
 * @returns Raw entropy bytes.
 * @throws If the mnemonic shape or checksum is invalid. {@link Error}
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Decode a mnemonic back into its original entropy bytes.
 * ```ts
 * import { mnemonicToEntropy } from '@scure/bip39';
 * import { wordlist } from '@scure/bip39/wordlists/english.js';
 * const mnem = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
 * const entropy = mnemonicToEntropy(mnem, wordlist);
 * // Produces the original 16-byte entropy payload.
 * new Uint8Array([
 *   0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
 *   0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f
 * ])
 * ```
 */
export function mnemonicToEntropy(mnemonic: string, wordlist: string[]): TRet<Uint8Array> {
  const { words } = normalize(mnemonic);
  const entropy = getCoder(wordlist).decode(words);
  aentropy(entropy);
  return entropy as TRet<Uint8Array>;
}

/**
 * Reversible: Converts raw entropy in form of byte array to mnemonic string.
 * @param entropy - Byte array.
 * @param wordlist - Imported wordlist for a specific language.
 * @returns 12-24 words.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Convert raw entropy into an English mnemonic.
 * ```ts
 * import { entropyToMnemonic } from '@scure/bip39';
 * import { wordlist } from '@scure/bip39/wordlists/english.js';
 * const ent = new Uint8Array([
 *   0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
 *   0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f
 * ]);
 * const mnemonic = entropyToMnemonic(ent, wordlist);
 * // 'legal winner thank year wave sausage worth useful legal winner thank yellow'
 * ```
 */
export function entropyToMnemonic(entropy: TArg<Uint8Array>, wordlist: string[]): string {
  aentropy(entropy);
  const words = getCoder(wordlist).encode(entropy);
  return words.join(isJapanese(wordlist) ? '\u3000' : ' ');
}

/**
 * Validates mnemonic for being 12-24 words contained in `wordlist`.
 * @param mnemonic - 12-24 words.
 * @param wordlist - Imported wordlist for a specific language.
 * @returns `true` when mnemonic checksum and words are valid.
 * @example
 * Validate one English mnemonic.
 * ```ts
 * import { validateMnemonic } from '@scure/bip39';
 * import { wordlist } from '@scure/bip39/wordlists/english.js';
 * const ok = validateMnemonic(
 *   'legal winner thank year wave sausage worth useful legal winner thank yellow',
 *   wordlist
 * );
 * // => true
 * ```
 */
export function validateMnemonic(mnemonic: string, wordlist: string[]): boolean {
  try {
    mnemonicToEntropy(mnemonic, wordlist);
  } catch (e) {
    return false;
  }
  return true;
}

// BIP-39 salts PBKDF2 with the UTF-8 NFKD string "mnemonic" + passphrase.
const psalt = (passphrase: string) => nfkd('mnemonic' + passphrase);

/**
 * Irreversible: Uses KDF to derive 64 bytes of key data from mnemonic + optional password.
 * @param mnemonic - 12-24 words.
 * @param passphrase - String that will additionally protect the key.
 * @returns 64 bytes of key data.
 * @throws If the mnemonic shape is invalid. {@link Error}
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * Derive a seed from a mnemonic with the async PBKDF2 helper.
 * ```ts
 * const mnem = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
 * const seed = await mnemonicToSeed(mnem, 'password');
 * // => new Uint8Array([...64 bytes])
 * ```
 */
// BIP-39 seed derivation is independent from mnemonic generation.
// These helpers normalize the phrase but do not verify checksum or wordlist membership.
export function mnemonicToSeed(mnemonic: string, passphrase = ''): Promise<TRet<Uint8Array>> {
  return pbkdf2Async(sha512, normalize(mnemonic).nfkd, psalt(passphrase), {
    c: 2048,
    dkLen: 64,
  }) as Promise<TRet<Uint8Array>>;
}

/**
 * Irreversible: Uses KDF to derive 64 bytes of key data from mnemonic + optional password.
 * @param mnemonic - 12-24 words.
 * @param passphrase - String that will additionally protect the key.
 * @returns 64 bytes of key data.
 * @throws If the mnemonic shape is invalid. {@link Error}
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * Derive a seed from a mnemonic with the sync PBKDF2 helper.
 * ```ts
 * const mnem = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
 * const seed = mnemonicToSeedSync(mnem, 'password');
 * // => new Uint8Array([...64 bytes])
 * ```
 */
export function mnemonicToSeedSync(mnemonic: string, passphrase = ''): TRet<Uint8Array> {
  return pbkdf2(sha512, normalize(mnemonic).nfkd, psalt(passphrase), {
    c: 2048,
    dkLen: 64,
  }) as TRet<Uint8Array>;
}

/**
 * Uses native, built-in functionality, provided by globalThis.crypto.
 * Irreversible: Uses KDF to derive 64 bytes of key data from mnemonic + optional password.
 * @param mnemonic - 12-24 words.
 * @param passphrase - String that will additionally protect the key.
 * @returns 64 bytes of key data.
 * @throws If the mnemonic shape is invalid. {@link Error}
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * Derive a seed with the native WebCrypto PBKDF2 helper.
 * ```ts
 * const mnem = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
 * const seed = await mnemonicToSeedWebcrypto(mnem, 'password');
 * // => new Uint8Array([...64 bytes])
 * ```
 */
export function mnemonicToSeedWebcrypto(
  mnemonic: string,
  passphrase = ''
): Promise<TRet<Uint8Array>> {
  return pbkdf2web(sha512web, normalize(mnemonic).nfkd, psalt(passphrase), {
    c: 2048,
    dkLen: 64,
  }) as Promise<TRet<Uint8Array>>;
}

/**
 * Byte-oriented support
 *
 * The following functions provide byte-oriented BIP-39 helpers for applications
 * that need explicit control over the lifetime of sensitive data.
 *
 * Uint8Array values can be overwritten after use, while JavaScript strings are
 * immutable and cannot be reliably zeroed once created in the heap.
 *
 * Some non-ASCII code paths may still create temporary strings internally for
 * Unicode normalization and wordlist handling, but the external API lets the
 * caller keep secrets in mutable buffers and zero them when they are no longer needed.
 */

const isASCII = (data: Uint8Array) => {
  for (let i = 0; i < data.length; i++) if (data[i] > 127) return false;
  return true;
};

const WORD_SEPARATOR = 0x20;
const MNEMONIC_SALT_PREFIX = new Uint8Array([109, 110, 101, 109, 111, 110, 105, 99]); // "mnemonic"
const JAPANESE_MNEMONIC_SEPARATOR = new Uint8Array([0xe3, 0x80, 0x80]);

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function splitMnemonicBytes(mnemonic: Uint8Array): Uint8Array[] {
  const separator = isJapaneseWordSeparator(mnemonic)
    ? JAPANESE_MNEMONIC_SEPARATOR
    : new Uint8Array([WORD_SEPARATOR]);
  const words: Uint8Array[] = [];
  let start = 0;

  for (let i = 0; i <= mnemonic.length - separator.length; ) {
    if (equalBytes(mnemonic.subarray(i, i + separator.length), separator)) {
      words.push(mnemonic.subarray(start, i));
      i += separator.length;
      start = i;
      continue;
    }
    i += 1;
  }

  words.push(mnemonic.subarray(start));
  if (![12, 15, 18, 21, 24].includes(words.length)) throw new Error('Invalid mnemonic');
  return words;
}

function isJapaneseWordSeparator(bytes: Uint8Array): boolean {
  for (let i = 0; i <= bytes.length - JAPANESE_MNEMONIC_SEPARATOR.length; i++) {
    if (
      equalBytes(
        bytes.subarray(i, i + JAPANESE_MNEMONIC_SEPARATOR.length),
        JAPANESE_MNEMONIC_SEPARATOR
      )
    ) {
      return true;
    }
  }
  return false;
}

function decodeMnemonicWordIndexes(words: Uint8Array[], wordlist: string[]): number[] {
  const encodedWordlist = wordlist.map((word) => nfkdBytes(word));

  return words.map((word) => {
    for (let i = 0; i < encodedWordlist.length; i++) {
      if (equalBytes(word, encodedWordlist[i])) return i;
    }
    throw new Error('Invalid mnemonic');
  });
}

function decodeMnemonicEntropy(wordIndexes: number[]): Uint8Array {
  const entropy = new Uint8Array((wordIndexes.length / 3) * 4);
  const entropyBitLength = entropy.length * 8;
  const checksumBitLength = entropy.length / 4;
  let checksum = 0;
  let bitIndex = 0;

  for (const wordIndex of wordIndexes) {
    for (let bit = 10; bit >= 0; bit--) {
      const value = (wordIndex >> bit) & 1;

      if (bitIndex < entropyBitLength) {
        if (value) entropy[bitIndex >> 3] |= 1 << (7 - (bitIndex & 7));
      } else {
        checksum = (checksum << 1) | value;
      }

      bitIndex += 1;
    }
  }

  aentropy(entropy);
  const expectedChecksum = sha256(entropy)[0]! >> (8 - checksumBitLength);
  if (checksum !== expectedChecksum) throw new Error('Invalid mnemonic');
  return entropy;
}

function nfkdBytes(value: string | Uint8Array): Uint8Array {
  if (value instanceof Uint8Array && isASCII(value)) return value;
  const normalized =
    typeof value === 'string'
      ? value.normalize('NFKD')
      : new TextDecoder().decode(value).normalize('NFKD');
  return new TextEncoder().encode(normalized);
}

/**
 * Generates a mnemonic as UTF-8 bytes.
 * @param wordlist - Imported wordlist for a specific language.
 * @param strength - Entropy strength in bits. Default is 128.
 * @returns 12-24 words encoded as UTF-8 bytes.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Generate a mutable English mnemonic buffer.
 * ```ts
 * import { generateMnemonicBytes } from '@scure/bip39';
 * import { wordlist } from '@scure/bip39/wordlists/english.js';
 * const mnemonic = generateMnemonicBytes(wordlist, 128);
 * const text = new TextDecoder().decode(mnemonic);
 * // 'legal winner thank year wave sausage worth useful legal winner thank yellow'
 * ```
 */
export function generateMnemonicBytes(wordlist: string[], strength: number = 128): Uint8Array {
  anumber(strength);
  if (strength % 32 !== 0 || strength > 256) throw new RangeError('Invalid entropy');
  return entropyToMnemonicBytes(randomBytes(strength / 8), wordlist);
}

/**
 * Reversible: Converts raw entropy in form of byte array to mnemonic UTF-8 bytes.
 * @param entropy - Byte array.
 * @param wordlist - Imported wordlist for a specific language.
 * @returns 12-24 words encoded as UTF-8 bytes.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Convert raw entropy into mnemonic bytes.
 * ```ts
 * import { entropyToMnemonicBytes } from '@scure/bip39';
 * import { wordlist } from '@scure/bip39/wordlists/english.js';
 * const ent = new Uint8Array([
 *   0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
 *   0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f
 * ]);
 * const mnemonic = entropyToMnemonicBytes(ent, wordlist);
 * const text = new TextDecoder().decode(mnemonic);
 * // 'legal winner thank year wave sausage worth useful legal winner thank yellow'
 * ```
 */
export function entropyToMnemonicBytes(entropy: TArg<Uint8Array>, wordlist: string[]): Uint8Array {
  aentropy(entropy);
  const words = getCoder(wordlist).encode(entropy);
  const sep = isJapanese(wordlist) ? JAPANESE_MNEMONIC_SEPARATOR : new Uint8Array([WORD_SEPARATOR]);
  const encoder = new TextEncoder();
  const wordBytes = words.map((w) => encoder.encode(w));
  let totalLen = 0;
  for (let i = 0; i < wordBytes.length; i++) {
    totalLen += wordBytes[i].length;
    if (i < wordBytes.length - 1) totalLen += sep.length;
  }
  const res = new Uint8Array(totalLen);
  let pos = 0;
  for (let i = 0; i < wordBytes.length; i++) {
    res.set(wordBytes[i], pos);
    pos += wordBytes[i].length;
    if (i < wordBytes.length - 1) {
      res.set(sep, pos);
      pos += sep.length;
    }
  }
  return res;
}

/**
 * Reversible: Converts mnemonic UTF-8 bytes to raw entropy bytes.
 * @param mnemonic - UTF-8 bytes containing 12-24 words.
 * @param wordlist - Imported wordlist for a specific language.
 * @returns Raw entropy bytes.
 * @throws If the mnemonic shape or checksum is invalid. {@link Error}
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Decode mnemonic bytes back into entropy.
 * ```ts
 * import { mnemonicToEntropyFromBytes } from '@scure/bip39';
 * import { wordlist } from '@scure/bip39/wordlists/english.js';
 * const mnemonic = new TextEncoder().encode(
 *   'legal winner thank year wave sausage worth useful legal winner thank yellow'
 * );
 * const entropy = mnemonicToEntropyFromBytes(mnemonic, wordlist);
 * // Produces the original 16-byte entropy payload.
 * ```
 */
export function mnemonicToEntropyFromBytes(mnemonic: Uint8Array, wordlist: string[]): Uint8Array {
  getCoder(wordlist);
  const normalizedMnemonic = nfkdBytes(mnemonic);
  const words = splitMnemonicBytes(normalizedMnemonic);
  const wordIndexes = decodeMnemonicWordIndexes(words, wordlist);
  return decodeMnemonicEntropy(wordIndexes);
}

/**
 * Validates mnemonic bytes for being 12-24 words contained in `wordlist`.
 * @param mnemonic - UTF-8 bytes containing 12-24 words.
 * @param wordlist - Imported wordlist for a specific language.
 * @returns `true` when mnemonic checksum and words are valid.
 * @example
 * Validate one English mnemonic encoded as bytes.
 * ```ts
 * import { validateMnemonicFromBytes } from '@scure/bip39';
 * import { wordlist } from '@scure/bip39/wordlists/english.js';
 * const ok = validateMnemonicFromBytes(
 *   new TextEncoder().encode(
 *     'legal winner thank year wave sausage worth useful legal winner thank yellow'
 *   ),
 *   wordlist
 * );
 * // => true
 * ```
 */
export function bip39ValidateMnemonicFromBytes(
  mnemonic: Uint8Array,
  wordlist: string[]
): boolean {
  try {
    mnemonicToEntropyFromBytes(mnemonic, wordlist);
    return true;
  } catch (e) {
    return false;
  }
}

/** Alias for {@link bip39ValidateMnemonicFromBytes}. */
export const validateMnemonicFromBytes: (
  mnemonic: Uint8Array,
  wordlist: string[]
) => boolean = bip39ValidateMnemonicFromBytes;

/**
 * Irreversible: Uses KDF to derive 64 bytes of key data from mnemonic bytes + optional password bytes.
 * @param mnemonic - UTF-8 bytes containing 12-24 words.
 * @param passphrase - UTF-8 bytes that will additionally protect the key.
 * @returns 64 bytes of key data.
 * @throws If the mnemonic shape is invalid. {@link Error}
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * Derive a seed from byte inputs with the sync PBKDF2 helper.
 * ```ts
 * import { mnemonicToSeedSyncFromBytes } from '@scure/bip39';
 * const mnemonic = new TextEncoder().encode(
 *   'legal winner thank year wave sausage worth useful legal winner thank yellow'
 * );
 * const passphrase = new TextEncoder().encode('password');
 * const seed = mnemonicToSeedSyncFromBytes(mnemonic, passphrase);
 * // => new Uint8Array([...64 bytes])
 * ```
 */
export function mnemonicToSeedSyncFromBytes(
  mnemonic: Uint8Array,
  passphrase: Uint8Array = new Uint8Array()
): Uint8Array {
  const m = nfkdBytes(mnemonic);
  const p = nfkdBytes(passphrase);
  const salt = new Uint8Array(MNEMONIC_SALT_PREFIX.length + p.length);
  salt.set(MNEMONIC_SALT_PREFIX);
  salt.set(p, MNEMONIC_SALT_PREFIX.length);
  return pbkdf2(sha512, m, salt, { c: 2048, dkLen: 64 }) as Uint8Array;
}
