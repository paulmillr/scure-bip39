/*! scure-bip39 - MIT License (c) 2022 Patricio Palladino, Paul Miller (paulmillr.com) */
import { pbkdf2, pbkdf2Async } from '@noble/hashes/pbkdf2.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { abytes, anumber, randomBytes, type TArg, type TRet } from '@noble/hashes/utils.js';
import { pbkdf2 as pbkdf2web, sha512 as sha512web } from '@noble/hashes/webcrypto.js';

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

// BIP-39 checksum is the first ENT/32 bits of SHA-256(entropy).
// Returned as a byte with checksum bits on the left and zeroes on the right.
const calcChecksum = (entropy: Uint8Array) => {
  // Checksum is ent.length/4 bits long
  const bitsLeft = 8 - entropy.length / 4;
  // Zero rightmost "bitsLeft" bits in byte
  // For example: bitsLeft=4 val=10111101 -> 10110000
  return (sha256(entropy)[0]! >> bitsLeft) << bitsLeft;
};

function awordlist(wordlist: string[]) {
  if (!Array.isArray(wordlist) || wordlist.length !== 2048 || typeof wordlist[0] !== 'string')
    throw new TypeError('Wordlist: expected array of 2048 strings');
  wordlist.forEach((i) => {
    if (typeof i !== 'string') throw new TypeError('wordlist: non-string element: ' + i);
  });
}

// BIP-39 appends checksum bits to entropy,
// then splits the bitstream into 11-bit indexes for a 2048-word list.
function encodeWords(entropy: Uint8Array, wordlist: string[]): string[] {
  awordlist(wordlist);
  const bytes = new Uint8Array(entropy.length + 1); // entropy || checksum byte
  bytes.set(entropy);
  bytes[entropy.length] = calcChecksum(entropy);
  const words: string[] = [];
  let carry = 0; // bit accumulator, holds < 19 bits
  let bits = 0;
  for (const byte of bytes) {
    carry = (carry << 8) | byte;
    bits += 8;
    if (bits >= 11) {
      bits -= 11;
      words.push(wordlist[(carry >>> bits) & 0x7ff]!);
      carry &= (1 << bits) - 1;
    }
  }
  // Bits still in carry are the zero right bits of the checksum byte; drop them.
  return words;
}

// Reverse of encodeWords: repacks 11-bit indexes into bytes and verifies checksum.
function decodeWords(words: string[], wordlist: string[]): Uint8Array {
  awordlist(wordlist);
  const entLen = (words.length / 3) * 4; // every 3 words hold 32 entropy bits + 1 checksum bit
  const bytes = new Uint8Array(entLen + 1); // entropy || checksum byte
  let carry = 0; // bit accumulator, holds < 19 bits
  let bits = 0;
  let pos = 0;
  for (const word of words) {
    const index = wordlist.indexOf(word);
    if (index === -1) throw new Error('Unknown word: ' + word);
    carry = (carry << 11) | index;
    bits += 11;
    while (bits >= 8) {
      bits -= 8;
      bytes[pos++] = (carry >>> bits) & 0xff;
    }
    carry &= (1 << bits) - 1;
  }
  // Left-align leftover checksum bits, matching calcChecksum output.
  if (bits > 0) bytes[pos] = carry << (8 - bits);
  const entropy = bytes.subarray(0, entLen);
  if (bytes[entLen] !== calcChecksum(entropy)) throw new Error('Invalid checksum');
  return Uint8Array.from(entropy);
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
  const entropy = decodeWords(words, wordlist);
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
  const words = encodeWords(entropy as Uint8Array, wordlist);
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
const psalt = (passphrase: string) => {
  if (typeof passphrase !== 'string')
    throw new TypeError('invalid passphrase type: ' + typeof passphrase);
  return nfkd('mnemonic' + passphrase);
};

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
