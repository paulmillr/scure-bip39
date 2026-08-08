import { mark } from '@paulmillr/jsbt/benchmark.js';
import { mnemonicToSeed, mnemonicToSeedSync } from '../index.js';

(async () => {
  const mn = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
  const pass = 'password';
  await mark('mnemonicToSeed', () => mnemonicToSeed(mn, pass))
  await mark('mnemonicToSeedSync', () => mnemonicToSeedSync(mn, pass))
})();