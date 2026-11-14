// Child process: witness -> Groth16 proof. Isolated so a slow proof never blocks the HTTP loop.
import { randomBytes } from 'node:crypto';
import { groth16, zKey } from 'snarkjs';
import { FIELD, WITNESS } from './policy.mjs';

const WASM = new URL('./circuits/gatekeeper.wasm', import.meta.url).pathname;
const ZKEY = new URL('./circuits/gatekeeper_final.zkey', import.meta.url).pathname;

process.once('message', async (signals) => {
  try {
    const witness = Object.fromEntries(WITNESS.map((n, i) => [n, signals[i]]));
    witness.salt = (BigInt('0x' + randomBytes(32).toString('hex')) % FIELD).toString();
    const { proof, publicSignals } = await groth16.fullProve(witness, WASM, ZKEY);
    if (publicSignals.length !== 13) throw new Error('signal count');
    if (publicSignals.slice(1).some((v, i) => v !== signals[i])) throw new Error('signal mismatch');
    const vk = await zKey.exportVerificationKey(ZKEY);
    if (!(await groth16.verify(vk, publicSignals, proof))) throw new Error('self verify');
    process.send({ proof, public_signals: publicSignals }, () => process.exit(0));
  } catch (err) {
    process.send({ error: String(err && err.message) }, () => process.exit(1));
  }
});
