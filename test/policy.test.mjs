// Tests for the pure decision engine — no proofs, no I/O, runs in milliseconds.
// Run with: npm test
import test from 'node:test';
import assert from 'node:assert/strict';

import { decide, publicInputs, FIELD, WITNESS } from '../policy.mjs';

const VK = '0x1a2b3c';
const RECIPIENT = '0x00000000000000000000000000000000000000aa';
const TASK_ID = '3f9a1b2c-4d5e-6f70-8192-a3b4c5d6e7f8';

// A witness that passes every gate; each test breaks exactly one field.
const valid = () => ({
  registered_vk: VK,
  proof_vk: VK,
  minimum: 100,
  public_balance: 500,
  expiry_block: 1000,
  current_block: 900,
  recipient: RECIPIENT,
  condition_recipient: RECIPIENT,
  amount: 50,
  max_transfer: 100,
});

test('a witness that satisfies every condition is approved', () => {
  assert.deepEqual(decide(valid()), {
    decision: 'APPROVE',
    reason_code: 'VALID_CONDITION',
  });
});

test('equal-but-differently-spelled values still match', () => {
  const input = { ...valid(), registered_vk: '0x1A2B3C', proof_vk: '1715004' };
  assert.equal(decide(input).decision, 'APPROVE');
});

test('a swapped verification key is rejected before anything else', () => {
  const input = { ...valid(), proof_vk: '0xdead', public_balance: 0, amount: 10000 };
  assert.deepEqual(decide(input), {
    decision: 'REJECT',
    reason_code: 'VK_SUBSTITUTION',
  });
});

test('balance under the minimum is a threshold mismatch', () => {
  const input = { ...valid(), public_balance: 99 };
  assert.deepEqual(decide(input), {
    decision: 'REJECT',
    reason_code: 'THRESHOLD_MISMATCH',
  });
});

test('balance exactly at the minimum passes the threshold', () => {
  const input = { ...valid(), public_balance: 100 };
  assert.equal(decide(input).reason_code, 'VALID_CONDITION');
});

test('an expired condition is rejected', () => {
  const input = { ...valid(), expiry_block: 900 };
  assert.deepEqual(decide(input), {
    decision: 'REJECT',
    reason_code: 'EXPIRED_CONDITION',
  });
});

test('a recipient that is not the condition recipient is rejected', () => {
  const input = { ...valid(), recipient: '0x00000000000000000000000000000000000000bb' };
  assert.deepEqual(decide(input), {
    decision: 'REJECT',
    reason_code: 'RECIPIENT_MISMATCH',
  });
});

test('an amount over the transfer cap is rejected', () => {
  const input = { ...valid(), amount: 101 };
  assert.deepEqual(decide(input), {
    decision: 'REJECT',
    reason_code: 'AMOUNT_OVERFLOW',
  });
});

test('an amount exactly at the cap passes', () => {
  const input = { ...valid(), amount: 100 };
  assert.equal(decide(input).reason_code, 'VALID_CONDITION');
});

test('trap precedence follows the documented order', () => {
  // Everything is wrong at once: the first gate is the one that reports.
  const input = {
    registered_vk: '0x1',
    proof_vk: '0x2',
    minimum: 100,
    public_balance: 0,
    expiry_block: 1,
    current_block: 2,
    recipient: '0x3',
    condition_recipient: '0x4',
    amount: 10,
    max_transfer: 1,
  };
  assert.equal(decide(input).reason_code, 'VK_SUBSTITUTION');

  const noVkSwap = { ...input, proof_vk: '0x1' };
  assert.equal(decide(noVkSwap).reason_code, 'THRESHOLD_MISMATCH');

  const funded = { ...noVkSwap, public_balance: 100 };
  assert.equal(decide(funded).reason_code, 'EXPIRED_CONDITION');

  const fresh = { ...funded, expiry_block: 3 };
  assert.equal(decide(fresh).reason_code, 'RECIPIENT_MISMATCH');

  const sameRecipient = { ...fresh, recipient: '0x4' };
  assert.equal(decide(sameRecipient).reason_code, 'AMOUNT_OVERFLOW');
});

test('publicInputs accepts decimal strings, hex strings and numbers alike', () => {
  const asHex = publicInputs({ ...valid(), minimum: '0x64' }, 'APPROVE', TASK_ID);
  const asDecimal = publicInputs({ ...valid(), minimum: '100' }, 'APPROVE', TASK_ID);
  const asNumber = publicInputs({ ...valid(), minimum: 100 }, 'APPROVE', TASK_ID);
  assert.deepEqual(asHex, asDecimal);
  assert.deepEqual(asDecimal, asNumber);
});

test('publicInputs emits the twelve signals in witness order', () => {
  const out = publicInputs(valid(), 'APPROVE', TASK_ID);
  assert.equal(out.length, 12);
  assert.equal(WITNESS.length, 12);
  assert.ok(out.every((v) => typeof v === 'string' && /^[0-9]+$/.test(v)));
});

test('publicInputs reduces every signal into the field', () => {
  const out = publicInputs(valid(), 'APPROVE', TASK_ID);
  const big = out.map((v) => BigInt(v));
  assert.ok(big.every((v) => v >= 0n && v < FIELD));
});

test('publicInputs encodes the decision as 1 for approve and 0 otherwise', () => {
  const approved = publicInputs(valid(), 'APPROVE', TASK_ID);
  const rejected = publicInputs(valid(), 'REJECT', TASK_ID);
  assert.equal(approved[10], '1');
  assert.equal(rejected[10], '0');
  // Every other signal must be identical between the two.
  approved.forEach((v, i) => {
    if (i !== 10) assert.equal(v, rejected[i]);
  });
});

test('publicInputs derives the task commitment from the task id', () => {
  const a = publicInputs(valid(), 'APPROVE', TASK_ID);
  const b = publicInputs(valid(), 'APPROVE', TASK_ID);
  const c = publicInputs(valid(), 'APPROVE', '3f9a1b2c-4d5e-6f70-8192-a3b4c5d6e7f9');
  assert.equal(a[11], b[11]);
  assert.notEqual(a[11], c[11]);
});
