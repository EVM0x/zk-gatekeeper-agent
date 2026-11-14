// Proof Gatekeeper — decision engine (pure, no I/O)
export const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export const WITNESS = ['registeredVkHash', 'proofVkHash', 'minimum', 'publicBalance',
  'expiryBlock', 'currentBlock', 'recipient', 'conditionRecipient', 'amount', 'maxTransfer',
  'decision', 'taskId'];

const hex = (v) => {
  if (typeof v === 'number') return BigInt(v);
  const s = String(v).trim();
  return s.startsWith('0x') || s.startsWith('0X') ? BigInt(s) : BigInt(s);
};

// Public-input order must match the platform's: 12 inputs, commitment is the 13th signal.
export function publicInputs(input, decision, taskId) {
  const d = decision === 'APPROVE' ? 1n : 0n;
  const tid = BigInt('0x' + String(taskId).slice(-36).replace(/-/g, ''));
  return [input.registered_vk, input.proof_vk, input.minimum, input.public_balance,
    input.expiry_block, input.current_block, input.recipient, input.condition_recipient,
    input.amount, input.max_transfer, d, tid].map((v) => (hex(v) % FIELD).toString());
}

// Deterministic gate. Order matters: it is the platform's own trap precedence.
export function decide(input) {
  const eq = (a, b) => hex(a) === hex(b);
  if (!eq(input.registered_vk, input.proof_vk))
    return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };
  if (hex(input.public_balance) < hex(input.minimum))
    return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
  if (hex(input.expiry_block) <= hex(input.current_block))
    return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
  if (!eq(input.recipient, input.condition_recipient))
    return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
  if (hex(input.amount) > hex(input.max_transfer))
    return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' };
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
}
