// Local rehearsal: signs tasks the way the platform does and checks every trap type.
import { createHmac, randomUUID } from 'node:crypto';
import { groth16 } from 'snarkjs';
import { readFileSync } from 'node:fs';

const SECRET = (process.env.AGENT_GAMES_HMAC_SECRET
  || readFileSync('/home/ubuntu/zkagent/.secret', 'utf8').trim());
const URL_ = `http://127.0.0.1:${process.env.PORT || 4795}/agent`;
const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const OTHER_VK = '0xa4c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1b8ff';
const A = '0xDe42000000000000000000000000000000000001';
const B = '0xDe42000000000000000000000000000000000002';
const sign = (raw) => createHmac('sha256', SECRET).update(raw).digest('hex');

const base = {
  registered_vk: VK, proof_vk: VK, minimum: '1000', public_balance: '1460',
  expiry_block: 19842201, current_block: 19832000, recipient: A, condition_recipient: A,
  amount: '500', max_transfer: '1000',
};

const cases = [
  ['VALID_CONDITION / approve', {}, 'APPROVE'],
  ['VK_SUBSTITUTION', { proof_vk: OTHER_VK }, 'REJECT'],
  ['THRESHOLD_MISMATCH', { public_balance: '900' }, 'REJECT'],
  ['EXPIRED_CONDITION', { expiry_block: 19832000 }, 'REJECT'],
  ['RECIPIENT_MISMATCH', { condition_recipient: B }, 'REJECT'],
  ['AMOUNT_OVERFLOW', { amount: '1001' }, 'REJECT'],
];

async function post(payload) {
  const raw = JSON.stringify(payload);
  const res = await fetch(URL_, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-agent-games-signature': sign(raw) },
    body: raw,
  });
  const text = await res.text();
  const sigOk = res.headers.get('x-agent-games-signature') === sign(text);
  return { body: JSON.parse(text), sigOk, status: res.status };
}

const vk = JSON.parse(readFileSync('/home/ubuntu/zkagent/vk.json', 'utf8'));
const reuseRef = '0x' + 'ab'.repeat(32);
let pass = 0, fail = 0;

// preflight
{
  const raw = JSON.stringify({ type: 'agent-games.preflight.v1', agent_id: 'agt_local', issued_at: new Date().toISOString(), nonce: 'n1' });
  const res = await fetch(URL_, { method: 'POST', headers: { 'content-type': 'application/json', 'x-agent-games-signature': sign(raw) }, body: raw });
  const t = await res.text();
  const ok = res.headers.get('x-agent-games-signature') === sign(t) && JSON.parse(t).ok === true;
  console.log(ok ? 'PASS' : 'FAIL', '| preflight ->', t);
  ok ? pass++ : fail++;
}

for (const [label, patch, want] of cases) {
  const task_id = 'gk_' + randomUUID();
  const payload = {
    type: 'agent-games.proof-gatekeeper.v1', task_id, mode: 'practice',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: { ...base, proof_tx: '0x' + randomUUID().replace(/-/g, ''), ...patch },
  };
  const t0 = Date.now();
  const r = await post(payload);
  let verified = null;
  if (r.body.proof) verified = await groth16.verify(vk, r.body.public_signals, r.body.proof);
  const ok = r.body.decision === want && r.sigOk && (want === 'REJECT' ? (verified === true || !r.body.proof) : verified === true);
  console.log(ok ? 'PASS' : 'FAIL', `| ${label.padEnd(26)} -> ${r.body.decision}/${r.body.reason_code} proofVerified=${verified} sig=${r.sigOk} ${Date.now() - t0}ms`);
  ok ? pass++ : fail++;
}

// replay the same proof reference in a fresh task -> must be PROOF_REUSED
{
  const task_id = 'gk_' + randomUUID();
  const payload = {
    type: 'agent-games.proof-gatekeeper.v1', task_id, mode: 'practice',
    issued_at: new Date().toISOString(), deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: { ...base, proof_tx: reuseRef },
  };
  const r = await post(payload);
  const ok = r.body.decision === 'APPROVE' && r.body.reason_code === 'VALID_CONDITION';
  console.log(ok ? 'PASS' : 'FAIL', '| fresh proof ref (first use) ->', r.body.decision + '/' + r.body.reason_code);
  ok ? pass++ : fail++;
}
{
  const task_id = 'gk_' + randomUUID();
  const payload = {
    type: 'agent-games.proof-gatekeeper.v1', task_id, mode: 'practice',
    issued_at: new Date().toISOString(), deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: { ...base, proof_tx: reuseRef },
  };
  const r = await post(payload);
  const ok = r.body.decision === 'REJECT' && r.body.reason_code === 'PROOF_REUSED';
  console.log(ok ? 'PASS' : 'FAIL', '| PROOF_REUSED (second sight) ->', r.body.decision + '/' + r.body.reason_code);
  ok ? pass++ : fail++;
}

// bad signature must be refused
{
  const raw = JSON.stringify({ type: 'agent-games.proof-gatekeeper.v1', task_id: 'gk_x', input: base });
  const res = await fetch(URL_, { method: 'POST', headers: { 'content-type': 'application/json', 'x-agent-games-signature': 'f'.repeat(64) }, body: raw });
  const t = JSON.parse(await res.text());
  const ok = res.status === 401 && t.reason_code === 'INVALID_SIGNATURE';
  console.log(ok ? 'PASS' : 'FAIL', '| bad signature rejected     ->', res.status, t.reason_code);
  ok ? pass++ : fail++;
}

console.log(`\n${pass} pass / ${fail} fail`);
process.exit(fail ? 1 : 0);
