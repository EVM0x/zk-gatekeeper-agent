/* Black-box tests for the gatekeeper HTTP surface.

   server.mjs is the half that actually answers the platform: signature check,
   replay guard, idempotency, and the decision plus proof it hands back. The
   policy module underneath already has tests; this file starts the real server
   on a real port and talks to it over HTTP, because the defects worth finding
   here are in the request handling, not in the arithmetic.

   The proof child process needs snarkjs, which is deliberately not installed
   here, so every proof attempt fails with `exit`. That is the point: it lets a
   test see what the server does when proving fails, without a 30 second proof. */

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHmac, randomUUID } from 'node:crypto';
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const SERVER = join(ROOT, 'server.mjs');
const SECRET = 'test-secret-that-is-definitely-long-enough-32';

const RECIPIENT = '0x00000000000000000000000000000000000000aa';
const VK = '0x1a2b3c';

function validInput(overrides = {}) {
  return {
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
    ...overrides,
  };
}

/** Start the real server on a free port with its own state file. */
async function startServer() {
  const dir = mkdtempSync(join(tmpdir(), 'zkagent-'));
  const statePath = join(dir, 'state.json');
  const port = 20000 + Math.floor(Math.random() * 20000);
  const child = spawn(process.execPath, [SERVER], {
    env: {
      ...process.env,
      AGENT_GAMES_HMAC_SECRET: SECRET,
      PORT: String(port),
      STATE_PATH: statePath,
      AGENT_PATH: '/agent',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const logs = [];
  child.stderr.on('data', (b) => logs.push(String(b)));
  child.stdout.on('data', (b) => logs.push(String(b)));

  // wait for the listen line rather than sleeping a fixed amount
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('server did not start: ' + logs.join(''))), 10000);
    child.stdout.on('data', (b) => {
      if (String(b).includes('[up]')) {
        clearTimeout(timer);
        resolve();
      }
    });
    child.once('exit', (code) => {
      clearTimeout(timer);
      reject(new Error('server exited ' + code + ': ' + logs.join('')));
    });
  });

  const sign = (raw) => createHmac('sha256', SECRET).update(raw).digest('hex');

  async function post(body, { path = '/agent', signature } = {}) {
    const raw = typeof body === 'string' ? body : JSON.stringify(body);
    const headers = { 'content-type': 'application/json' };
    headers['x-agent-games-signature'] = signature === undefined ? sign(raw) : signature;
    const res = await fetch(`http://127.0.0.1:${port}${path}`, { method: 'POST', headers, body: raw });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* not json */ }
    return { status: res.status, json, text, raw, headers: res.headers };
  }

  return { child, port, statePath, post, sign, logs, stop: () => child.kill('SIGKILL') };
}

function task(overrides = {}) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: randomUUID(),
    input: validInput(),
    ...overrides,
  };
}

// ------------------------------------------------------------------ liveness

test('the server answers its health check without a signature', async () => {
  const s = await startServer();
  try {
    const res = await fetch(`http://127.0.0.1:${s.port}/healthz`);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { ok: true });
  } finally { s.stop(); }
});

test('a preflight handshake is accepted and signed back', async () => {
  const s = await startServer();
  try {
    const body = {
      type: 'agent-games.preflight.v1',
      agent_id: 'agt_test',
      issued_at: new Date().toISOString(),
      nonce: randomUUID(),
    };
    const res = await s.post(body);
    assert.equal(res.status, 200);
    assert.deepEqual(res.json, { ok: true, protocolVersion: 'v1' });
    // the platform verifies our signature over the exact bytes we sent
    assert.equal(res.headers.get('x-agent-games-signature'), s.sign(res.text));
  } finally { s.stop(); }
});

// ---------------------------------------------------------------- signature

test('a body with no signature is refused', async () => {
  const s = await startServer();
  try {
    const res = await s.post(task(), { signature: '' });
    assert.equal(res.status, 401);
    assert.equal(res.json.reason_code, 'INVALID_SIGNATURE');
  } finally { s.stop(); }
});

test('a body whose signature does not match is refused', async () => {
  const s = await startServer();
  try {
    const res = await s.post(task(), { signature: 'a'.repeat(64) });
    assert.equal(res.status, 401);
    assert.equal(res.json.reason_code, 'INVALID_SIGNATURE');
  } finally { s.stop(); }
});

test('a tampered body is refused even with a valid looking header', async () => {
  const s = await startServer();
  try {
    const original = JSON.stringify(task());
    const sig = s.sign(original);
    const tampered = original.replace('"amount":50', '"amount":5');
    assert.notEqual(tampered, original);
    const res = await s.post(tampered, { signature: sig });
    assert.equal(res.status, 401);
    assert.equal(res.json.reason_code, 'INVALID_SIGNATURE');
  } finally { s.stop(); }
});

test('a signature that is not 64 hex is refused rather than compared', async () => {
  const s = await startServer();
  try {
    const res = await s.post(task(), { signature: 'zzzz' });
    assert.equal(res.status, 401);
    assert.equal(res.json.reason_code, 'INVALID_SIGNATURE');
  } finally { s.stop(); }
});

// ------------------------------------------------------------------ routing

test('an unknown path is a 404 that still carries a signature', async () => {
  const s = await startServer();
  try {
    const res = await s.post(task(), { path: '/nope' });
    assert.equal(res.status, 404);
    assert.equal(res.json.reason_code, 'NOT_FOUND');
    assert.equal(res.headers.get('x-agent-games-signature'), s.sign(res.text));
  } finally { s.stop(); }
});

test('the agent path with a query string still reaches the agent', async () => {
  // The platform appends nothing today, but a proxy or a retry helper that adds
  // ?source=... would turn every task into a 404 because the path is compared
  // against req.url, which carries the query.
  const s = await startServer();
  try {
    const res = await s.post(task(), { path: '/agent?source=platform' });
    assert.equal(res.status, 200, 'query string made the agent unreachable');
    assert.notEqual(res.json.reason_code, 'NOT_FOUND');
  } finally { s.stop(); }
});

test('a GET on the agent path is a 405', async () => {
  const s = await startServer();
  try {
    const res = await fetch(`http://127.0.0.1:${s.port}/agent`);
    assert.equal(res.status, 405);
    assert.equal((await res.json()).reason_code, 'METHOD');
  } finally { s.stop(); }
});

test('a body over 64 KiB is refused before it is parsed', async () => {
  const s = await startServer();
  try {
    const res = await s.post(JSON.stringify({ type: 'agent-games.proof-gatekeeper.v1', pad: 'x'.repeat(70000) }));
    assert.equal(res.status, 413);
    assert.equal(res.json.reason_code, 'BODY_TOO_LARGE');
  } finally { s.stop(); }
});

test('a body that is not json is refused', async () => {
  const s = await startServer();
  try {
    const res = await s.post('not json at all');
    assert.equal(res.status, 400);
    assert.equal(res.json.reason_code, 'INVALID_JSON');
  } finally { s.stop(); }
});

test('a well signed body of an unknown type is refused', async () => {
  const s = await startServer();
  try {
    const res = await s.post({ type: 'something.else', input: validInput() });
    assert.equal(res.status, 400);
    assert.equal(res.json.reason_code, 'UNKNOWN_TYPE');
  } finally { s.stop(); }
});

// ------------------------------------------------------------------ verdicts

test('a valid task is approved and the decision survives the proof failure', async () => {
  const s = await startServer();
  try {
    const res = await s.post(task());
    assert.equal(res.status, 200);
    assert.equal(res.json.decision, 'APPROVE');
    assert.equal(res.json.reason_code, 'VALID_CONDITION');
    // snarkjs is not installed here, so there is no proof — but the decision is
    // still the right one and still signed
    assert.equal(res.headers.get('x-agent-games-signature'), s.sign(res.text));
  } finally { s.stop(); }
});

test('a broken condition is rejected with the policy reason code', async () => {
  const s = await startServer();
  try {
    const res = await s.post(task({ input: validInput({ public_balance: 10 }) }));
    assert.equal(res.json.decision, 'REJECT');
    assert.equal(res.json.reason_code, 'THRESHOLD_MISMATCH');
  } finally { s.stop(); }
});

test('a retried task gets the cached answer instead of a second proof', async () => {
  const s = await startServer();
  try {
    const body = task();
    const first = await s.post(body);
    const second = await s.post(body);
    assert.deepEqual(second.json, first.json);
    assert.equal(second.status, 200);
  } finally { s.stop(); }
});

test('a proof that was already used cannot be used again', async () => {
  const s = await startServer();
  try {
    const ref = '0x' + 'ab'.repeat(32);
    await s.post(task({ input: validInput({ proof_tx: ref }) }));
    const again = await s.post(task({ input: validInput({ proof_tx: ref }) }));
    assert.equal(again.json.reason_code, 'PROOF_REUSED');
  } finally { s.stop(); }
});

test('a proof is only burned by a task that was accepted', async () => {
  // A rejected task never had a usable proof, so burning its ref locks out the
  // honest task that carries the same transaction later.
  const s = await startServer();
  try {
    const ref = '0x' + 'cd'.repeat(32);
    const rejected = await s.post(task({ input: validInput({ proof_tx: ref, public_balance: 1 }) }));
    assert.equal(rejected.json.decision, 'REJECT');
    const honest = await s.post(task({ input: validInput({ proof_tx: ref }) }));
    assert.equal(honest.json.decision, 'APPROVE', 'a rejected task burned the proof reference');
  } finally { s.stop(); }
});

test('a task with no id is not answered with another task answer', async () => {
  // Both land under the empty string key, so the second one reads the first one
  // out of the cache and is told a decision about somebody else's input.
  const s = await startServer();
  try {
    const first = await s.post({ type: 'agent-games.proof-gatekeeper.v1', input: validInput() });
    const second = await s.post({
      type: 'agent-games.proof-gatekeeper.v1',
      input: validInput({ public_balance: 1 }),
    });
    assert.equal(second.json.reason_code, 'THRESHOLD_MISMATCH', 'an id-less task read another task out of the cache');
    assert.notDeepEqual(second.json, first.json);
  } finally { s.stop(); }
});

test('a proof failure is not cached as if it were the final answer', async () => {
  // Proving fails here for want of snarkjs. The platform retries a task that
  // came back without a proof; if the proof-less answer was cached, the retry is
  // handed the same proof-less answer and the bonus is lost for good.
  const s = await startServer();
  try {
    const body = task();
    const first = await s.post(body);
    assert.equal(first.json.proof, undefined, 'this test needs the proof to fail');
    const retry = await s.post(body);
    assert.equal(retry.json.decision, first.json.decision);
    // the retry must not be served from the cache while the first one has no proof
    // no state file at all is the strongest form of "nothing was cached"
    const state = existsSync(s.statePath)
      ? JSON.parse(readFileSync(s.statePath, 'utf8'))
      : { tasks: {}, refs: {} };
    const cached = state.tasks[body.task_id];
    assert.ok(!cached || cached.proof, 'a proof-less answer was cached for ' + body.task_id);
  } finally { s.stop(); }
});
