// zkVerify Agent Games — Proof Gatekeeper agent.
// Public HTTPS endpoint the platform POSTs signed tasks to. We answer with a
// decision plus a locally generated Groth16 proof the platform re-verifies.
import http from 'node:http';
import { createHmac, createHash, timingSafeEqual, randomUUID } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { fork } from 'node:child_process';
import { decide, publicInputs } from './policy.mjs';
import { readFileSync as readSync } from 'node:fs';

// Secret comes from the platform (Rotate Secret) and lives in a 0600 file.
const SECRET_FILE = '/home/ubuntu/zkagent/.secret';
const SECRET = (process.env.AGENT_GAMES_HMAC_SECRET
  || (existsSync(SECRET_FILE) ? readSync(SECRET_FILE, 'utf8').trim() : ''));
const PORT = Number(process.env.PORT || 4795);
const AGENT_PATH = process.env.AGENT_PATH || '/agent';
const STATE = process.env.STATE_PATH || '/home/ubuntu/zkagent/data/state.json';
const PROOF_BUDGET_MS = 30000;

if (SECRET.length < 32) {
  console.error('[fatal] AGENT_GAMES_HMAC_SECRET missing or too short');
  process.exit(1);
}
mkdirSync('/home/ubuntu/zkagent/data', { recursive: true });

// ---- persistent state: seen proof refs (replay guard) + answered task ids
let state = { refs: {}, tasks: {} };
if (existsSync(STATE)) {
  try { state = JSON.parse(readFileSync(STATE, 'utf8')); } catch { /* start clean */ }
}
const save = () => {
  try { writeFileSync(STATE + '.tmp', JSON.stringify(state)); writeFileSync(STATE, JSON.stringify(state)); }
  catch (err) { console.error('[state] save failed', err.message); }
};

const sign = (raw) => createHmac('sha256', SECRET).update(raw).digest('hex');
const authentic = (raw, header) => {
  if (typeof header !== 'string' || !/^[a-f0-9]{64}$/i.test(header)) return false;
  const want = Buffer.from(sign(raw), 'hex');
  const got = Buffer.from(header, 'hex');
  return want.length === got.length && timingSafeEqual(want, got);
};

// ---- proof generation in a child process, hard-capped by PROOF_BUDGET_MS
function prove(signals) {
  return new Promise((resolve) => {
    const child = fork(new URL('./prover.mjs', import.meta.url).pathname, [], {
      stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
      env: { PATH: process.env.PATH, NODE_ENV: 'production' },
    });
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { child.kill('SIGKILL'); } catch { /* already gone */ }
      resolve(value);
    };
    const timer = setTimeout(() => finish({ error: 'timeout' }), PROOF_BUDGET_MS);
    child.once('error', () => finish({ error: 'spawn' }));
    child.once('exit', () => finish({ error: 'exit' }));
    child.once('message', (msg) => finish(msg));
    child.send(signals);
  });
}

function reply(res, body, status = 200) {
  const raw = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json',
    'cache-control': 'no-store',
    'x-agent-games-signature': sign(raw),
    'x-content-type-options': 'nosniff',
  });
  res.end(raw);
}

const REASONS = new Set(['VK_SUBSTITUTION', 'THRESHOLD_MISMATCH', 'EXPIRED_CONDITION',
  'RECIPIENT_MISMATCH', 'AMOUNT_OVERFLOW', 'VALID_CONDITION']);

async function handle(req, res) {
  const started = Date.now();
  // req.url still carries the query string, so compare paths only: a proxy or a
  // retry helper that appends ?source=... must not turn every task into a 404.
  const path = req.url.split('?')[0];
  if (req.method === 'GET' && path === '/healthz') return reply(res, { ok: true });
  if (path !== AGENT_PATH) return reply(res, { decision: 'REJECT', reason_code: 'NOT_FOUND' }, 404);
  if (req.method !== 'POST') return reply(res, { decision: 'REJECT', reason_code: 'METHOD' }, 405);

  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 65536) return reply(res, { decision: 'REJECT', reason_code: 'BODY_TOO_LARGE' }, 413);
    chunks.push(Buffer.from(chunk));
  }
  const raw = Buffer.concat(chunks);

  // Signature is checked over the raw body, before any parsing.
  if (!authentic(raw, req.headers['x-agent-games-signature'])) {
    console.error(`[sig] reject len=${raw.length} hdr=${String(req.headers['x-agent-games-signature']).slice(0, 10)} want=${sign(raw).slice(0, 10)} ua=${req.headers['user-agent']}`);
    return reply(res, { decision: 'REJECT', reason_code: 'INVALID_SIGNATURE' }, 401);
  }

  let body;
  try { body = JSON.parse(raw.toString('utf8')); }
  catch { return reply(res, { decision: 'REJECT', reason_code: 'INVALID_JSON' }, 400); }

  // Preflight handshake — must pass before the platform marks us active.
  // The platform's own health check may label itself slightly differently from
  // the documented type, so accept any handshake-shaped body (no `input`).
  const type = String(body && body.type || '');
  const isHandshake = body && !body.input &&
    (type === 'agent-games.preflight.v1' || /preflight|health/i.test(type));
  if (isHandshake) {
    console.log(`[preflight] type=${type} agent=${body.agent_id} nonce=${String(body.nonce).slice(0, 12)}`);
    return reply(res, { ok: true, protocolVersion: 'v1' });
  }

  if (!body || body.type !== 'agent-games.proof-gatekeeper.v1') {
    console.error(`[unknown] type=${type} keys=${body ? Object.keys(body).join(',') : '-'}`);
    return reply(res, { decision: 'REJECT', reason_code: 'UNKNOWN_TYPE' }, 400);
  }

  const taskId = String(body.task_id || '');
  const input = body.input || {};

  // Idempotency: the platform may retry the same task. A task that arrives with
  // no id has nothing to be idempotent about — keyed under the empty string,
  // every later id-less task would read the first one's answer as its own.
  if (taskId && state.tasks[taskId]) {
    console.log(`[task] ${taskId} replayed -> cached`);
    return reply(res, state.tasks[taskId]);
  }

  const ref = String(input.proof_tx || '').toLowerCase();
  let verdict;
  // A genuine proof that was already accepted does not gain re-entry — but a
  // retry of the task that accepted it is the same task, not a second use. The
  // ref is burned before the proof exists (proving can still fail below), so a
  // ref-only check answers the platform's retry with PROOF_REUSED: a decision
  // that contradicts the answer already sent, and no proof ever, because
  // PROOF_REUSED is never proved. An id-less task has no id to match on, so it
  // gets no such exemption.
  const sameTask = Boolean(taskId) && state.refs[ref] === taskId;
  if (ref && state.refs[ref] && !sameTask) {
    verdict = { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
  } else {
    verdict = decide(input);
  }

  let out = { decision: verdict.decision, reason_code: verdict.reason_code };

  // PROOF_REUSED tasks have no proof to submit — they are excluded from the bonus.
  const needsProof = verdict.reason_code !== 'PROOF_REUSED';
  if (needsProof) {
    const signals = publicInputs(input, verdict.decision, taskId);
    const proof = await prove(signals);
    if (proof && proof.proof && Array.isArray(proof.public_signals)) {
      out.proof = proof.proof;
      out.public_signals = proof.public_signals;
    } else {
      console.error(`[proof] ${taskId} failed: ${proof && proof.error}`);
    }
  }

  // Only an accepted task consumes its proof transaction. A task rejected by
  // policy never carried a usable proof, so burning its ref would lock out the
  // honest task that submits the same transaction afterwards.
  let dirty = false;
  if (ref && verdict.decision === 'APPROVE') {
    state.refs[ref] = taskId;
    dirty = true;
  }

  // Cache only a final answer. When proving fails the platform retries, and a
  // cached proof-less answer would hand the retry the same proof-less answer —
  // losing the bonus for good. PROOF_REUSED is final by definition: it has no
  // proof to submit.
  const final = Boolean(out.proof) || !needsProof;
  if (taskId && final) {
    state.tasks[taskId] = out;
    dirty = true;
  }
  if (dirty) save();

  console.log(`[task] ${taskId} ${out.decision}/${out.reason_code} proof=${Boolean(out.proof)} ${Date.now() - started}ms`);
  return reply(res, out);
}

const server = http.createServer((req, res) => {
  handle(req, res).catch((err) => {
    console.error('[fatal-handler]', err && err.stack);
    // Fail closed: never leave an APPROVE in flight after an internal error.
    try { reply(res, { decision: 'REJECT', reason_code: 'INTERNAL_ERROR' }); } catch { /* socket gone */ }
  });
});
server.requestTimeout = 70000;
server.listen(PORT, '127.0.0.1', () => console.log(`[up] gatekeeper listening on 127.0.0.1:${PORT}${AGENT_PATH}`));
