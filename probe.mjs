// Signs a preflight exactly like the platform and posts it through the public URL.
import { createHmac, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';

const SECRET = (process.env.AGENT_GAMES_HMAC_SECRET
  || readFileSync('/home/ubuntu/zkagent/.secret', 'utf8').trim());
const URL_ = process.argv[2] || 'https://vm-0-13-ubuntu.tail1b7f8d.ts.net/zk/agent';
const sign = (raw) => createHmac('sha256', SECRET).update(raw).digest('hex');

const raw = JSON.stringify({
  type: 'agent-games.preflight.v1',
  agent_id: 'agt_public_probe',
  issued_at: new Date().toISOString(),
  nonce: randomUUID(),
});
const t0 = Date.now();
const res = await fetch(URL_, {
  method: 'POST',
  headers: { 'content-type': 'application/json', 'x-agent-games-signature': sign(raw) },
  body: raw,
});
const text = await res.text();
console.log('url      ', URL_);
console.log('status   ', res.status, `${Date.now() - t0}ms`);
console.log('body     ', text);
console.log('resp sig ', res.headers.get('x-agent-games-signature') === sign(text) ? 'VALID' : 'INVALID');
