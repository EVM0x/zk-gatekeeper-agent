# zk-gatekeeper-agent

An autonomous agent for **zkVerify Agent Games — Proof Gatekeeper track**.

It receives signed, proof-backed payment requests over HTTP, decides whether to
approve or reject them under a fixed policy, and returns a **Groth16 proof** that
the decision was computed correctly against the official `gatekeeper` circuit.

## What it does

```
platform  --(HMAC-signed task)-->  /agent
                                     |
                                     v
                        policy.mjs  (pure decision engine)
                                     |
                                     v
                        prover.mjs  (Groth16, child process)
                                     |
                                     v
          <--(signed decision + proof + 13 public signals)--
```

1. **Authenticate** — the raw request body is verified with HMAC-SHA256 against a
   shared secret *before* it is parsed. Nothing unauthenticated ever reaches the
   decision logic. The response is signed the same way.
2. **Decide** — `policy.mjs` evaluates the request against the circuit's rules in
   a fixed precedence order, so the reason code is always deterministic:
   `VK_SUBSTITUTION` → `THRESHOLD_MISMATCH` → `EXPIRED_CONDITION` →
   `RECIPIENT_MISMATCH` → `AMOUNT_OVERFLOW` → `CONDITION_VALID`.
3. **Prove** — the witness (12 signals + salt) is fed to the official
   `gatekeeper.wasm` / `gatekeeper_final.zkey` via snarkjs Groth16. The prover runs
   in a forked child process so a 5–10 s proving round never blocks the HTTP
   event loop. The child gets `PATH` and `NODE_ENV` only — never the secret.
4. **Fail closed** — if proving fails, times out, or the self-verification does not
   pass, the agent answers `REJECT` with a transport reason code. It never returns
   `APPROVE` without a proof that it has verified locally first.

## Anti-abuse

- **Replay guard** — every `proof_tx` that has been seen is stored in
  `data/state.json`; a second sighting is rejected as `PROOF_REUSED`.
- **Idempotency** — `task_id` is cached with its decision, so a retried task
  returns the same answer instead of being re-proved.
- **Stale tasks** — anything past `deadline_at` is refused.
- **Constant work per request** — one proof per request, hard budget of 30 s.

## Layout

| file | role |
| --- | --- |
| `server.mjs` | HTTP entry point, HMAC verification, state, prover supervision |
| `policy.mjs` | pure decision function + public-input ordering (no I/O) |
| `prover.mjs` | forked Groth16 worker, self-verifies before handing back |
| `rehearse.mjs` | local harness: 10 scenarios (valid, 5 trap types, replay, bad signature) |
| `probe.mjs` | signed preflight against the deployed endpoint |
| `circuits/` | official `gatekeeper.wasm` + `gatekeeper_final.zkey` (pinned by SHA-256) |
| `zkagent.service` | systemd unit: restart always, no new privileges, private tmp |

Circuit artifacts are byte-identical to the published ones:

- `gatekeeper.wasm` — `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f`
- `gatekeeper_final.zkey` — `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d`

Verification key hash matches the mainnet value published by the platform
(`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`).

## Running it

```bash
npm install
export AGENT_GAMES_HMAC_SECRET=...   # or place it in .secret (chmod 600)
node server.mjs                      # listens on 127.0.0.1:4795/agent
node rehearse.mjs                    # local scenario suite
```

The agent is exposed through a TLS-terminating tunnel; the platform only ever
talks to `https://<host>/agent`.

## Measured locally

- proof generation: 3.8 s (reject paths) – 10.3 s (approve path), budget 60 s
- 13 public signals, Groth16 / bn128, self-verify passes
- 10/10 rehearsal scenarios behave as specified
