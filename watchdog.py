#!/usr/bin/env python3
"""zkagent round watchdog.

Prints a report ONLY when something needs attention (or when the score moves).
Silent otherwise, so an empty stdout means "all good" and the cron delivers nothing.
"""
import json
import os
import subprocess
import urllib.request

LOG = "/home/ubuntu/zkagent/data/agent.log"
OFF = "/home/ubuntu/zkagent/data/watch_offset"
SCORE = "/home/ubuntu/zkagent/data/watch_score"
AGENT_NAME = "EVM0x Gatekeeper"

# Transport reason codes that are legitimate; anything else with proof=false is a problem.
OK_NO_PROOF = {"PROOF_REUSED"}

alerts = []
notes = []


def sh(cmd):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=25).stdout.strip()
    except Exception:
        return ""


# 1. service alive?
if sh("systemctl is-active zkagent") != "active":
    alerts.append("service zkagent NOT active")
    if sh("curl -s -m 8 http://127.0.0.1:4795/healthz") != '{"ok":true}':
        alerts.append("local /healthz not answering")

# 2. new log lines since last run
try:
    offset = int(open(OFF).read().strip())
except Exception:
    offset = 0
try:
    size = os.path.getsize(LOG)
except OSError:
    size = 0
if size < offset:  # log rotated / service restarted with fresh append
    offset = 0

new_lines = []
if size > offset:
    with open(LOG, "r", errors="replace") as f:
        f.seek(offset)
        new_lines = f.read().splitlines()
    open(OFF, "w").write(str(size))

tasks = 0
for line in new_lines:
    if line.startswith("[task]"):
        tasks += 1
        # [task] <id> DECISION/REASON proof=true|false <ms>ms
        parts = line.split()
        if len(parts) >= 4:
            verdict = parts[2]
            proof = parts[3].split("=")[-1]
            reason = verdict.split("/")[-1]
            if proof != "true" and reason not in OK_NO_PROOF:
                alerts.append(f"no proof: {parts[1][:24]} {verdict}")
    elif line.startswith("[sig] reject"):
        alerts.append("platform request failed HMAC: " + line[:90])
    elif line.startswith("[proof]"):
        alerts.append("prover error: " + line[:110])
    elif line.startswith("[fatal"):
        alerts.append("handler crash: " + line[:110])

if tasks:
    notes.append(f"{tasks} task(s) answered this window")

# 3. score movement (public leaderboard)
try:
    req = urllib.request.Request(
        "https://agentgames.zkverify.io/api/leaderboard",
        headers={"user-agent": "zkagent-watchdog"},
    )
    rows = json.load(urllib.request.urlopen(req, timeout=20))
    mine = next((r for r in rows if r.get("name") == AGENT_NAME), None)
    if mine:
        cur = f"{mine.get('gatekeeper')}|{mine.get('gkCorrect')}|{mine.get('gkTimeouts')}|{mine.get('status')}"
        try:
            prev = open(SCORE).read().strip()
        except Exception:
            prev = ""
        if cur != prev:
            open(SCORE, "w").write(cur)
            if prev:
                notes.append(
                    f"score {mine.get('gatekeeper')} (correct {mine.get('gkCorrect')}, "
                    f"timeouts {mine.get('gkTimeouts')}, {mine.get('status')}, rank #{mine.get('rank')})"
                )
        if mine.get("status") not in ("active",):
            alerts.append(f"agent status = {mine.get('status')}")
except Exception as e:
    alerts.append(f"leaderboard unreachable: {type(e).__name__}")

# 4. emit
if alerts:
    print("⚠️ zkagent")
    for a in dict.fromkeys(alerts):
        print("• " + a)
    for n in notes:
        print("· " + n)
elif notes:
    print("zkagent · " + " · ".join(notes))
