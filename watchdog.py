#!/usr/bin/env python3
"""zkagent round watchdog.

Prints a report ONLY when something needs attention (or when the score moves).
Silent otherwise, so an empty stdout means "all good" and the cron delivers nothing.

The decision logic lives in functions so it can be tested without a live service,
a live log or a network: `report()` takes the paths and the two side effects it
needs, and `main()` is the only part that touches this machine.
"""
import json
import os
import subprocess
import sys
import urllib.request

LOG = "/home/ubuntu/zkagent/data/agent.log"
OFF = "/home/ubuntu/zkagent/data/watch_offset"
SCORE = "/home/ubuntu/zkagent/data/watch_score"
AGENT_NAME = "EVM0x Gatekeeper"
HEALTHZ = "http://127.0.0.1:4795/healthz"
LEADERBOARD = "https://agentgames.zkverify.io/api/leaderboard"

# Transport reason codes that are legitimate; anything else with proof=false is a problem.
OK_NO_PROOF = {"PROOF_REUSED"}


def sh(cmd):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=25).stdout.strip()
    except Exception:
        return ""


def write_text(path, text):
    """Write through a closed handle: an unclosed one is a leaked descriptor."""
    try:
        with open(path, "w") as f:
            f.write(text)
        return True
    except OSError:
        return False


def read_offset(path):
    try:
        return int(open(path).read().strip())
    except Exception:
        return 0


def read_new_lines(log_path, off_path):
    """Return the complete lines appended since the last run, and the new offset.

    Only whole lines are consumed. A line the service is still writing has no
    trailing newline yet, so it is left for the next run instead of being read
    half-finished and then skipped forever. The read is in bytes because the
    offset is a byte count: decoding first and measuring the decoded text drifts
    by one byte for every replacement character.
    """
    offset = read_offset(off_path)
    try:
        size = os.path.getsize(log_path)
    except OSError:
        return [], offset
    if size < offset:  # log rotated / service restarted with fresh append
        offset = 0
    if size <= offset:
        return [], offset

    with open(log_path, "rb") as f:
        f.seek(offset)
        chunk = f.read(size - offset)

    cut = chunk.rfind(b"\n")
    if cut == -1:  # nothing complete yet
        return [], offset
    complete = chunk[: cut + 1]
    return complete.decode("utf-8", "replace").splitlines(), offset + len(complete)


def classify(lines):
    """Turn log lines into alerts, and count the tasks answered in this window."""
    alerts = []
    tasks = 0
    for line in lines:
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
    return alerts, tasks


def score_alerts(rows, score_path, agent_name=AGENT_NAME):
    """Compare this agent's leaderboard row with the last one seen."""
    alerts = []
    notes = []
    mine = next((r for r in rows if isinstance(r, dict) and r.get("name") == agent_name), None)
    if not mine:
        return alerts, notes

    cur = f"{mine.get('gatekeeper')}|{mine.get('gkCorrect')}|{mine.get('gkTimeouts')}|{mine.get('status')}"
    try:
        prev = open(score_path).read().strip()
    except Exception:
        prev = ""
    if cur != prev:
        write_text(score_path, cur)
        if prev:
            notes.append(
                f"score {mine.get('gatekeeper')} (correct {mine.get('gkCorrect')}, "
                f"timeouts {mine.get('gkTimeouts')}, {mine.get('status')}, rank #{mine.get('rank')})"
            )
    if mine.get("status") not in ("active",):
        alerts.append(f"agent status = {mine.get('status')}")
    return alerts, notes


def report(log_path=LOG, off_path=OFF, score_path=SCORE, run=sh, fetch=None):
    """Build the report text. An empty string means all good."""
    fetch = fetch or fetch_leaderboard
    alerts = []
    notes = []

    # 1. service alive?
    if run("systemctl is-active zkagent") != "active":
        alerts.append("service zkagent NOT active")
        if run(f"curl -s -m 8 {HEALTHZ}") != '{"ok":true}':
            alerts.append("local /healthz not answering")

    # 2. new log lines since last run
    lines, new_offset = read_new_lines(log_path, off_path)
    log_alerts, tasks = classify(lines)
    alerts.extend(log_alerts)
    if new_offset != read_offset(off_path):
        write_text(off_path, str(new_offset))
    if tasks:
        notes.append(f"{tasks} task(s) answered this window")

    # 3. score movement (public leaderboard)
    try:
        score_alert, score_notes = score_alerts(fetch(), score_path)
        alerts.extend(score_alert)
        notes.extend(score_notes)
    except Exception as e:
        alerts.append(f"leaderboard unreachable: {type(e).__name__}")

    # 4. emit
    out = []
    if alerts:
        out.append("⚠️ zkagent")
        for a in dict.fromkeys(alerts):
            out.append("• " + a)
        for n in notes:
            out.append("· " + n)
    elif notes:
        out.append("zkagent · " + " · ".join(notes))
    return "\n".join(out)


def fetch_leaderboard():
    req = urllib.request.Request(LEADERBOARD, headers={"user-agent": "zkagent-watchdog"})
    return json.load(urllib.request.urlopen(req, timeout=20))


def main():
    text = report()
    if text:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
