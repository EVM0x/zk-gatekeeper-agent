"""Tests for the zkagent watchdog.

The watchdog is the only thing that notices when the agent stops answering, so a
watchdog that silently loses an alert is worse than none. Everything here runs
against temp files with the service and the leaderboard stubbed out — no live
log, no network, no systemd.

Run: python3 -m unittest discover -s test -v
"""
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import watchdog  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.log = os.path.join(self.dir, "agent.log")
        self.off = os.path.join(self.dir, "watch_offset")
        self.score = os.path.join(self.dir, "watch_score")
        open(self.log, "w").close()

    def write(self, text, mode="a"):
        with open(self.log, mode) as f:
            f.write(text)

    def rows(self, **overrides):
        row = {"name": watchdog.AGENT_NAME, "gatekeeper": 10, "gkCorrect": 8,
               "gkTimeouts": 1, "status": "active", "rank": 3}
        row.update(overrides)
        return [row]

    def report(self, rows=None, run=None):
        return watchdog.report(
            log_path=self.log,
            off_path=self.off,
            score_path=self.score,
            run=run or (lambda cmd: "active"),
            fetch=lambda: self.rows() if rows is None else rows,
        )


class ReadingTest(Base):
    def test_a_fresh_log_is_read_from_the_start(self):
        self.write("[task] a1 APPROVE/VALID_CONDITION proof=true 12ms\n")
        self.assertIn("1 task(s) answered", self.report())

    def test_the_offset_advances_so_a_line_is_not_reported_twice(self):
        self.write("[task] a1 APPROVE/VALID_CONDITION proof=true 12ms\n")
        self.assertIn("1 task(s) answered", self.report())
        self.assertEqual(self.report(), "", "the same line was reported again")

    def test_only_the_new_lines_are_read(self):
        self.write("[task] a1 APPROVE/VALID_CONDITION proof=true 12ms\n")
        self.report()
        self.write("[task] a2 APPROVE/VALID_CONDITION proof=true 12ms\n")
        self.assertIn("1 task(s) answered", self.report())

    def test_a_partial_line_is_left_for_the_next_run(self):
        # The service appends while the watchdog reads. A half written line has no
        # trailing newline yet, so it must not be consumed: the bytes are gone from
        # the offset but the line is unreadable, and the alert inside it is lost.
        self.write("[task] a1 REJECT/VK_SUBSTITUTION proof=false 5ms\n")
        self.write("[task] a2 REJECT/EXPIRED_CONDITION proof=fal")
        self.assertIn("a1", self.report())

        self.write("se 7ms\n")  # the rest of the line arrives
        text = self.report()
        self.assertIn("a2", text, "the line completed in two writes was never reported")
        self.assertIn("no proof: a2", text)

    def test_a_log_with_no_newline_at_all_is_not_consumed(self):
        self.write("[task] a1 REJECT/VK_SUBSTITUTION proof=false 5ms")
        self.assertEqual(self.report(), "")
        self.assertEqual(watchdog.read_offset(self.off), 0, "a half written line advanced the offset")

    def test_a_rotated_log_is_read_again_from_the_start(self):
        self.write("[task] a1 REJECT/VK_SUBSTITUTION proof=false 5ms\n")
        self.report()
        self.assertGreater(watchdog.read_offset(self.off), 0)
        # a rotated log starts over, and it is shorter than the old offset
        self.write("[task] b1 REJECT/VK proof=false 5ms\n", mode="w")
        self.assertIn("b1", self.report())

    def test_a_missing_log_does_not_crash(self):
        os.remove(self.log)
        self.assertEqual(self.report(), "")

    def test_a_missing_offset_file_is_treated_as_zero(self):
        self.write("[task] a1 REJECT/VK_SUBSTITUTION proof=false 5ms\n")
        self.assertIn("a1", self.report())

    def test_a_corrupt_offset_file_is_treated_as_zero(self):
        self.write("[task] a1 REJECT/VK_SUBSTITUTION proof=false 5ms\n")
        open(self.off, "w").write("not a number")
        self.assertIn("a1", self.report())

    def test_bytes_are_not_miscounted_when_the_log_is_not_ascii(self):
        # The offset is a byte count. Decoding first and measuring the text drifts
        # by one byte per replacement character, which re-reads or skips lines.
        self.write("[task] a1 REJECT/VK_SUBSTITUTION proof=false 5ms — café\n")
        self.report()
        self.write("[task] a2 REJECT/EXPIRED_CONDITION proof=false 5ms\n")
        text = self.report()
        self.assertIn("a2", text)
        self.assertNotIn("a1", text, "the non-ascii line was read a second time")


class ClassifyTest(Base):
    def test_a_task_without_a_proof_is_an_alert(self):
        self.write("[task] 3f9a1b2c-4d5e REJECT/VK_SUBSTITUTION proof=false 5ms\n")
        self.assertIn("no proof: 3f9a1b2c-4d5e REJECT/VK_SUBSTITUTION", self.report())

    def test_a_reused_proof_is_a_legitimate_reason(self):
        self.write("[task] a1 REJECT/PROOF_REUSED proof=false 5ms\n")
        text = self.report()
        self.assertNotIn("no proof", text)
        self.assertIn("1 task(s) answered", text)

    def test_a_task_with_a_proof_is_quiet(self):
        self.write("[task] a1 APPROVE/VALID_CONDITION proof=true 5ms\n")
        self.assertNotIn("no proof", self.report())

    def test_a_truncated_task_line_does_not_crash_and_does_not_alert(self):
        self.write("[task] a1 REJECT/EXPIRED_CONDITION\n")
        text = self.report()
        self.assertNotIn("no proof", text)
        self.assertIn("1 task(s) answered", text)

    def test_a_rejected_hmac_is_an_alert(self):
        self.write("[sig] reject bad signature\n")
        self.assertIn("failed HMAC", self.report())

    def test_a_prover_error_is_an_alert(self):
        self.write("[proof] groth16 failed: witness not satisfied\n")
        self.assertIn("prover error: [proof] groth16 failed", self.report())

    def test_a_handler_crash_is_an_alert(self):
        self.write("[fatal] unhandled rejection in handler\n")
        self.assertIn("handler crash", self.report())

    def test_an_unrelated_line_is_ignored(self):
        self.write("[boot] listening on 4795\n")
        self.assertEqual(self.report(), "")

    def test_identical_alerts_are_reported_once(self):
        self.write("[fatal] same crash\n[fatal] same crash\n")
        self.assertEqual(self.report().count("handler crash"), 1)


class ServiceTest(Base):
    def test_an_inactive_service_with_a_live_healthz_is_one_alert(self):
        self.write("[task] a1 APPROVE/VALID_CONDITION proof=true 5ms\n")
        text = self.report(run=lambda cmd: "inactive" if "systemctl" in cmd else '{"ok":true}')
        self.assertIn("service zkagent NOT active", text)
        self.assertNotIn("healthz", text)

    def test_an_inactive_service_with_a_dead_healthz_is_two_alerts(self):
        self.write("[task] a1 APPROVE/VALID_CONDITION proof=true 5ms\n")
        text = self.report(run=lambda cmd: "")
        self.assertIn("service zkagent NOT active", text)
        self.assertIn("local /healthz not answering", text)

    def test_an_active_service_says_nothing_about_the_service(self):
        self.write("[task] a1 APPROVE/VALID_CONDITION proof=true 5ms\n")
        self.assertNotIn("service", self.report())


class ScoreTest(Base):
    def test_a_score_that_has_not_moved_is_quiet(self):
        self.write("[task] a1 APPROVE/VALID_CONDITION proof=true 5ms\n")
        self.report()
        self.assertEqual(self.report(), "")

    def test_a_score_that_moved_is_reported(self):
        self.write("[task] a1 APPROVE/VALID_CONDITION proof=true 5ms\n")
        self.report()
        text = self.report(rows=self.rows(gatekeeper=11, gkCorrect=9))
        self.assertIn("score 11", text)
        self.assertIn("rank #3", text)

    def test_the_first_sight_of_a_score_is_recorded_but_not_announced(self):
        self.write("[task] a1 APPROVE/VALID_CONDITION proof=true 5ms\n")
        text = self.report()
        self.assertNotIn("score 10", text)
        self.assertTrue(os.path.exists(self.score), "the score was never written down")

    def test_an_agent_that_is_not_active_is_an_alert(self):
        self.write("[task] a1 APPROVE/VALID_CONDITION proof=true 5ms\n")
        self.assertIn("agent status = paused", self.report(rows=self.rows(status="paused")))

    def test_an_agent_missing_from_the_board_is_not_an_alert(self):
        self.write("[task] a1 APPROVE/VALID_CONDITION proof=true 5ms\n")
        self.assertNotIn("agent status", self.report(rows=[{"name": "someone else"}]))

    def test_a_row_that_is_not_an_object_is_skipped(self):
        self.write("[task] a1 APPROVE/VALID_CONDITION proof=true 5ms\n")
        self.assertNotIn("agent status", self.report(rows=["junk", 7, None]))

    def test_an_unreachable_leaderboard_is_an_alert(self):
        def boom():
            raise OSError("network down")

        text = watchdog.report(
            log_path=self.log, off_path=self.off, score_path=self.score,
            run=lambda cmd: "active", fetch=boom,
        )
        self.assertIn("leaderboard unreachable: OSError", text)


class OutputTest(Base):
    def test_all_good_prints_nothing(self):
        self.assertEqual(self.report(), "")

    def test_an_alert_gets_the_header_and_bullets(self):
        self.write("[fatal] boom\n")
        lines = self.report().splitlines()
        self.assertEqual(lines[0], "⚠️ zkagent")
        self.assertTrue(lines[1].startswith("• "))

    def test_notes_ride_along_with_alerts(self):
        self.write("[fatal] boom\n[task] a1 APPROVE/VALID_CONDITION proof=true 5ms\n")
        text = self.report()
        self.assertIn("• handler crash", text)
        self.assertIn("· 1 task(s) answered", text)

    def test_notes_alone_are_one_line(self):
        self.write("[task] a1 APPROVE/VALID_CONDITION proof=true 5ms\n")
        text = self.report()
        self.assertTrue(text.startswith("zkagent · "))
        self.assertNotIn("⚠️", text)

    def test_the_module_does_not_run_itself_on_import(self):
        # Everything used to be at module scope, so importing this file ran the
        # whole report against the live log, the live service and the network.
        self.assertTrue(callable(watchdog.report))
        self.assertTrue(callable(watchdog.main))


if __name__ == "__main__":
    unittest.main()
