"""Tests for guard.py — IDENTICAL in every full-tier repo, like guard.py.

Replays every example in this repo's guard-config.json, then the generic
cases every repo's policy must satisfy, then the failure modes (a broken
guard must ASK, never fail open).

Run: python3 -m unittest discover -s .claude/hooks -p 'test_*.py'
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import guard  # noqa: E402

CFG = guard.load_config()


def verdict(tool: str, tool_input: dict, lock: bool = False, branch: str = "feature/x",
            cwd: str = "") -> str:
    event = {"tool_name": tool, "tool_input": tool_input,
             "cwd": os.path.join(guard.ROOT, cwd)}
    return guard.decide(event, CFG, guard.ROOT, lock_present=lock,
                        branch_fn=lambda _cwd: branch)[0]


class ConfigExamples(unittest.TestCase):
    def test_every_example(self):
        self.assertGreater(len(CFG["examples"]), 10, "policy without worked examples is untested")
        for ex in CFG["examples"]:
            with self.subTest(ex=ex):
                got = verdict(ex["tool"], ex["input"], ex.get("lock", False),
                              ex.get("branch", "feature/x"), ex.get("cwd", ""))
                self.assertEqual(got, ex["expect"])


class GenericPolicy(unittest.TestCase):
    """Cases every full-tier repo's guard-config.json must satisfy."""

    def test_secrets(self):
        self.assertEqual(verdict("Read", {"file_path": ".env"}), "deny")
        self.assertEqual(verdict("Read", {"file_path": "sub/dir/.env.local"}), "deny")
        self.assertEqual(verdict("Read", {"file_path": ".env.example"}), "allow")
        self.assertEqual(verdict("Read", {"file_path": "~/.ssh/id_ed25519"}), "deny")
        self.assertEqual(verdict("Read", {"file_path": "~/.ssh/id_ed25519.pub"}), "allow")
        self.assertEqual(verdict("Bash", {"command": "cat .env"}), "deny")
        self.assertEqual(verdict("Bash", {"command": "head -3 < .env"}), "deny")
        self.assertEqual(verdict("Bash", {"command": "grep -rn '.env' src"}), "allow")

    def test_git(self):
        self.assertEqual(verdict("Bash", {"command": "git log --oneline -5"}), "allow")
        self.assertEqual(verdict("Bash", {"command": "git push -u origin feature/x"}), "allow")
        self.assertEqual(verdict("Bash", {"command": "git push origin main"}), "ask")
        self.assertEqual(verdict("Bash", {"command": "git push"}, branch="main"), "ask")
        self.assertEqual(verdict("Bash", {"command": "git -C /tmp push --force"}), "deny")
        self.assertEqual(verdict("Bash", {"command": "git push --all"}), "ask")
        self.assertEqual(verdict("Bash", {"command": "git fetch && git push -fu origin x"}), "deny")

    def test_guard_protects_itself(self):
        for p in (".claude/settings.json", ".claude/hooks/guard.py", ".claude/hooks/guard-config.json"):
            self.assertEqual(verdict("Edit", {"file_path": p}), "ask", p)
        self.assertEqual(verdict("Bash", {"command": "echo '{}' > .claude/settings.json"}), "ask")
        self.assertEqual(verdict("Read", {"file_path": ".claude/hooks/guard.py"}), "allow")

    def test_fix_lock(self):
        t = {"file_path": "tests/test_something.py"}
        self.assertEqual(verdict("Edit", t, lock=False), "allow")
        self.assertEqual(verdict("Edit", t, lock=True), "deny")
        self.assertEqual(verdict("Bash", {"command": "echo x >> tests/test_something.py"}, lock=True), "deny")
        self.assertEqual(verdict("Bash", {"command": "git checkout -- tests/test_something.py"}, lock=True), "deny")
        self.assertEqual(verdict("Bash", {"command": "cat tests/test_something.py"}, lock=True), "allow")
        # engaging is free; releasing is the owner's call
        self.assertEqual(verdict("Bash", {"command": "python3 .claude/hooks/guard.py fix-lock on docs/build-records/x.md"}), "allow")
        self.assertEqual(verdict("Bash", {"command": "python3 .claude/hooks/guard.py fix-lock off"}), "ask")
        self.assertEqual(verdict("Bash", {"command": "rm -f .claude/state/fix-lock"}), "ask")
        self.assertEqual(verdict("Write", {"file_path": ".claude/state/fix-lock"}), "allow")
        self.assertEqual(verdict("Edit", {"file_path": ".claude/state/fix-lock"}), "ask")

    def test_strictest_wins(self):
        self.assertEqual(verdict("Bash", {"command": "git push origin main; cat .env"}), "deny")

    def test_unknown_tools_pass(self):
        self.assertEqual(verdict("WebSearch", {"query": ".env"}), "allow")
        self.assertEqual(verdict("Bash", {"command": ""}), "allow")


class FailureModes(unittest.TestCase):
    def test_bad_config_asks(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write('{"secret_globs": []}')
        try:
            out = guard.run_hook(json.dumps({"tool_name": "Read", "tool_input": {"file_path": "x"}}), f.name)
        finally:
            os.unlink(f.name)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "ask")
        self.assertIn("NOT being checked", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_garbage_stdin_asks(self):
        out = guard.run_hook("not json")
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_allow_is_silent(self):
        self.assertIsNone(guard.run_hook(json.dumps({"tool_name": "Read", "tool_input": {"file_path": "README.md"},
                                                      "cwd": guard.ROOT})))

    def test_real_process_contract(self):
        """End to end through the interpreter, the way Claude Code invokes it."""
        event = {"tool_name": "Read", "tool_input": {"file_path": ".env"}, "cwd": guard.ROOT}
        proc = subprocess.run([sys.executable, guard.__file__], input=json.dumps(event),
                              capture_output=True, text=True, timeout=20)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_fix_lock_cli_roundtrip(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(guard.fix_lock_cli(["on", "docs/build-records/x.md"], root), 0)
            lock = os.path.join(root, guard.LOCK_REL)
            with open(lock) as f:
                self.assertEqual(json.load(f)["record"], "docs/build-records/x.md")
            self.assertEqual(guard.fix_lock_cli(["off"], root), 0)
            self.assertFalse(os.path.exists(lock))
            self.assertEqual(guard.fix_lock_cli(["bogus"], root), 2)


if __name__ == "__main__":
    unittest.main()
