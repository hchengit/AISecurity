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
            cwd: str = "", profile: str = "stable", cfg: dict | None = None) -> str:
    """The guard's decision under a given profile. Tests name the profile they
    describe; the repo's own setting is whatever its owner chose today."""
    event = {"tool_name": tool, "tool_input": tool_input,
             "cwd": os.path.join(guard.ROOT, cwd)}
    return guard.decide(event, dict(cfg or CFG, profile=profile), guard.ROOT, lock_present=lock,
                        branch_fn=lambda _cwd: branch)[0]


class ConfigExamples(unittest.TestCase):
    def test_every_example(self):
        self.assertGreater(len(CFG["examples"]), 10, "policy without worked examples is untested")
        for ex in CFG["examples"]:
            args = (ex["tool"], ex["input"], ex.get("lock", False), ex.get("branch", "feature/x"),
                    ex.get("cwd", ""))
            with self.subTest(ex=ex, profile="stable"):
                self.assertEqual(verdict(*args, profile="stable"), ex["expect"])
            # Development relaxes every ask EXCEPT money moves and secrets, so
            # an example that must keep asking says so explicitly (expect_dev).
            want_dev = ex.get("expect_dev", "allow" if ex["expect"] == "ask" else ex["expect"])
            with self.subTest(ex=ex, profile="development"):
                self.assertEqual(verdict(*args, profile="development"), want_dev)


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
        # The permission settings are protected in every repo.
        self.assertEqual(verdict("Edit", {"file_path": ".claude/settings.json"}), "ask")
        self.assertEqual(verdict("Bash", {"command": "echo '{}' > .claude/settings.json"}), "ask")
        self.assertEqual(verdict("Read", {"file_path": ".claude/hooks/guard.py"}), "allow")
        # The guard's own files follow this repo's policy: protected unless the
        # owner chose otherwise (rikurinode, 2026-09-26).
        for p in (".claude/hooks/guard.py", ".claude/hooks/guard-config.json"):
            want = "ask" if guard.matches(p, CFG["protected_globs"]) else "allow"
            self.assertEqual(verdict("Edit", {"file_path": p}), want, p)

    def test_fix_lock(self):
        t = {"file_path": "tests/test_something.py"}
        self.assertEqual(verdict("Edit", t, lock=False), "allow")
        self.assertEqual(verdict("Edit", t, lock=True), "deny")
        self.assertEqual(verdict("Bash", {"command": "echo x >> tests/test_something.py"}, lock=True), "deny")
        self.assertEqual(verdict("Bash", {"command": "git checkout -- tests/test_something.py"}, lock=True), "deny")
        self.assertEqual(verdict("Bash", {"command": "cat tests/test_something.py"}, lock=True), "allow")
        # engaging is free; releasing is the owner's call unless this repo's
        # owner chose otherwise (fix_lock_release_needs_owner: false)
        self.assertEqual(verdict("Bash", {"command": "python3 .claude/hooks/guard.py fix-lock on docs/build-records/x.md"}), "allow")
        release = "ask" if CFG.get("fix_lock_release_needs_owner", True) else "allow"
        self.assertEqual(verdict("Bash", {"command": "python3 .claude/hooks/guard.py fix-lock off"}), release)
        self.assertEqual(verdict("Bash", {"command": "rm -f .claude/state/fix-lock"}), "ask")
        self.assertEqual(verdict("Write", {"file_path": ".claude/state/fix-lock"}), "allow")
        self.assertEqual(verdict("Edit", {"file_path": ".claude/state/fix-lock"}), "ask")

    def test_strictest_wins(self):
        self.assertEqual(verdict("Bash", {"command": "git push origin main; cat .env"}), "deny")

    def test_unknown_tools_pass(self):
        self.assertEqual(verdict("WebSearch", {"query": ".env"}), "allow")
        self.assertEqual(verdict("Bash", {"command": ""}), "allow")


class Profiles(unittest.TestCase):
    """Owner, 2026-09-27: one switch between 'stable' (every gate asks) and
    'development' (only money moves and secrets ask; denies never change)."""

    SYN = dict(CFG, funds_patterns=[
        {"regex": r"\bmovemoney\b", "reason": "moves money", "always_ask": True},
        {"regex": r"\brestartthing\b", "reason": "restarts a thing"},
    ])

    def v(self, tool, tin, profile, **kw):
        return verdict(tool, tin, profile=profile, cfg=self.SYN, **kw)

    def test_absent_profile_is_stable(self):
        cfg = dict(self.SYN)
        cfg.pop("profile", None)
        event = {"tool_name": "Bash", "tool_input": {"command": "restartthing"}, "cwd": guard.ROOT}
        self.assertEqual(guard.decide(event, cfg, guard.ROOT, lock_present=False)[0], "ask")

    def test_development_keeps_only_money_and_secret_asks(self):
        for profile, other in (("stable", "ask"), ("development", "allow")):
            self.assertEqual(self.v("Bash", {"command": "movemoney now"}, profile), "ask", profile)
            self.assertEqual(self.v("Bash", {"command": "restartthing now"}, profile), other, profile)
            self.assertEqual(self.v("Edit", {"file_path": ".claude/settings.json"}, profile), other, profile)
            self.assertEqual(self.v("Bash", {"command": "git push origin main"}, profile), other, profile)
            self.assertEqual(self.v("Bash", {"command": "rm -f .env"}, profile), "ask", profile)
            self.assertEqual(self.v("Write", {"file_path": ".env"}, profile), "ask", profile)

    def test_development_never_changes_a_deny(self):
        d = "development"
        self.assertEqual(self.v("Read", {"file_path": ".env"}, d), "deny")
        self.assertEqual(self.v("Bash", {"command": "cat .env"}, d), "deny")
        self.assertEqual(self.v("Bash", {"command": "git push --force origin x"}, d), "deny")
        self.assertEqual(self.v("Edit", {"file_path": "tests/test_x.py"}, d, lock=True), "deny")
        self.assertEqual(self.v("Bash", {"command": "restartthing; cat .env"}, d), "deny")

    def test_loosening_asks_tightening_is_free(self):
        loosen = {"command": "python3 .claude/hooks/guard.py profile development"}
        tighten = {"command": "python3 .claude/hooks/guard.py profile stable"}
        self.assertEqual(self.v("Bash", loosen, "stable"), "ask")
        self.assertEqual(self.v("Bash", loosen, "development"), "allow")
        self.assertEqual(self.v("Bash", tighten, "stable"), "allow")
        self.assertEqual(self.v("Bash", tighten, "development"), "allow")

    def _cfg_file(self, root: str, profile: str | None) -> str:
        cfg = json.loads(json.dumps(self.SYN))
        cfg.pop("fix_lock_preflight", None)
        cfg.pop("profile", None)
        path = os.path.join(root, "guard-config.json")
        with open(path, "w") as f:
            text = json.dumps(cfg, indent=2)
            if profile is not None:
                text = text.replace("{\n", '{\n  "profile": "%s",\n' % profile, 1)
            f.write(text + "\n")
        return path

    def test_every_relaxed_ask_is_logged(self):
        with tempfile.TemporaryDirectory() as root:
            path = self._cfg_file(root, "development")
            event = {"tool_name": "Bash", "tool_input": {"command": "restartthing now"}, "cwd": root}
            self.assertIsNone(guard.run_hook(json.dumps(event), path, root))
            with open(os.path.join(root, guard.RELAXED_LOG_REL)) as f:
                rows = [json.loads(line) for line in f]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["what"], "restartthing now")
            self.assertIn("restarts a thing", rows[0]["why"][0])
            self.assertTrue(rows[0]["at"])

    def test_profile_cli_roundtrip(self):
        with tempfile.TemporaryDirectory() as root:
            path = self._cfg_file(root, None)
            with open(path) as f:
                before = json.load(f)
            self.assertEqual(guard.profile_cli([], root, path), 0)
            self.assertEqual(guard.profile_cli(["development"], root, path), 0)
            after = guard.load_config(path)
            self.assertEqual(after["profile"], "development")
            self.assertEqual({k: v for k, v in after.items() if k != "profile"}, before)
            self.assertEqual(guard.profile_cli(["stable"], root, path), 0)
            self.assertEqual(guard.load_config(path)["profile"], "stable")
            self.assertEqual(guard.profile_cli(["loose"], root, path), 2)
            with open(os.path.join(root, guard.PROFILE_LOG_REL)) as f:
                rows = [json.loads(line) for line in f]
            self.assertEqual([(r["from"], r["to"]) for r in rows],
                             [("stable", "development"), ("development", "stable")])

    def test_config_validation(self):
        with tempfile.TemporaryDirectory() as root:
            for bad in ({"profile": "loose"},
                        {"funds_patterns": [{"regex": "x", "reason": "r", "always_ask": "yes"}]}):
                path = self._cfg_file(root, None)
                with open(path) as f:
                    cfg = json.load(f)
                cfg.update(bad)
                with open(path, "w") as f:
                    json.dump(cfg, f)
                with self.assertRaises(ValueError, msg=str(bad)):
                    guard.load_config(path)


class InlineTests(unittest.TestCase):
    """Lesson gate (2026-09-28): Rust keeps most unit tests inside the source
    file (`#[cfg(test)] mod tests`). The fix-lock covered test FILES only, so
    the test proving a fix stayed editable during the fix. A repo names its
    inline-test markers in `inline_tests`: from a file's first marker to its
    end is test code, read-only under the lock like any test file."""

    SRC = ("pub fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n\n"
           "#[cfg(test)]\nmod tests {\n    use super::*;\n\n"
           "    #[test]\n    fn adds() {\n        assert_eq!(add(2, 2), 4);\n    }\n}\n")
    PLAIN = "pub fn sub(a: i32, b: i32) -> i32 {\n    a - b\n}\n"
    QUOTED = ('pub fn f() {}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n'
              '        assert!(true, "holds");\n    }\n}\n')
    # A test-only helper module (cfg(any(test, feature))) above the tests is test
    # code too; cfg(not(test)) marks production code and is not a marker.
    SUPPORT = ('#[cfg(not(test))]\npub fn real() -> u8 {\n    1\n}\n\n'
               '#[cfg(any(test, feature = "test-helpers"))]\npub mod test_support {\n'
               '    pub fn fake() -> u8 {\n        2\n    }\n}\n\n#[cfg(test)]\nmod tests {}\n')
    # A comment directly above the marker (as in two real files).
    DOC = ("pub fn f() {}\n\n/// note ZQX\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n"
           "        assert!(true);\n    }\n}\n")
    # A lone CR planted above the code, and the same two lines inside the tests.
    CR = 'pub fn f() {} // L1\rL2\n\n#[cfg(test)]\nmod tests {\n    const S: &str = "L1\nL2";\n}\n'
    BANNER = "pub fn f() {}\n\n// ====\n// Tests\n// ====\n#[cfg(test)]\nmod tests {}\n"
    CRLF = "pub fn f() {} // Z\r\n#[cfg(test)]\r\nmod tests {\r\n    fn t() { assert!(true); }\r\n}\r\n"
    # The rule rikurinode and AISecurity configure (test_marker_shapes pins it).
    RUST = dict(CFG, inline_tests=[{"glob": "*.rs", "starts_at":
                                    r"^[ \t\f\v\r​-‏⁠﻿]*#\s*\[\s*cfg\s*\(\s*(?:test|(?:any|all)\s*\((?:.*[(,]\s*)?(?<!not\()test(?=\s*[,)]).*\))\s*\)\s*\]",
                                    "guarded_lines": r"cfg(?:_attr)?\s*!?\s*\(.*\btest\b|macro_rules!\s*(?:assert\w*|debug_assert\w*|panic|unreachable|todo)\b",
                                    "attached_above": r"^[ \t\f\v\r​-‏⁠﻿]*(#\s*\[|//|/\*|\*)"}])

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        os.makedirs(os.path.join(self.root, "src", "dir.rs"))
        for name, text in (("lib.rs", self.SRC), ("plain.rs", self.PLAIN), ("notes.md", self.SRC),
                           ("quoted.rs", self.QUOTED), ("support.rs", self.SUPPORT), ("doc.rs", self.DOC),
                           ("cr.rs", self.CR), ("blank.rs", "\n  \n"), ("bom.rs", "\ufeff\n"),
                           ("crlf.rs", self.CRLF), ("banner.rs", self.BANNER),
                           ("lfa.rs", "pub fn f() {} // Z\n#[cfg(test)]\nmod tests {}\n"),
                           ("join.rs", "pub fn f() {}\n// cfg!( Z\ntest) marker\n"),
                           ("allow.rs", "pub fn f() {} // Z\n#[allow(unused)]\n#[cfg(test)]\nmod tests {}\n")):
            with open(os.path.join(self.root, "src", name), "w", newline="") as f:
                f.write(text)
        with open(os.path.join(self.root, "src", "bytes.rs"), "wb") as f:
            f.write(b"pub fn f() {}\n// \xff\n#[cfg(test)]\nmod tests {}\n")

    def tearDown(self):
        self._tmp.cleanup()

    def v(self, tool, tin, lock=True, profile="stable", cfg=None):
        event = {"tool_name": tool, "tool_input": tin, "cwd": self.root}
        return guard.decide(event, dict(cfg or self.RUST, profile=profile), self.root,
                            lock_present=lock, branch_fn=lambda _cwd: "feature/x")[0]

    @staticmethod
    def edit(old, new, path="src/lib.rs", **kw):
        return dict({"file_path": path, "old_string": old, "new_string": new}, **kw)

    def test_edit_inside_the_tests(self):
        change = self.edit("assert_eq!(add(2, 2), 4);", "assert_eq!(add(2, 2), 5);")
        self.assertEqual(self.v("Edit", change), "deny")
        self.assertEqual(self.v("Edit", change, lock=False), "allow")
        self.assertEqual(self.v("Edit", dict(change, file_path=os.path.join(self.root, "src/lib.rs"))), "deny")

    def test_edit_above_the_tests_is_the_fix(self):
        self.assertEqual(self.v("Edit", self.edit("    a + b\n", "    b + a\n")), "allow")
        # New code inserted just above the tests leaves them byte-identical.
        above = self.edit("}\n\n#[cfg(test)]", "}\n\npub fn two() -> i32 {\n    2\n}\n\n#[cfg(test)]")
        self.assertEqual(self.v("Edit", above), "allow")

    def test_edit_reaching_into_the_tests(self):
        self.assertEqual(self.v("Edit", self.edit("#[cfg(test)]\nmod tests {\n    use super::*;",
                                                  "#[cfg(test)]\nmod tests {\n    use super::add;")), "deny")
        self.assertEqual(self.v("Edit", self.edit("add(", "sum(", replace_all=True)), "deny")
        # Removing the marker, or adding a second test module above it, changes the tests too.
        self.assertEqual(self.v("Edit", self.edit("#[cfg(test)]\n", "")), "deny")
        self.assertEqual(self.v("Edit", self.edit("}\n\n#[cfg(test)]",
                                                  "}\n\n#[cfg(test)]\nmod more {}\n\n#[cfg(test)]")), "deny")

    def test_multiedit_applies_every_edit(self):
        fix = {"old_string": "    a + b\n", "new_string": "    b + a\n"}
        cheat = {"old_string": "(add(2, 2), 4)", "new_string": "(add(2, 2), 5)"}
        self.assertEqual(self.v("MultiEdit", {"file_path": "src/lib.rs", "edits": [fix]}), "allow")
        self.assertEqual(self.v("MultiEdit", {"file_path": "src/lib.rs", "edits": [fix, cheat]}), "deny")

    def test_write(self):
        fixed = self.SRC.replace("    a + b\n", "    b + a\n")
        self.assertEqual(self.v("Write", {"file_path": "src/lib.rs", "content": fixed}), "allow")
        self.assertEqual(self.v("Write", {"file_path": "src/lib.rs", "content": fixed.replace(", 4)", ", 5)")}),
                         "deny")
        self.assertEqual(self.v("Write", {"file_path": "src/lib.rs", "content": fixed.split("#[cfg")[0]}),
                         "deny")
        # A new file: production code is free, a new test module is a new test.
        self.assertEqual(self.v("Write", {"file_path": "src/new.rs", "content": self.PLAIN}), "allow")
        self.assertEqual(self.v("Write", {"file_path": "src/new.rs", "content": self.SRC}), "deny")
        # Edit with an empty old_string creates a file, the same as Write.
        self.assertEqual(self.v("Edit", self.edit("", self.PLAIN, path="src/new.rs")), "allow")
        self.assertEqual(self.v("Edit", self.edit("", self.SRC, path="src/new.rs")), "deny")

    def test_adding_tests_to_a_file_without_any(self):
        self.assertEqual(self.v("Edit", self.edit("    a - b\n}\n", "    a - b\n}\n\n#[cfg(test)]\nmod tests {}\n",
                                                  path="src/plain.rs")), "deny")
        self.assertEqual(self.v("Edit", self.edit("    a - b\n", "    b - a\n", path="src/plain.rs")), "allow")

    def test_only_the_configured_files(self):
        # Same text in a file the glob does not name: not Rust, not inline tests.
        self.assertEqual(self.v("Edit", self.edit(", 4)", ", 5)", path="src/notes.md")), "allow")
        # A repo that does not opt in keeps today's behaviour.
        plain = {k: v for k, v in self.RUST.items() if k != "inline_tests"}
        self.assertEqual(self.v("Edit", self.edit(", 4)", ", 5)"), cfg=plain), "allow")

    def test_an_edit_must_match_exactly(self):
        # Verifier, 2026-09-28: the Edit tool also matches loosely (curly quotes
        # straightened, \\uXXXX escapes decoded), so an old_string the guard
        # finds nowhere can still land inside the tests. Under the lock, a
        # covered file takes exact edits only.
        for path, old in (("src/quoted.rs", "assert!(true, \u201cholds\u201d);"),
                          ("src/lib.rs", "assert_eq!(add(2, 2), 4)\\u003b"),
                          ("src/plain.rs", "    a \u2212 b\n")):
            change = self.edit(old, "let _ = 0;", path=path)
            self.assertEqual(self.v("Edit", change), "deny", old)
            self.assertEqual(self.v("Edit", change, lock=False), "allow", old)
        fix = {"old_string": "    a + b\n", "new_string": "    b + a\n"}
        loose = {"old_string": "(add(2, 2), 4)\\u003b", "new_string": "(add(2, 2), 5);"}
        self.assertEqual(self.v("MultiEdit", {"file_path": "src/lib.rs", "edits": [fix, loose]}), "deny")

    def test_marker_shapes(self):
        rx = self.RUST["inline_tests"][0]["starts_at"]
        for line, marker in (("#[cfg(test)]", True), ('#[cfg(any(test, feature = "test-helpers"))]', True),
                             ("    #[cfg(all(test, unix))]", True), ("#[cfg(all(unix, test))]", True),
                             ("#[cfg(not(test))]", False), ('#[cfg(feature = "x")]', False),
                             ('#[cfg(any(feature = "test-helpers", unix))]', False),
                             ("#[cfg(any(not(test), unix))]", False), ("#[cfg_attr(test, derive(Debug))]", False),
                             ("# [cfg(test)]", True), ("#[cfg (test)]", True), ("#[ cfg(test) ]", True),
                             ("\u200e#[cfg(test)]", True), ("#[cfg(not (test))]", False)):
            self.assertEqual(guard.inline_region("fn a() {}\n" + line + "\n", rx) is not None, marker, line)

    def test_the_edit_tool_is_modelled_exactly(self):
        # Verifier round two, 2026-09-28. (A) Deleting text (new_string "")
        # also removes the newline after it, which can pull the marker onto
        # the line above and hide every test below it from the lock.
        self.assertEqual(self.v("Edit", self.edit(" ZQX", "", path="src/doc.rs")), "deny")
        self.assertEqual(self.v("Edit", self.edit("pub fn f() {}", "", path="src/doc.rs")), "allow")
        # (B) The tool splits lines on \\n only; a lone \\r is not a line break.
        self.assertEqual(self.v("Edit", self.edit("L1\nL2", "X", path="src/cr.rs")), "deny")
        # (C) An empty old_string replaces a whitespace-only file entirely.
        self.assertEqual(self.v("Edit", self.edit("", self.SRC, path="src/blank.rs")), "deny")
        self.assertEqual(self.v("Edit", self.edit("", self.PLAIN, path="src/blank.rs")), "allow")
        # (D) Text that is not UTF-8 cannot be checked (rustc rejects it anyway).
        self.assertEqual(self.v("Edit", self.edit("pub fn f() {}", "pub fn g() {}", path="src/bytes.rs")), "deny")
        for path in ("src/doc.rs", "src/cr.rs", "src/blank.rs", "src/bytes.rs"):
            self.assertEqual(self.v("Edit", self.edit("", "x", path=path), lock=False), "allow")

    def test_lines_attached_above_the_marker(self):
        # Verifier round three: `#[cfg(any())]` added above the marker switches
        # the whole module off, even across blank lines. Attributes and
        # comments directly above it belong to it.
        self.assertEqual(self.v("Edit", self.edit("}\n\n#[cfg(test)]", "}\n\n#[cfg(any())]\n#[cfg(test)]")), "deny")
        self.assertEqual(self.v("Edit", self.edit("}\n\n#[cfg(test)]", "}\n#[cfg(any())]\n\n#[cfg(test)]")), "deny")
        self.assertEqual(self.v("Edit", self.edit(" ZQX", " ZQY", path="src/doc.rs")), "deny")
        # Every line of a stacked banner, other attribute spellings, block comments.
        self.assertEqual(self.v("Edit", self.edit("\n\n// ====\n", "\n\n// ==\n", path="src/banner.rs")), "deny")
        for above in ("# [cfg(any())]", "#\t[cfg(any())]", "/* note */", "/** doc */", "\u200e#[cfg(any())]"):
            self.assertEqual(self.v("Edit", self.edit("}\n\n#[cfg(test)]", "}\n\n%s\n#[cfg(test)]" % above)),
                             "deny", above)
        # Code above them, and the blank lines between, are not the tests.
        self.assertEqual(self.v("Edit", self.edit("pub fn f() {}\n", "pub fn f() {}\n\n\n", path="src/doc.rs")), "allow")
        self.assertEqual(self.v("Edit", self.edit("}\n\n#[cfg(test)]",
                                                  "}\n\n#[inline]\npub fn two() -> i32 {\n    2\n}\n\n#[cfg(test)]")), "allow")
        self.assertEqual(self.v("Edit", self.edit("}\n\n#[cfg(test)]", "}\n\n#[cfg(any())]\n#[cfg(test)]"),
                                lock=False), "allow")

    def test_an_empty_old_string_is_judged_both_ways(self):
        # Verifier round three: the tool calls a file blank by JS trim() (U+FEFF
        # included), Python's strip() doesn't. Rather than model that, both
        # outcomes, "replaced" and "unchanged", must leave the tests alone.
        self.assertEqual(self.v("Edit", self.edit("", self.SRC, path="src/bom.rs")), "deny")
        self.assertEqual(self.v("Edit", self.edit("", self.PLAIN, path="src/bom.rs")), "allow")

    def test_crlf_is_folded_as_the_tool_does(self):
        # An LF old_string matches a CRLF file, and a deletion there still
        # takes the line break with it (route A on a CRLF file).
        self.assertEqual(self.v("Edit", self.edit("pub fn f() {} // Z\n", "pub fn g() {} // Z\n", path="src/crlf.rs")),
                         "allow")
        self.assertEqual(self.v("Edit", self.edit(" // Z", "", path="src/crlf.rs")), "deny")
        # The same deletion on an LF file (route A where the line above is code).
        self.assertEqual(self.v("Edit", self.edit(" // Z", "", path="src/lfa.rs")), "deny")
        # ...and where the joined line is an attached attribute, not a guarded
        # line, so only the region check sees the second outcome.
        self.assertEqual(self.v("Edit", self.edit(" // Z", "", path="src/allow.rs")), "deny")

    def test_production_code_may_not_start_behaving_differently_under_test(self):
        # Verifier round five (class G): production code that acts differently
        # only in the test build turns a failing inline test green without
        # touching it (a tests/* integration test is built without cfg(test)
        # and would still fail). Under the lock such lines may not change.
        for old, new in (("    a + b\n", "    if cfg!(test) { return 4; }\n    a + b\n"),
                         ("pub fn add", "#[cfg(not(test))]\npub fn add"),
                         ("pub fn add", "#[cfg(not(not(test)))]\npub fn add"),
                         ("pub fn add", "#[cfg_attr(test, allow(unused))]\npub fn add"),
                         ("pub fn add", "macro_rules! assert_eq { ($($t:tt)*) => {} }\npub fn add")):
            self.assertEqual(self.v("Edit", self.edit(old, new)), "deny", new)
            self.assertEqual(self.v("Edit", self.edit(old, new), lock=False), "allow", new)
        # In a file with no tests at all, and a second copy of an existing line.
        self.assertEqual(self.v("Edit", self.edit("pub fn sub", "#[cfg(not(test))]\npub fn sub", path="src/plain.rs")),
                         "deny")
        self.assertEqual(self.v("Edit", self.edit("pub fn real() -> u8 {", "pub fn real2() -> u8 { 1 }\n#[cfg(not(test))]\n"
                                                  "pub fn real() -> u8 {", path="src/support.rs")), "deny")
        # A deletion that joins two lines into one (the tool's newline swallow).
        self.assertEqual(self.v("Edit", self.edit(" Z", "", path="src/join.rs")), "deny")
        # A rule without guarded_lines guards nothing.
        rule = {k: v for k, v in self.RUST["inline_tests"][0].items() if k != "guarded_lines"}
        self.assertEqual(self.v("Edit", self.edit("pub fn sub", "#[cfg(not(test))]\npub fn sub", path="src/plain.rs"),
                                cfg=dict(self.RUST, inline_tests=[rule])), "allow")
        # Removing one changes what the tests exercise, too.
        self.assertEqual(self.v("Edit", self.edit("#[cfg(not(test))]\n", "", path="src/support.rs")), "deny")
        # Ordinary production edits stay open.
        self.assertEqual(self.v("Edit", self.edit("    a + b\n", "    let s = a + b;\n    s\n")), "allow")

    def test_a_test_edit_is_named_as_one(self):
        # The marker line itself matches guarded_lines; the deny must still say
        # "this changes the tests", the message that tells the session what to do.
        event = {"tool_name": "Edit", "tool_input": self.edit("#[cfg(test)]\nmod tests {", "mod tests {"),
                 "cwd": self.root}
        reasons = guard.decide(event, dict(self.RUST, profile="stable"), self.root, lock_present=True,
                               branch_fn=lambda _cwd: "feature/x")[1]
        self.assertTrue(any("changes the tests inside" in r for r in reasons), reasons)

    def test_test_helper_modules_are_tests(self):
        self.assertEqual(self.v("Edit", self.edit("        2\n", "        3\n", path="src/support.rs")), "deny")
        self.assertEqual(self.v("Edit", self.edit("    1\n", "    9\n", path="src/support.rs")), "allow")

    def test_shell_writes_to_rust_files(self):
        # Verifier, 2026-09-28: a check that reads the file on disk misses `cd`,
        # globs and new files, so a shell write to ANY covered file is refused
        # by name under the lock, the way tests/* is. Edit and Write stay open.
        for cmd in ("sed -i 's/4/5/' src/lib.rs", "rm src/lib.rs", "git checkout -- src/lib.rs",
                    "echo '// x' >> src/lib.rs", "cp /tmp/other.rs src/lib.rs",
                    "sed -i 's/a - b/b - a/' src/plain.rs", "printf '#[cfg(test)] mod t {}' >> src/plain.rs",
                    "cp src/lib.rs src/copy.rs", "cd src && sed -i 's/4/5/' lib.rs",
                    "sed -i 's/4/5/' src/*.rs", "sed -i 's/4/5/' src/lib.r?",
                    "sed -i 's/4/5/' src/{lib,plain}.rs", "sed -i 's/4/5/' src/lib.{rs,bak}"):
            self.assertEqual(self.v("Bash", {"command": cmd}), "deny", cmd)
            self.assertEqual(self.v("Bash", {"command": cmd}, lock=False), "allow", cmd)
        for cmd in ("cat src/lib.rs", "sed -i 's/a/b/' src/notes.md", "cargo test -p x"):
            self.assertEqual(self.v("Bash", {"command": cmd}), "allow", cmd)

    def test_denies_hold_in_development(self):
        self.assertEqual(self.v("Edit", self.edit(", 4)", ", 5)"), profile="development"), "deny")
        self.assertEqual(self.v("Bash", {"command": "rm src/lib.rs"}, profile="development"), "deny")

    def test_a_file_that_cannot_be_read_is_refused(self):
        self.assertEqual(self.v("Edit", self.edit("x", "y", path="src/dir.rs")), "deny")
        self.assertEqual(self.v("Bash", {"command": "rm -r src/dir.rs"}), "deny")
        self.assertEqual(self.v("Bash", {"command": "rm -r src/dir.rs"}, lock=False), "allow")

    def test_config_validation(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "guard-config.json")
            for bad in ("*.rs", [{"glob": "", "starts_at": "x"}], [{"glob": "*.rs"}],
                        [{"glob": "*.rs", "starts_at": "("}], ["*.rs"],
                        [{"glob": "*.rs", "starts_at": "x", "attached_above": 3}],
                        [{"glob": "*.rs", "starts_at": "x", "attached_above": "("}],
                        [{"glob": "*.rs", "starts_at": "x", "guarded_lines": 3}],
                        [{"glob": "*.rs", "starts_at": "x", "guarded_lines": "("}]):
                with open(path, "w") as f:
                    json.dump(dict(CFG, inline_tests=bad), f)
                with self.assertRaises(ValueError, msg=repr(bad)):
                    guard.load_config(path)
            with open(path, "w") as f:
                json.dump(self.RUST, f)
            self.assertEqual(guard.load_config(path)["inline_tests"], self.RUST["inline_tests"])


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
            # An explicit config without preflight: the repo's own may carry
            # checks that only run in the real repo root.
            cfg = self._cfg_with(root, None)
            self.assertEqual(guard.fix_lock_cli(["on", "docs/build-records/x.md"], root, cfg), 0)
            lock = os.path.join(root, guard.LOCK_REL)
            with open(lock) as f:
                self.assertEqual(json.load(f)["record"], "docs/build-records/x.md")
            self.assertEqual(guard.fix_lock_cli(["off"], root), 0)
            self.assertFalse(os.path.exists(lock))
            self.assertEqual(guard.fix_lock_cli(["bogus"], root), 2)

    # Lesson gate (2026-09-25): twice a ratchet breach was found only AFTER the
    # lock was engaged, and fixing the test then cost the owner a release. A
    # repo can name checks that must pass before the lock may engage.
    def _cfg_with(self, root: str, preflight) -> str:
        cfg = json.loads(json.dumps(CFG))
        cfg.pop("fix_lock_preflight", None)
        if preflight is not None:
            cfg["fix_lock_preflight"] = preflight
        path = os.path.join(root, "guard-config.json")
        with open(path, "w") as f:
            json.dump(cfg, f)
        return path

    def test_fix_lock_preflight_failing_refuses(self):
        with tempfile.TemporaryDirectory() as root:
            cfg = self._cfg_with(root, [[sys.executable, "-c", "import sys; sys.exit(3)"]])
            self.assertEqual(guard.fix_lock_cli(["on", "docs/build-records/x.md"], root, cfg), 1)
            self.assertFalse(os.path.exists(os.path.join(root, guard.LOCK_REL)))

    def test_fix_lock_preflight_runs_in_repo_root_and_passes(self):
        with tempfile.TemporaryDirectory() as root:
            marker = os.path.join(root, "ran-here")
            cfg = self._cfg_with(root, [[sys.executable, "-c", "open('ran-here','w').close()"]])
            self.assertEqual(guard.fix_lock_cli(["on", "docs/build-records/x.md"], root, cfg), 0)
            self.assertTrue(os.path.exists(marker))
            self.assertTrue(os.path.exists(os.path.join(root, guard.LOCK_REL)))

    def test_fix_lock_without_preflight_is_unchanged(self):
        with tempfile.TemporaryDirectory() as root:
            cfg = self._cfg_with(root, None)
            self.assertEqual(guard.fix_lock_cli(["on", "docs/build-records/x.md"], root, cfg), 0)

    # Owner, 2026-09-26: a release may be free, but never invisible.
    def test_every_release_is_logged(self):
        with tempfile.TemporaryDirectory() as root:
            cfg = self._cfg_with(root, None)
            guard.fix_lock_cli(["on", "docs/build-records/a.md"], root, cfg)
            guard.fix_lock_cli(["off"], root, cfg)
            guard.fix_lock_cli(["on", "docs/build-records/b.md"], root, cfg)
            guard.fix_lock_cli(["off"], root, cfg)
            with open(os.path.join(root, guard.LOCK_LOG_REL)) as f:
                rows = [json.loads(line) for line in f]
            self.assertEqual([r["record"] for r in rows], ["docs/build-records/a.md", "docs/build-records/b.md"])
            self.assertTrue(all(r.get("engaged_since") and r.get("released_at") for r in rows))

    def test_release_policy_must_be_a_boolean(self):
        with tempfile.TemporaryDirectory() as root:
            path = self._cfg_with(root, None)
            with open(path) as f:
                cfg = json.load(f)
            cfg["fix_lock_release_needs_owner"] = "no"
            with open(path, "w") as f:
                json.dump(cfg, f)
            with self.assertRaises(ValueError):
                guard.load_config(path)

    def test_fix_lock_malformed_preflight_refuses(self):
        with tempfile.TemporaryDirectory() as root:
            cfg = self._cfg_with(root, "node scripts/quality-ratchet.mjs")  # a string, not argv lists
            self.assertNotEqual(guard.fix_lock_cli(["on", "docs/build-records/x.md"], root, cfg), 0)
            self.assertFalse(os.path.exists(os.path.join(root, guard.LOCK_REL)))
            with self.assertRaises(ValueError):
                guard.load_config(cfg)


class PerSessionLock(unittest.TestCase):
    """Owner, 2026-10-03: "Let's not share fix-lock." Two sessions worked one
    repo; one session's lock blocked the other's test writes, `on` overwrote
    another record's lock and `off` released anyone's. A lock now binds only
    the session that took it; the old global file (taken outside any session,
    e.g. from the owner's terminal) still binds everyone."""

    TEST = "tests/test_something.py"

    def _cfg(self, root: str) -> str:
        cfg = json.loads(json.dumps(CFG))
        cfg.pop("fix_lock_preflight", None)
        path = os.path.join(root, "guard-config.json")
        with open(path, "w") as f:
            json.dump(cfg, f)
        return path

    def _edit(self, root: str, session) -> str:
        event = {"tool_name": "Edit", "tool_input": {"file_path": self.TEST}, "cwd": root}
        if session is not None:
            event["session_id"] = session
        return guard.decide(event, dict(CFG, profile="stable"), root, branch_fn=lambda _c: "feature/x")[0]

    def test_a_lock_binds_only_its_own_session(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(guard.fix_lock_cli(["on", "docs/build-records/a.md"], root, self._cfg(root),
                                                session="sess-A"), 0)
            self.assertFalse(os.path.exists(os.path.join(root, guard.LOCK_REL)))
            self.assertEqual(self._edit(root, "sess-A"), "deny")
            self.assertEqual(self._edit(root, "sess-B"), "allow")
            self.assertEqual(self._edit(root, None), "allow")

    def test_the_global_lock_still_binds_everyone(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(guard.fix_lock_cli(["on", "docs/build-records/owner.md"], root, self._cfg(root)), 0)
            for s in ("sess-A", "sess-B", None):
                self.assertEqual(self._edit(root, s), "deny")

    def test_on_never_touches_another_sessions_lock_and_off_only_releases_your_own(self):
        with tempfile.TemporaryDirectory() as root:
            cfg = self._cfg(root)
            guard.fix_lock_cli(["on", "docs/build-records/a.md"], root, cfg, session="sess-A")
            guard.fix_lock_cli(["on", "docs/build-records/b.md"], root, cfg, session="sess-B")
            guard.fix_lock_cli(["on", "docs/build-records/owner.md"], root, cfg)  # global
            with open(guard.session_lock_path(root, "sess-A")) as f:
                self.assertEqual(json.load(f)["record"], "docs/build-records/a.md")
            self.assertEqual(guard.fix_lock_cli(["off"], root, cfg, session="sess-B"), 0)
            self.assertFalse(os.path.exists(guard.session_lock_path(root, "sess-B")))
            self.assertTrue(os.path.exists(guard.session_lock_path(root, "sess-A")))
            self.assertTrue(os.path.exists(os.path.join(root, guard.LOCK_REL)))
            # releasing someone else's is explicit
            self.assertEqual(guard.fix_lock_cli(["off", "--session", "sess-A"], root, cfg, session="sess-B"), 0)
            self.assertFalse(os.path.exists(guard.session_lock_path(root, "sess-A")))
            self.assertEqual(guard.fix_lock_cli(["off", "--global"], root, cfg, session="sess-B"), 0)
            self.assertFalse(os.path.exists(os.path.join(root, guard.LOCK_REL)))

    def test_every_release_is_logged_with_its_session(self):
        with tempfile.TemporaryDirectory() as root:
            cfg = self._cfg(root)
            guard.fix_lock_cli(["on", "docs/build-records/a.md"], root, cfg, session="sess-A")
            guard.fix_lock_cli(["off"], root, cfg, session="sess-A")
            with open(os.path.join(root, guard.LOCK_LOG_REL)) as f:
                entry = json.loads(f.read().splitlines()[-1])
            self.assertEqual((entry["record"], entry["session"]), ("docs/build-records/a.md", "sess-A"))
            self.assertIn("released_at", entry)

    def test_status_lists_every_lock_and_marks_yours(self):
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as root:
            cfg = self._cfg(root)
            guard.fix_lock_cli(["on", "docs/build-records/a.md"], root, cfg, session="sess-A")
            guard.fix_lock_cli(["on", "docs/build-records/b.md"], root, cfg, session="sess-B")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(guard.fix_lock_cli(["status"], root, cfg, session="sess-A"), 0)
            out = buf.getvalue()
            self.assertIn("docs/build-records/a.md", out)
            self.assertIn("docs/build-records/b.md", out)
            self.assertIn("this session", out)

    def test_a_session_id_cannot_escape_the_lock_directory(self):
        with tempfile.TemporaryDirectory() as root:
            path = guard.session_lock_path(root, "../../etc/x")
            self.assertTrue(os.path.realpath(path).startswith(os.path.realpath(
                os.path.join(root, guard.LOCK_DIR_REL)) + os.sep))

    def test_releasing_someone_elses_lock_always_asks(self):
        for cmd in ("python3 .claude/hooks/guard.py fix-lock off --session abc",
                    "python3 .claude/hooks/guard.py fix-lock off --global"):
            for profile in ("stable", "development"):
                self.assertEqual(verdict("Bash", {"command": cmd}, profile=profile), "ask")

    def test_lock_files_are_guarded_like_the_global_one(self):
        self.assertEqual(verdict("Bash", {"command": "rm -f .claude/state/fix-locks/sess-A.json"}), "ask")
        self.assertEqual(verdict("Edit", {"file_path": ".claude/state/fix-locks/sess-A.json"}), "ask")

    # The 2026-10-03 hole: a python3 heredoc with a relative path wrote a test
    # file while a lock was engaged — only shell write targets were checked.
    def test_inline_code_cannot_write_a_locked_test(self):
        writes = [
            "python3 - <<'EOF'\nopen('tests/test_something.py', 'a').write('x')\nEOF",
            "python3 -c \"open('tests/test_something.py','w').write('')\"",
            "node -e \"require('fs').writeFileSync('tests/test_something.py', '')\"",
            "python3 <<EOF\nfrom pathlib import Path\nPath('tests/test_something.py').write_text('')\nEOF",
            # Live drill, 2026-10-03: the interpreter was not the first word.
            "cd . && python3 - <<'EOF'\nopen('tests/test_something.py', 'w').write('// drill')\nEOF",
            "echo go | python3 -c \"open('tests/test_something.py','w')\"",
        ]
        for cmd in writes:
            self.assertEqual({"cmd": cmd, "v": verdict("Bash", {"command": cmd}, lock=True)},
                             {"cmd": cmd, "v": "deny"})
            self.assertEqual(verdict("Bash", {"command": cmd}, lock=False), "allow")

    def test_running_or_reading_a_test_is_still_fine_while_locked(self):
        for cmd in ("python3 -m pytest tests/test_something.py",
                    "node --test tests/test_something.py",
                    "python3 -c \"print(open('tests/test_something.py').read())\""):
            self.assertEqual({"cmd": cmd, "v": verdict("Bash", {"command": cmd}, lock=True)},
                             {"cmd": cmd, "v": "allow"})


if __name__ == "__main__":
    unittest.main()
