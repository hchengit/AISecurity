#!/usr/bin/env python3
"""Claude Code PreToolUse guard: the deterministic gates of BUILD-PROCEDURE.md.

CLAUDE.md, skills, and the procedure are advisory: an AI session can skip
them. This file is not. It is IDENTICAL in every full-tier repo (rikurinode,
Iceman, AISecurity); each repo's policy lives beside it in guard-config.json,
including worked examples that test_guard.py replays.

Decisions: "deny" (refused; the reason goes to the agent), "ask" (the owner
must approve in the UI), or silent allow. Any internal failure (bad config,
crash) returns ASK with the error: the guard never fails open and never
bricks a session.

Bash matching is a tripwire, not a wall: it reads the command segment by
segment (split on ; && || | and newlines, recursing into sh -c), so routine
commands stay silent. A determined `python -c open(...)` gets past it. That
is what code review and the owner are for.

Hook:  stdin = PreToolUse JSON  (wired in .claude/settings.json)
CLI:   guard.py fix-lock on <build-record> | off | status
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import shlex
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
CONFIG_PATH = os.path.join(HERE, "guard-config.json")
LOCK_REL = ".claude/state/fix-lock"

PATH_TOOLS = {"Read": "file_path", "Edit": "file_path", "Write": "file_path",
              "MultiEdit": "file_path", "NotebookEdit": "notebook_path", "Grep": "path"}
READ_TOOLS = {"Read", "Grep"}
READER_VERBS = {"cat", "less", "more", "head", "tail", "grep", "egrep", "fgrep", "rg",
                "awk", "sed", "xxd", "od", "hexdump", "strings", "base64", "nl", "tac",
                "cut", "sort", "uniq", "diff", "cp", "scp", "rsync", "vi", "vim", "nano",
                "source", ".", "bat", "jq", "openssl"}
METADATA_VERBS = {"ls", "stat", "test", "[", "du", "wc", "find", "realpath", "readlink",
                  "dirname", "basename"}
PATTERN_FIRST = {"grep", "egrep", "fgrep", "rg", "awk", "sed", "jq"}
PREFIX_WORDS = {"sudo", "env", "command", "nohup", "time", "nice", "exec"}
WRITE_ALL_ARGS = {"rm", "mv", "tee", "truncate", "touch", "chmod", "chown", "ln",
                  "unlink", "shred", "patch"}
WRITE_LAST_ARG = {"cp", "install", "rsync"}
GIT_PATH_WRITERS = {"checkout", "restore", "rm", "mv", "apply"}
RANK = {"allow": 0, "ask": 1, "deny": 2}
CONFIG_KEYS = {"secret_globs": list, "secret_allow_globs": list, "protected_globs": list,
               "protected_branches": list, "test_globs": list, "funds_patterns": list,
               "examples": list}


# ── config ──────────────────────────────────────────────────────────────────

def load_config(path: str = CONFIG_PATH) -> dict:
    with open(path) as f:
        cfg = json.load(f)
    for key, typ in CONFIG_KEYS.items():
        if not isinstance(cfg.get(key), typ):
            raise ValueError("guard-config.json: '%s' missing or not a %s" % (key, typ.__name__))
    for p in cfg["funds_patterns"]:
        re.compile(p["regex"])
        if not p.get("reason"):
            raise ValueError("guard-config.json: funds pattern without a reason: %r" % p)
    pre = cfg.get("fix_lock_preflight", [])
    if not (isinstance(pre, list) and all(
            isinstance(cmd, list) and cmd and all(isinstance(w, str) and w for w in cmd) for cmd in pre)):
        raise ValueError("guard-config.json: 'fix_lock_preflight' must be a list of argv lists, e.g. "
                         '[["node", "scripts/quality-ratchet.mjs"]]')
    return cfg


# ── path helpers ────────────────────────────────────────────────────────────

def rel_to_root(path: str, cwd: str, root: str) -> str | None:
    """Repo-relative path, or None when the path is outside the repo."""
    path = os.path.expanduser(path)
    absolute = os.path.normpath(path if os.path.isabs(path) else os.path.join(cwd, path))
    rel = os.path.relpath(absolute, root)
    return None if rel == ".." or rel.startswith("../") else rel


def matches(path: str, globs: list) -> bool:
    base = os.path.basename(path)
    for g in globs:
        target = path if "/" in g else base
        if fnmatch.fnmatchcase(target, g):
            return True
    return False


def is_secret(path: str, cfg: dict) -> bool:
    base = os.path.basename(path)
    return matches(base, cfg["secret_globs"]) and not matches(base, cfg["secret_allow_globs"])


# ── bash parsing ────────────────────────────────────────────────────────────

def split_segments(cmd: str) -> list:
    """Split on ; && || | and newlines, outside quotes."""
    segs, cur, quote, i = [], [], None, 0
    while i < len(cmd):
        c = cmd[i]
        if quote:
            if c == quote:
                quote = None
            cur.append(c)
        elif c in "'\"":
            quote = c
            cur.append(c)
        elif c in ";|\n" or cmd.startswith("&&", i):
            segs.append("".join(cur))
            cur = []
            if cmd.startswith("&&", i) or cmd.startswith("||", i):
                i += 1
        else:
            cur.append(c)
        i += 1
    segs.append("".join(cur))
    return [s.strip() for s in segs if s.strip()]


def words_of(seg: str) -> list:
    try:
        return shlex.split(seg, comments=False)
    except ValueError:
        return seg.split()


def verb_and_args(words: list) -> tuple:
    i = 0
    while i < len(words) and (words[i] in PREFIX_WORDS or re.match(r"^\w+=", words[i])):
        i += 1
    if i >= len(words):
        return "", []
    return os.path.basename(words[i]), words[i + 1:]


def file_args(verb: str, args: list) -> list:
    """Words that can name a file: drops the pattern of grep/sed/awk/jq, and
    quoted prose (a commit message mentioning .env is not a read of .env)."""
    if verb in PATTERN_FIRST and "-e" not in args and "-f" not in args:
        positional = [a for a in args if not a.startswith("-")]
        if positional:
            args = list(args)
            args.remove(positional[0])
    out = []
    for w in args:
        if not re.search(r"\s", w):
            out += [p for p in re.split(r"[=<>]", w) if p]
    return out


def redirect_targets(seg: str) -> list:
    return re.findall(r"(?<![0-9&])>{1,2}\|?\s*([^\s;&|<>]+)", seg)


def write_targets(seg: str) -> list:
    """Paths this segment writes, as far as a tripwire can tell."""
    verb, args = verb_and_args(words_of(seg))
    paths = [a for a in args if not a.startswith("-")]
    out = list(redirect_targets(seg))
    if verb in WRITE_ALL_ARGS:
        out += paths
    elif verb in WRITE_LAST_ARG and paths:
        out.append(paths[-1])
    elif verb in ("sed", "perl") and any(a.startswith("-i") or a == "--in-place" for a in args):
        out += paths
    elif verb == "dd":
        out += [a[3:] for a in args if a.startswith("of=")]
    elif verb == "git" and paths and paths[0] in GIT_PATH_WRITERS:
        out += paths[1:]
    return out


def git_push_verdict(args: list, cwd: str, cfg: dict, branch_fn) -> tuple:
    """(decision, reason) for `git <args>`; allow when it is not a push."""
    i, git_cwd = 0, cwd
    while i < len(args) and args[i].startswith("-"):
        if args[i] in ("-C", "-c") and i + 1 < len(args):
            if args[i] == "-C":
                git_cwd = os.path.join(cwd, args[i + 1])
            i += 2
        else:
            i += 1
    if i >= len(args) or args[i] != "push":
        return "allow", ""
    rest = args[i + 1:]
    for a in rest:
        if (a in ("--force", "--mirror", "--delete", "--prune", "--force-if-includes")
                or a.startswith("--force-with-lease")
                or (re.match(r"^-[A-Za-z]+$", a) and ("f" in a or "d" in a))):
            return "deny", "git push %s rewrites or deletes remote history — the owner runs that by hand" % a
    positional = [a for a in rest if not a.startswith("-")]
    refspecs = positional[1:]
    protected = cfg["protected_branches"]
    if "--all" in rest:
        return "ask", "git push --all includes protected branches (%s)" % ", ".join(protected)
    if not refspecs:
        refspecs = ["HEAD"]
    for spec in refspecs:
        if spec.startswith("+"):
            return "deny", "git push %s is a force push (leading +)" % spec
        if spec.startswith(":"):
            return "deny", "git push %s deletes a remote branch" % spec
        dst = spec.split(":", 1)[-1].replace("refs/heads/", "")
        if dst == "HEAD":
            dst = branch_fn(git_cwd)
        if dst in protected:
            return "ask", "git push to protected branch '%s' — owner approves pushes to %s" % (dst, dst)
    return "allow", ""


def current_branch(cwd: str) -> str:
    try:
        return subprocess.run(["git", "-C", cwd, "rev-parse", "--abbrev-ref", "HEAD"],
                              capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


# ── decision ────────────────────────────────────────────────────────────────

def decide(event: dict, cfg: dict, root: str = ROOT, lock_present: bool | None = None,
           branch_fn=current_branch) -> tuple:
    """Return (decision, [reasons]). Pure apart from branch_fn / lock lookup."""
    tool = event.get("tool_name", "")
    tin = event.get("tool_input") or {}
    cwd = event.get("cwd") or root
    if lock_present is None:
        lock_present = os.path.exists(os.path.join(root, LOCK_REL))
    hits = []

    if tool in PATH_TOOLS:
        raw = tin.get(PATH_TOOLS[tool])
        if raw:
            rel = rel_to_root(raw, cwd, root)
            if is_secret(raw, cfg):
                hits.append(("deny" if tool in READ_TOOLS else "ask",
                             "%s is a secret file — its contents must not enter the transcript; "
                             "ask the owner for the one value you need" % raw))
            if rel is not None and tool not in READ_TOOLS:
                if rel == LOCK_REL:
                    if tool != "Write":
                        hits.append(("ask", "editing the fix-lock ends the fix phase — owner approves"))
                elif matches(rel, cfg["protected_globs"]):
                    hits.append(("ask", "%s is protected (constitution / gate) — owner approves every change" % rel))
                if lock_present and matches(rel, cfg["test_globs"]):
                    hits.append(("deny", "fix-lock is engaged: %s is a test/baseline. Fix the code, not the "
                                         "test (release with `guard.py fix-lock off`, owner approves)" % rel))
    elif tool == "Bash":
        hits += bash_hits(tin.get("command", ""), cwd, cfg, root, lock_present, branch_fn)

    if not hits:
        return "allow", []
    worst = max(hits, key=lambda h: RANK[h[0]])[0]
    return worst, [r for d, r in hits if d == worst]


def bash_hits(cmd: str, cwd: str, cfg: dict, root: str, lock_present: bool, branch_fn) -> list:
    hits = []
    for seg in split_segments(cmd):
        words = words_of(seg)
        verb, args = verb_and_args(words)
        if verb in ("sh", "bash", "zsh") and "-c" in args and args.index("-c") + 1 < len(args):
            hits += bash_hits(args[args.index("-c") + 1], cwd, cfg, root, lock_present, branch_fn)
            continue
        secrets = [t for t in file_args(verb, args) + redirect_targets(seg) if is_secret(t, cfg)]
        if secrets and verb not in METADATA_VERBS:
            if verb in READER_VERBS:
                hits.append(("deny", "`%s` would print secret file %s into the transcript" % (verb, secrets[0])))
            else:
                hits.append(("ask", "command touches secret file %s" % secrets[0]))
        if verb == "git":
            d, r = git_push_verdict(args, cwd, cfg, branch_fn)
            if d != "allow":
                hits.append((d, r))
        if "guard.py" in seg and "fix-lock" in words and "off" in words:
            hits.append(("ask", "releasing the fix-lock ends the fix phase — owner approves"))
        for target in write_targets(seg):
            rel = rel_to_root(target, cwd, root)
            if rel is None:
                continue
            if rel == LOCK_REL or matches(rel, cfg["protected_globs"]):
                hits.append(("ask", "command writes protected path %s — owner approves" % rel))
            if lock_present and matches(rel, cfg["test_globs"]):
                hits.append(("deny", "fix-lock is engaged: command writes test/baseline %s. "
                                     "Fix the code, not the test" % rel))
        for p in cfg["funds_patterns"]:
            if re.search(p["regex"], seg):
                hits.append(("ask", p["reason"]))
    return hits


# ── entry points ────────────────────────────────────────────────────────────

def run_hook(stdin_text: str, config_path: str = CONFIG_PATH, root: str = ROOT) -> dict | None:
    """Hook output dict, or None for a silent allow. Never raises."""
    try:
        decision, reasons = decide(json.loads(stdin_text), load_config(config_path), root)
    except Exception as e:  # noqa: BLE001 — a broken guard must be loud, not open
        decision, reasons = "ask", ["guard.py failed (%s: %s) — gates are NOT being checked; "
                                    "fix .claude/hooks before continuing" % (type(e).__name__, e)]
    if decision == "allow":
        return None
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                   "permissionDecision": decision,
                                   "permissionDecisionReason": " | ".join(reasons)}}


def fix_lock_preflight(root: str, config_path: str) -> str | None:
    """Run the repo's pre-lock checks; the reason to refuse, or None to go ahead.

    Lesson gate (2026-09-25): twice a quality-ratchet breach in a new test was
    found only after the lock was engaged, and fixing the test then needed the
    owner's `fix-lock off`. Checks listed in guard-config.json's optional
    `fix_lock_preflight` (argv lists, run from the repo root, no shell) must
    pass before tests become read-only.
    """
    try:
        cfg = load_config(config_path)
    except Exception as e:  # noqa: BLE001 — any config problem refuses, with the reason
        return "cannot read %s: %s" % (config_path, e)
    for argv in cfg.get("fix_lock_preflight", []):
        try:
            proc = subprocess.run(argv, cwd=root, capture_output=True, text=True, timeout=600)
        except (OSError, subprocess.TimeoutExpired) as e:
            return "preflight %s could not run: %s" % (" ".join(argv), e)
        if proc.returncode != 0:
            tail = "\n".join((proc.stdout + proc.stderr).strip().splitlines()[-8:])
            return "preflight %s failed (exit %d):\n%s" % (" ".join(argv), proc.returncode, tail)
    return None


def fix_lock_cli(args: list, root: str = ROOT, config_path: str = CONFIG_PATH) -> int:
    lock = os.path.join(root, LOCK_REL)
    if args[:1] == ["on"] and len(args) == 2:
        refused = fix_lock_preflight(root, config_path)
        if refused:
            print("fix-lock NOT engaged — %s\nNothing was changed. Fix it first, then engage." % refused,
                  file=sys.stderr)
            return 1
        os.makedirs(os.path.dirname(lock), exist_ok=True)
        with open(lock, "w") as f:
            json.dump({"record": args[1], "since": time.strftime("%Y-%m-%dT%H:%M:%S%z")}, f)
        print("fix-lock ENGAGED for %s — test files and baselines are now read-only" % args[1])
        return 0
    if args == ["off"]:
        if os.path.exists(lock):
            os.remove(lock)
        print("fix-lock released")
        return 0
    if args == ["status"]:
        if os.path.exists(lock):
            with open(lock) as f:
                print(f.read())
        else:
            print("fix-lock not engaged")
        return 0
    print("usage: guard.py fix-lock on <build-record> | off | status", file=sys.stderr)
    return 2


def main() -> int:
    if sys.argv[1:2] == ["fix-lock"]:
        return fix_lock_cli(sys.argv[2:])
    out = run_hook(sys.stdin.read())
    if out:
        print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
