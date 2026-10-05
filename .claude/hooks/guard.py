#!/usr/bin/env python3
"""Claude Code PreToolUse guard: the deterministic gates of BUILD-PROCEDURE.md.

CLAUDE.md, skills, and the procedure are advisory: an AI session can skip
them. This file is not. It is IDENTICAL in every full-tier repo (rikurinode,
Iceman, AISecurity, Rikuri-PI); each repo's policy lives beside it in guard-config.json,
including worked examples that test_guard.py replays.

Decisions: "deny" (refused; the reason goes to the agent), "ask" (the owner
must approve in the UI), or silent allow. Any internal failure (bad config,
crash) returns ASK with the error: the guard never fails open and never
bricks a session.

Profiles (owner, 2026-09-27): "stable" (the default) asks at every gate.
"development" asks only before money moves (funds patterns marked
"always_ask") and before touching a secret file; every other ask becomes an
allow, logged to .claude/state/guard-relaxed.log. Denies never change.
Switch with `guard.py profile development|stable`; loosening asks the owner.

The fix-lock makes tests read-only while a defect is being fixed: files
named by `test_globs`, and the tests written INSIDE a source file, named by
the optional `inline_tests` (Rust's `#[cfg(test)]` module: from a file's first
marker to its end, plus the attribute/comment lines directly above the marker
named by `attached_above`). Lines matching the optional `guarded_lines` (e.g.
code that acts differently under `cfg(test)`) may not change anywhere in the
file while locked. An Edit/Write is checked by comparing that region before
and after, and an Edit must match the file exactly (the Edit tool also matches
loosely, which the guard can't follow). A shell write to a file of that type
is refused by name, as a test file's is, since it can't be checked.

A fix-lock belongs to the session that took it (owner, 2026-10-03: "Let's not
share fix-lock"). `fix-lock on` inside a Claude Code session writes
.claude/state/fix-locks/<CLAUDE_CODE_SESSION_ID>.json and binds only that
session (the hook reads `session_id`); taken outside a session (the owner's
terminal) it writes the global .claude/state/fix-lock, which binds every
session. `off` releases only your own; `off --session <id>` / `off --global`
release someone else's and always ask the owner.

Bash matching is a tripwire, not a wall: it reads the command segment by
segment (split on ; && || | and newlines, recursing into sh -c), so routine
commands stay silent. While your lock is held, inline interpreter code
(python/node/... with -c/-e/stdin/heredoc) that writes and names a test path
is refused (the 2026-10-03 heredoc hole); a determined workaround still gets
past it. That is what code review and the owner are for.

Hook:  stdin = PreToolUse JSON  (wired in .claude/settings.json)
CLI:   guard.py fix-lock on <build-record> | off [--session <id> | --global] | status
       guard.py profile [development | stable]
"""
from __future__ import annotations

import fnmatch
import glob
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
# One lock per Claude Code session: <session id>.json (see the header).
LOCK_DIR_REL = ".claude/state/fix-locks"
# Every release, one JSON line: a release may be free (the owner's choice) but never invisible.
LOCK_LOG_REL = ".claude/state/fix-lock.log"
# An ask the development profile let through, one JSON line each: relaxed, never invisible.
RELAXED_LOG_REL = ".claude/state/guard-relaxed.log"
PROFILE_LOG_REL = ".claude/state/profile.log"
PROFILES = ("stable", "development")

EDIT_TOOLS = {"Edit", "MultiEdit", "Write"}
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
PREFIX_WORDS = {"sudo", "env", "command", "nohup", "time", "nice", "exec", "timeout", "stdbuf",
                "busybox", "ionice", "doas", "setsid", "strace", "watch", "chrt", "taskset"}
# Prefix options that take a separate value (`nice -n 5`, `sudo -u x`, `strace -o f`, `exec -a n`).
PREFIX_VALUE_OPTS = {"-n", "-u", "-g", "-s", "-k", "-C", "-p", "-c", "-o", "-e", "-a", "--signal",
                     "--kill-after", "--user", "--group", "--adjustment", "--unset", "--chdir", "--output",
                     "--interval"}
# Shell grouping words that start a segment without being the command.
GROUP_WORDS = {"(", "{", "!", "then", "do", "else", "elif", "if", "while", "until"}
# Commands that run a shell command string: verb -> the option carrying it.
SHELL_STRING = {"sh": "-c", "bash": "-c", "zsh": "-c", "dash": "-c", "su": "-c", "script": "-c"}
# Runners that start another program: `npx tsx …`, `uv run python …`.
RUNNERS = {"npx", "bunx", "pnpx"}
RUN_RUNNERS = {"uv", "poetry", "pipenv", "pdm", "hatch", "rye"}
# Recursive searches (2026-10-04, owner: no searching into .env without
# permission): grep -r & co, rg/ag/ack (recursive by default), find -exec,
# git grep over untracked files.
GREP_VERBS = {"grep", "egrep", "fgrep", "ugrep", "ug", "rgrep"}
TREE_SEARCH_VERBS = {"rg", "ag", "ack"}
# Per verb: options that take a SEPARATE value (GNU grep's -T/--color take
# none — verifier, 2026-10-04: treating -T as valued hid `grep -T x .env`).
SEARCH_VALUE_OPTS = {
    "grep": {"-e", "-f", "-m", "-A", "-B", "-C", "-d", "-D", "--regexp", "--file", "--max-count",
             "--after-context", "--before-context", "--context", "--directories", "--devices",
             "--exclude", "--include", "--exclude-dir", "--exclude-from", "--label", "--binary-files",
             "--group-separator"},
    "rg": {"-e", "-f", "-g", "-t", "-T", "-m", "-A", "-B", "-C", "-j", "-d", "-M", "-r", "-E",
           "--regexp", "--file", "--glob", "--iglob", "--type", "--type-not", "--max-count",
           "--after-context", "--before-context", "--context", "--threads", "--max-depth",
           "--max-columns", "--replace", "--encoding", "--ignore-file", "--type-add", "--pre",
           "--sort", "--sortr", "--path-separator", "--colors", "--color"},
    "ag": {"-G", "-A", "-B", "-C", "-m", "-p", "--file-search-regex", "--ignore", "--ignore-dir",
           "--depth", "--pager", "--path-to-ignore"},
    "ack": {"--ignore-dir", "--ignore-file", "--type", "-A", "-B", "-C", "-m", "--match"},
}
# Values of these options are filename patterns, never file reads.
# (--exclude-from / --ignore-file READ the named file — verifier round 2: rg
# prints a bad ignore-file's lines in its errors — so they are file arguments.)
FILTER_OPTS = {
    "grep": {"--exclude", "--include", "--exclude-dir"},
    "rg": {"-g", "--glob", "--iglob", "-t", "-T", "--type", "--type-not"},
    "ag": {"--ignore", "--ignore-dir", "-G", "--file-search-regex"},
    "ack": {"--ignore-dir", "--type"},
}
# Filter options that EXCLUDE (globs only when written `!…`).
EXCLUDE_OPTS = {"--exclude", "--exclude-dir", "-g", "--glob", "--iglob", "--ignore", "--ignore-dir"}
# find -exec commands that never print file contents.
FIND_SAFE_EXEC = {"ls", "stat", "test", "[", "echo", "printf", "rm", "rmdir", "chmod", "chown", "touch",
                  "mv", "du", "wc", "basename", "dirname", "realpath", "readlink", "file"}
SECRET_WALK_BUDGET = 30000
SECRET_WALK_SKIP = {"node_modules", ".git"}
# Wall-clock cap for all search walks in one decision (the hook has 10 s;
# verifier round 5 reached 9.7 s with many `cd`s). Past it: "may hold secrets".
SEARCH_TIME_BUDGET = 2.5
_DEADLINE = float("inf")
# Wall-clock cap for the new checks as a whole (verifier round 6: nested
# `sh -c` / eval with many `cd`s took 12 s through the hook). Past it the new
# checks answer "ask: too complex to check in time".
CHECK_TIME_BUDGET = 4.0
_DEADLINE_ALL = float("inf")
MAX_FOLDERS = 6  # folders one command may be judged from (cd targets + the start)


class _TooSlow(Exception):
    pass


def _tick() -> None:
    if time.time() > _DEADLINE_ALL:
        raise _TooSlow()
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
        if not isinstance(p.get("always_ask", False), bool):
            raise ValueError("guard-config.json: 'always_ask' must be true or false: %r" % p)
    if cfg.get("profile", "stable") not in PROFILES:
        raise ValueError("guard-config.json: 'profile' must be one of %s" % ", ".join(PROFILES))
    pre = cfg.get("fix_lock_preflight", [])
    if not (isinstance(pre, list) and all(
            isinstance(cmd, list) and cmd and all(isinstance(w, str) and w for w in cmd) for cmd in pre)):
        raise ValueError("guard-config.json: 'fix_lock_preflight' must be a list of argv lists, e.g. "
                         '[["node", "scripts/quality-ratchet.mjs"]]')
    if not isinstance(cfg.get("fix_lock_release_needs_owner", True), bool):
        raise ValueError("guard-config.json: 'fix_lock_release_needs_owner' must be true or false")
    inline = cfg.get("inline_tests", [])
    if not (isinstance(inline, list) and all(
            isinstance(r, dict) and isinstance(r.get("glob"), str) and r["glob"]
            and isinstance(r.get("starts_at"), str) and r["starts_at"] for r in inline)):
        raise ValueError("guard-config.json: 'inline_tests' must be a list of "
                         '{"glob": "*.rs", "starts_at": "<regex>"} objects')
    for r in inline:
        for key in ("attached_above", "guarded_lines"):
            if not isinstance(r.get(key, ""), str):
                raise ValueError("guard-config.json: inline_tests %s must be a regex string" % key)
        for key in ("starts_at", "attached_above", "guarded_lines"):
            try:
                re.compile(r.get(key, ""))
            except re.error as e:
                raise ValueError("guard-config.json: inline_tests %s %r: %s" % (key, r[key], e)) from e
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


# ── inline tests ────────────────────────────────────────────────────────────

def read_text(path: str) -> str:
    """A file's text as the Edit tool sees it: UTF-8, with only \\r\\n folded
    to \\n (a lone \\r is not a line break); "" when the file does not exist
    yet. Anything else, bytes that are not UTF-8 included, raises."""
    try:
        with open(path, encoding="utf-8", newline="") as f:
            return f.read().replace("\r\n", "\n")
    except FileNotFoundError:
        return ""


def inline_region(text: str, starts_at: str, attached_above: str = "") -> str | None:
    """The tests inside `text`: from the first match of `starts_at` to the end,
    widened up over the lines directly above it that match `attached_above`
    (attributes, comments), across blank lines, since an attribute there
    still applies to the tests (`#[cfg(any())]` switches them off)."""
    m = re.search(starts_at, text, re.M)
    if m is None:
        return None
    start = scan = m.start()
    while attached_above and scan > 0 and text[scan - 1] == "\n":
        prev = text.rfind("\n", 0, scan - 1) + 1
        line = text[prev:scan - 1]
        if line.strip() and not re.match(attached_above, line):
            break
        scan = prev
        if line.strip():
            start = prev
    return text[start:]


def texts_after(tool: str, tin: dict, before: str) -> list | None:
    """Every text the file may hold once this Write / Edit / MultiEdit lands,
    modelled on the Edit tool (Claude Code 2.1.221):
    - an old_string with no exact match: None. The tool then tries loose
      matches (curly quotes straightened, \\uXXXX decoded) the guard can't
      follow;
    - a deletion (new_string "") also takes the newline after old_string
      when there is one; both outcomes are returned;
    - an empty old_string replaces a file the tool judges blank and is
      refused otherwise; the guard does not guess which (JS trim() and
      Python strip() disagree on U+FEFF), so both outcomes are returned."""
    if tool == "Write":
        return [tin.get("content") or ""]
    texts = [before]
    for e in (tin.get("edits") or []) if tool == "MultiEdit" else [tin]:
        old, new = e.get("old_string") or "", e.get("new_string") or ""
        nxt = []
        for text in texts:
            if not old:
                nxt += [new, text]
                continue
            if old not in text:
                return None
            olds = [old]
            if not new and not old.endswith("\n") and old + "\n" in text:
                olds.append(old + "\n")
            for o in olds:
                nxt.append(text.replace(o, new) if e.get("replace_all") else text.replace(o, new, 1))
        texts = list(dict.fromkeys(nxt))
    return texts


def guarded(text: str, pattern: str) -> dict:
    """How many times each line matching `pattern` occurs in `text`."""
    counts: dict = {}
    for line in text.split("\n"):
        if pattern and re.search(pattern, line):
            counts[line.strip()] = counts.get(line.strip(), 0) + 1
    return counts


def inline_rules(rel: str, cfg: dict) -> list:
    return [r for r in cfg.get("inline_tests", []) if matches(rel, [r["glob"]])]


def inline_edit_hit(tool: str, tin: dict, rel: str, root: str, cfg: dict) -> tuple | None:
    """Deny when this edit changes the tests inside `rel` (fix-lock engaged)."""
    rules = inline_rules(rel, cfg)
    if not rules:
        return None
    try:
        before = read_text(os.path.join(root, rel))
    except (OSError, UnicodeDecodeError) as e:
        return ("deny", "fix-lock is engaged and %s could not be read to check the tests inside it (%s)"
                % (rel, e), True)
    after = texts_after(tool, tin, before)
    if after is None:
        return ("deny", "fix-lock is engaged: an old_string does not match %s exactly. The Edit tool can "
                        "still apply it by a loose match, which the guard cannot check, so under the "
                        "fix-lock this file takes exact edits only (copy the text as it is)" % rel, True)
    for r in rules:
        region = inline_region(before, r["starts_at"], r.get("attached_above", ""))
        if any(inline_region(a, r["starts_at"], r.get("attached_above", "")) != region for a in after):
            return ("deny", "fix-lock is engaged: this changes the tests inside %s (its first "
                            "inline-test marker to the end of the file, with the attribute and comment "
                            "lines directly above that marker). Fix the code, not the test "
                            "(release with `guard.py fix-lock off`)" % rel, True)
        lines = guarded(before, r.get("guarded_lines", ""))
        if any(guarded(a, r.get("guarded_lines", "")) != lines for a in after):
            return ("deny", "fix-lock is engaged: this adds, removes or changes code in %s that acts "
                            "differently under test (cfg(test) / cfg!(test) / cfg_attr(test, …), or an assert "
                            "macro shadow). While a fix is locked, production code must not behave differently "
                            "in the test build" % rel, True)
    return None


def expand_braces(word: str) -> list:
    """`a/{b,c}.rs` -> [`a/b.rs`, `a/c.rs`], as the shell would (unnested)."""
    m = re.search(r"\{([^{}]*,[^{}]*)\}", word)
    if not m:
        return [word]
    return [x for part in m.group(1).split(",")
            for x in expand_braces(word[:m.start()] + part + word[m.end():])]


def shell_names(target: str, cwd: str) -> list:
    """A write target as written, plus what its braces and globs expand to."""
    out = [target]
    for word in expand_braces(target):
        out.append(word)
        if any(c in word for c in "*?["):
            out += glob.glob(os.path.join(cwd, os.path.expanduser(word)))
    return out


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
        elif c == "\\" and i + 1 < len(cmd) and cmd[i + 1] != "\n":
            cur.append(cmd[i:i + 2])  # an escaped char (`\;`) is not a separator
            i += 2
            continue
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
    """The command a segment really runs, past prefixes and their options
    (`timeout 5`, `nice -n 5`, `env -i`, `stdbuf -oL`, `sudo -u x`, VAR=v)."""
    words, i = list(words), 0
    while i < len(words):
        w = words[i]
        if w in GROUP_WORDS:  # `( cd x && …`, `{ …; }`, `if …; then …`
            i += 1
            continue
        if re.match(r"^\w+=", w):
            i += 1
            continue
        if os.path.basename(w) not in PREFIX_WORDS:
            break
        prefix = os.path.basename(w)
        i += 1
        while i < len(words) and words[i].startswith("-") and words[i] != "-":
            opt = words[i]
            i += 1
            if prefix == "env" and opt in ("-S", "--split-string") and i < len(words):
                words[i:i + 1] = words_of(words[i])  # `env -S 'cmd args'`
                break
            if opt in PREFIX_VALUE_OPTS and i < len(words):
                i += 1
        if prefix == "timeout" and i < len(words) and re.fullmatch(r"[\d.]+[smhd]?", words[i]):
            i += 1
    if i >= len(words):
        return "", []
    verb, rest = os.path.basename(words[i]), words[i + 1:]
    if verb in RUNNERS:  # `npx [-y] tsx -e …`
        while rest and rest[0].startswith("-"):
            rest = rest[1:]
        return verb_and_args(rest) if rest else (verb, [])
    if verb in RUN_RUNNERS and rest[:1] == ["run"]:  # `uv run [--with x] python -c …`
        rest = rest[1:]
        while rest and rest[0].startswith("-"):
            rest = rest[2:] if rest[0] in ("--with", "--python", "-p", "--project", "--directory") else rest[1:]
        return verb_and_args(rest) if rest else (verb, [])
    return verb, rest


def search_family(verb: str) -> str | None:
    if verb in GREP_VERBS:
        return "grep"
    return verb if verb in TREE_SEARCH_VERBS else None


def file_args(verb: str, args: list) -> list:
    """Words that can name a file: drops the pattern of grep/sed/awk/jq, and
    quoted prose (a commit message mentioning .env is not a read of .env)."""
    if verb in PATTERN_FIRST and "-e" not in args and "-f" not in args:
        positional = [a for a in args if not a.startswith("-")]
        if positional:
            args = list(args)
            args.remove(positional[0])
    out, skip = [], False
    fam = search_family(verb)
    filters = FILTER_OPTS.get(fam, set())
    for w in args:
        if skip:  # a search filter's value names a pattern, not a file
            skip = False
            continue
        if w in filters:
            skip = True
            continue
        if w.split("=", 1)[0] in filters:
            continue
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


# ── fix-lock ownership ──────────────────────────────────────────────────────

def session_lock_path(root: str, session: str) -> str:
    """The lock file for one session; the id is reduced to [A-Za-z0-9_-]."""
    safe = re.sub(r"[^A-Za-z0-9_-]", "_", session) or "_"
    return os.path.join(root, LOCK_DIR_REL, safe + ".json")


def lock_held(root: str, session: str | None) -> bool:
    """Is the caller locked? The global lock binds everyone; a session lock its owner."""
    if os.path.exists(os.path.join(root, LOCK_REL)):
        return True
    return bool(session) and os.path.exists(session_lock_path(root, session))


def is_lock_file(rel: str) -> bool:
    return rel == LOCK_REL or rel.startswith(LOCK_DIR_REL + "/")


INTERPRETER = re.compile(r"(?:python[\d.]*|pypy[\d.]*|node(?:js)?|perl[\d.]*|ruby[\d.]*|tsx|ts-node|deno|bun|php|lua)$")
# Interpreters whose write targets we try to resolve; others stay strict.
RESOLVING = re.compile(r"(?:python[\d.]*|pypy[\d.]*|node(?:js)?|tsx|ts-node)$")
INLINE_FLAGS = ("-c", "-e", "-E", "--eval", "-p", "--print")
# `<<TAG` / `<<-TAG` (not the here-string `<<<`); group 1 = "-" when tabs are stripped.
HEREDOC = re.compile(r"(?<!<)<<(?!<)(-?)\s*\\?['\"]?(\w+)['\"]?")
HERESTRING = re.compile(r"<<<\s*(.*)$", re.S)
# Anything that may write. A hint the target scanner cannot account for makes
# the code "unresolved" (strict rule). (`str.replace(` is not a write — only
# os.replace / Path(…).replace; verifier round 2's false positive.)
INLINE_WRITE = re.compile(r"\bopen\s*\(|\.write_text\s*\(|\.write_bytes\s*\(|writeFile|appendFile|writeText|"
                          r"fs\.write|createWriteStream|\bunlink|os\.remove|shutil\.|\brename|os\.replace\s*\(|"
                          r"Path\([^)]*\)\.replace\s*\(|\.touch\s*\(|\bcopyFile|\bcpSync|\bcp\s*\(|\brmSync\b|"
                          r"\brm\s*\(|File\.write|\bDeno\.|\bBun\.write|\bsymlink|\blink\s*\(|\btruncate|"
                          r"\bsysopen|\bspew|\bopenSync|subprocess|os\.system|os\.popen|child_process|"
                          r"\bexecSync|\bexecFileSync|\bspawn|ZipFile|tarfile|sqlite3|shelve|\bdbm\b")
# Calls whose target is an argument (python / node).
WRITE_FUNCS = re.compile(r"(?<![\w.])(?:fs\.|fs\.promises\.|require\(\s*['\"]fs['\"]\s*\)\.|os\.|shutil\.)?"
                         r"(open|openSync|writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|"
                         r"unlinkSync|unlink|remove|copyfile|copy2?|move|rmtree|copyFileSync|copyFile|rmSync|rm)"
                         r"\s*\(")
# Code that is not straight-line: any of these makes the tripwire strict, so
# no binding trick (parameters, loops, match/case, lambdas, ** unpacking…) can
# make a name look like a harmless literal (verifier round 2).
NOT_STRAIGHT = re.compile(r"\b(?:def|lambda|class|match|case|for|while|function|yield|global|nonlocal|del)\b"
                          r"|=>|\*\*|\*\s*\w|\bexec\s*\(|\beval\s*\(|\bglobals\s*\(|\blocals\s*\(|\bvars\s*\(|"
                          r"\bsetattr\s*\(|__dict__|\bFunction\s*\(|\bReflect\.|\bimportlib\b")
RECEIVER_WRITES = re.compile(r"\.(write_text|write_bytes|unlink|open)\s*\(")
# One plain string literal: no f-string, no embedded quote or escape
# (verifier 2026-10-04: `'a' and 'tests/x'` passed as one literal).
STRING_LIT = re.compile(r"""\s*[rRbBuU]{0,2}(?:'([^'\\\n]*)'|"([^"\\\n]*)")\s*""")
DYNAMIC_SCOPE = re.compile(r"\b(?:globals|locals|vars|exec|eval|setattr|Function)\s*\(|__dict__|\bReflect\.")


def _balanced(code: str, i: int) -> int:
    """Index just past the ')' matching the '(' at code[i] (quotes respected)."""
    depth, quote, j = 0, None, i
    while j < len(code):
        c = code[j]
        if quote:
            if c == "\\":
                j += 1
            elif c == quote:
                quote = None
        elif c in "'\"`":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return len(code)


def _top_args(argtext: str) -> list:
    """Split a call's argument text on top-level commas."""
    out, cur, depth, quote, k = [], [], 0, None, 0
    while k < len(argtext):
        c = argtext[k]
        if quote:
            cur.append(c)
            if c == "\\" and k + 1 < len(argtext):
                cur.append(argtext[k + 1])
                k += 1
            elif c == quote:
                quote = None
        elif c in "'\"`":
            quote = c
            cur.append(c)
        elif c in "([{":
            depth += 1
            cur.append(c)
        elif c in ")]}":
            depth -= 1
            cur.append(c)
        elif c == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        k += 1
    if "".join(cur).strip():
        out.append("".join(cur).strip())
    return out


def _literal(expr: str) -> str | None:
    m = STRING_LIT.fullmatch(expr)
    return None if not m else (m.group(1) if m.group(1) is not None else m.group(2))


def _resolve(expr: str, code: str) -> str | None:
    """A write target's path when it is unambiguous: one plain string literal,
    Path('<literal>'), or a bare name whose EVERY binding in the code is a
    simple `name = '<one literal>'`. Any other binding (for-loop, tuple,
    walrus, `as`, augmented, destructuring, globals()/exec…) → None."""
    expr = expr.strip()
    lit = _literal(expr)
    if lit is not None:
        return lit
    m = re.fullmatch(r"(?:pathlib\.)?Path\((.*)\)", expr, re.S)
    if m:
        return _resolve(m.group(1), code)
    if not re.fullmatch(r"[A-Za-z_$][\w$]*", expr) or DYNAMIC_SCOPE.search(code):
        return None
    name = re.escape(expr)
    if re.search(r"\bfor\b[^\n:]*\b" + name + r"\b[^\n:]*\bin\b|\b" + name + r"\s*:=|\bas\s+" + name +
                 r"\b|(?<![\w.])" + name + r"\s*(?:[-+*/%&|^@]|//|\*\*|<<|>>)=|\bdel\s+" + name +
                 r"\b|\b(?:global|nonlocal)\s+[^\n]*\b" + name + r"\b", code):
        return None
    values = []
    for line in code.split("\n"):
        for stmt in line.split(";"):
            mm = re.match(r"\s*(.*?)(?<![=!<>])=(?![=>])(.*)$", stmt)
            if not mm or not re.search(r"(?<![\w.$])" + name + r"(?![\w$])", mm.group(1)):
                continue
            lhs = mm.group(1).strip()
            if not re.fullmatch(r"(?:(?:const|let|var)\s+)?" + name, lhs):
                return None  # tuple / destructuring / attribute target
            values.append(_resolve(mm.group(2).strip().rstrip(";"), ""))
    if values and all(v is not None for v in values) and len(set(values)) == 1:
        return values[0]
    return None


def _call_args(args: list) -> tuple:
    """(positional, keyword) arguments of a call."""
    pos, kw = [], {}
    for a in args:
        m = re.match(r"([A-Za-z_]\w*)\s*=(?!=)(.*)$", a, re.S)
        if m:
            kw[m.group(1)] = m.group(2).strip()
        else:
            pos.append(a)
    return pos, kw


def _write_targets_in(code: str) -> tuple:
    """(resolved target paths, unresolved?, names used as targets) for every
    write call in `code`."""
    targets, unresolved, covered, names = [], False, [], []
    for m in WRITE_FUNCS.finditer(code):
        name, start = m.group(1), m.end() - 1
        end = _balanced(code, start)
        covered.append((m.start(), end))
        pos, kw = _call_args(_top_args(code[start + 1:end - 1]))
        if name in ("open", "openSync"):
            target = kw.get("file", pos[0] if pos else None)
            mode = kw.get("mode", pos[1] if len(pos) > 1 else None)
            if mode is None:
                continue  # open(path) reads
            lit = _literal(mode)
            if lit is not None and not re.search(r"[wax+>]", lit):
                continue  # a read mode
            exprs = [target]
        elif name in ("copyfile", "copy", "copy2", "move", "copyFileSync", "copyFile"):
            exprs = [pos[-1] if pos else kw.get("dst")]
        else:
            exprs = [pos[0] if pos else next(iter(kw.values()), None)]
        for e in exprs:
            if e and re.fullmatch(r"\s*[A-Za-z_$][\w$]*\s*", e):
                names.append(e.strip())
            path = _resolve(e, code) if e else None
            if path is None:
                unresolved = True
            else:
                targets.append(path)
    for m in RECEIVER_WRITES.finditer(code):
        dot = m.start()
        if m.group(1) == "open":
            end = _balanced(code, m.end() - 1)
            mode = _top_args(code[m.end():end - 1])
            lit = _literal(mode[0]) if mode else None
            if not mode or (lit is not None and not re.search(r"[wax+]", lit)):
                covered.append((dot, end))
                continue  # Path(...).open() / .open('r') reads
        covered.append((dot, m.end()))
        j = dot
        if j and code[j - 1] == ")":
            depth, j = 0, j - 1
            while j >= 0:
                depth += code[j] == ")"
                depth -= code[j] == "("
                if depth == 0:
                    break
                j -= 1
        while j > 0 and re.match(r"[\w.$]", code[j - 1]):
            j -= 1
        recv = code[j:dot]
        m_name = re.search(r"([A-Za-z_$][\w$]*)\s*\)?\s*$", recv)
        if m_name:
            names.append(m_name.group(1))
        path = _resolve(recv, code)
        if path is None:
            unresolved = True
        else:
            targets.append(path)
    for h in INLINE_WRITE.finditer(code):
        if not any(a <= h.start() < b for a, b in covered):
            unresolved = True  # a write the scanner cannot read: stay strict
    if re.search(r"\bchdir\s*\(", code):
        unresolved = True  # relative targets no longer mean what they say
    return targets, unresolved, names


def split_heredocs(cmd: str) -> tuple:
    """(shell lines, [(tag, body, shell line index)]). A body ends at a line that
    is exactly its tag — after stripping leading tabs only for `<<-` — as in bash
    (verifier round 2: an indented `  EOF` inside a body hid the rest)."""
    lines, shell, bodies, i = cmd.split("\n"), [], [], 0
    while i < len(lines):
        shell.append(lines[i])
        for dash, tag in HEREDOC.findall(lines[i]):
            body, i = [], i + 1
            while i < len(lines) and (lines[i].lstrip("\t") if dash else lines[i]) != tag:
                body.append(lines[i])
                i += 1
            bodies.append((tag, "\n".join(body), len(shell) - 1))
        i += 1
    return shell, bodies


def shell_string_of(verb: str, args: list) -> str | None:
    """The command string `sh -c '…'`, `su -c '…'`, `script -qc '…'` would run."""
    opt = SHELL_STRING.get(verb)
    if not opt:
        return None
    for k, a in enumerate(args):
        if (a == opt or re.fullmatch(r"-[A-Za-z]*" + opt[1], a)) and k + 1 < len(args):
            return args[k + 1]
    return None


def cd_target(here: str, args: list) -> str:
    """The directory `cd`/`pushd` moves to (options skipped); unchanged when unknowable."""
    rest = [a for a in args if not (a.startswith("-") and a != "-")]
    target = rest[0] if rest else "~"
    if _dynamic(target) or target == "-":
        return here
    return os.path.normpath(os.path.join(here, os.path.expanduser(target)))


def _inline_regions(cmd: str, cwd: str = "") -> list:
    """(interpreter, code, cwd) for the inline code in a command: each
    interpreter's -c/-e argument (bundled flags too: -Bc, -pe), here-string,
    `deno eval`, or heredoc body, read with the shell's own quoting (a ';'
    inside code does not split it); `sh -c`/`su -c`/`script -c`/`eval` text
    and a heredoc fed to a shell are read recursively; `cd`/`pushd` ADD a folder for the
    cwd for later segments. Code that arrives on stdin (a pipe, `<(…)`) gets
    the WHOLE command, strictly."""
    shell, bodies = split_heredocs(cmd)
    regions, heres = [], [cwd]
    for seg in split_segments("\n".join(shell)):
        _tick()
        words = words_of(seg)
        verb, args = verb_and_args(words)
        seg_bodies = []
        for _dash, tag in HEREDOC.findall(seg):
            k = next((n for n, (t, _b, _l) in enumerate(bodies) if t == tag), None)
            if k is not None:
                seg_bodies.append(bodies.pop(k)[1])
        if verb in ("cd", "pushd"):
            nxt = cd_target(heres[-1], args)  # ADDS a folder: the cd may not take effect
            heres = heres + [nxt] if nxt not in heres and len(heres) < MAX_FOLDERS else heres
            continue
        sub = shell_string_of(verb, args)
        if sub is not None:
            regions += [r for h in heres for r in _inline_regions(sub, h)]
            continue
        if verb in ("sh", "bash", "zsh", "dash") and seg_bodies:
            for body in seg_bodies:
                regions += [r for h in heres for r in _inline_regions(body, h)]
            continue
        if verb == "eval":
            regions += [r for h in heres for r in _inline_regions(" ".join(args), h)]
            continue
        if not INTERPRETER.fullmatch(verb):
            continue
        found = list(seg_bodies)
        k = 0
        while k < len(args):
            a = args[k]
            if a in INLINE_FLAGS or re.fullmatch(r"-[A-Za-z]*[ceEp]", a):
                if k + 1 < len(args):
                    found.append(args[k + 1])
                k += 2
                continue
            k += 1
        if verb in ("deno", "bun") and args[:1] == ["eval"] and len(args) > 1:
            found.append(args[1])  # `deno eval "<code>"`
        hs = HERESTRING.search(seg)
        if hs:
            w = words_of(hs.group(1))
            if w:
                found.append(w[0])
        program = found or any(a == "-m" for a in args) or any(
            not a.startswith("-") and not a.startswith("<(") for a in args)
        if (not program or "<(" in seg
                or (args and args[-1] == "-" and not seg_bodies and not hs)):
            found.append(cmd)  # code arrives on stdin: read the whole command, strictly
        regions += [(verb, c, h) for c in found for h in heres]
    return regions


def _strip_strings(code: str) -> str:
    """The code with ordinary '…' / "…" / triple-quoted string CONTENTS removed
    (each becomes ""). Backticks are NOT strings here — they stay, so a template
    literal or a backtick in a comment keeps the code strict (verifier round 3:
    a multi-line backtick match hid a `def`)."""
    out, i, n = [], 0, len(code)
    while i < n:
        c = code[i]
        if c in "'\"":
            triple = code[i:i + 3] in ("'''", '"""')
            q = code[i:i + 3] if triple else c
            j = i + len(q)
            while j < n and not code.startswith(q, j):
                if code[j] == "\\":
                    j += 1
                elif code[j] == "\n" and not triple:
                    break  # unterminated single-line string ends at the line
                j += 1
            out.append('""')
            i = j + len(q) if j < n and code.startswith(q, j) else j
            continue
        out.append(c)
        i += 1
    return "".join(out)


SAFE_MODULES = {"re", "json", "pathlib", "textwrap", "datetime"}
SAFE_CALLS = {
    # control words that take parentheses
    "if", "elif", "while", "not", "and", "or", "in", "return", "assert", "with", "else", "print",
    # reading / writing the resolved target (judged by target resolution)
    "open", "read", "write", "close", "readlines", "readline", "writelines", "read_text", "write_text",
    "Path", "exists", "is_file", "isfile", "readFileSync", "writeFileSync", "appendFileSync", "existsSync",
    "require",
    # strings, collections, re, json
    "replace", "replaceAll", "strip", "rstrip", "lstrip", "split", "rsplit", "splitlines", "join", "format",
    "partition", "rpartition", "startswith", "endswith", "find", "rfind", "index", "count", "lower", "upper",
    "title", "capitalize", "casefold", "zfill", "ljust", "rjust", "center", "encode", "decode", "len", "str",
    "int", "float", "bool", "sorted", "list", "dict", "set", "tuple", "min", "max", "sum", "any", "all",
    "range", "append", "extend", "insert", "pop", "items", "keys", "values", "get", "update", "sub", "subn",
    "search", "findall", "compile", "escape", "fullmatch", "group", "groups", "loads", "dumps", "load",
    "dump", "dedent", "indent", "now", "today", "isoformat", "strftime", "includes", "indexOf", "slice",
    "substring", "toString", "trim", "trimEnd", "trimStart", "parse", "stringify", "log", "padStart",
    "padEnd", "concat", "repeat", "repr",
}


def _lenient_ok(code: str, targets_named: list) -> bool:
    """May the tripwire trust resolved targets? Only for plain straight-line
    code: outside string literals it is ASCII with no backtick and no \\u / \\x
    escape (no NFKC or escaped identifiers), has no NOT_STRAIGHT construct, does
    not reach a name through an object (`.p`, globalThis, sys.modules…), and
    every assignment to a target name is its own statement (`x = p = …` is not)."""
    bare = _strip_strings(code)
    if not bare.isascii() or "`" in bare or re.search(r"\\[uUxN]", bare) or NOT_STRAIGHT.search(bare):
        return False
    if re.search(r"\b(?:globalThis|global|window|self|sys\.modules|builtins|__builtins__|__import__|"
                 r"module\.exports|exports)\b", bare):
        return False
    # Allowlist (verifier round 4: getattr / rmtree / mkdir / chmod / urlretrieve
    # / an import rebinding a name all rode along with a harmless .md write):
    # every call is a known-harmless one, every import is a known-harmless module.
    if any(n not in SAFE_CALLS for n in re.findall(r"([A-Za-z_$][\w$]*)\s*\(", bare)):
        return False
    # No aliasing (verifier round 5: `read = open; read('tests/x','w')`): no
    # writer named without being called, and no rebinding of a safe/writer name.
    code_lines = [ln for ln in bare.split("\n") if not ln.strip().startswith(("import ", "from "))]
    plain = "\n".join(code_lines)
    if re.search(r"\b(?:open|write_text|write_bytes|writeFileSync|appendFileSync|writeFile|appendFile|"
                 r"Path|require)\b(?!\s*\()", plain):
        return False
    for stmt in re.split(r"[;\n]", plain):
        m = re.match(r"\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=(?![=>])", stmt)
        if m and m.group(1) in SAFE_CALLS:
            return False
    for line in bare.split("\n"):
        st = line.strip()
        m = re.fullmatch(r"from\s+([\w.]+)\s+import\s+(.+)", st)
        if m:  # `from pathlib import Path` yes; `from helpers import p` (rebinds p) no
            names = [x.strip() for x in m.group(2).strip("()").split(",")]
            if m.group(1) not in SAFE_MODULES or " as " in st or set(names) & set(targets_named):
                return False
        elif st.startswith("from "):
            return False
        elif st.startswith("import ") and (" as " in st or any(
                x.strip() not in SAFE_MODULES for x in st[7:].split(","))):
            return False
    if any(m not in ("fs", "path", "node:fs", "node:path")
           for m in re.findall(r"require\(\s*['\"]([^'\"]+)['\"]\s*\)", code)):
        return False
    for name in targets_named:
        nm = re.escape(name)
        if re.search(r"\.\s*" + nm + r"\b", bare):
            return False
        for stmt in re.split(r"[;\n]", bare):
            if re.search(r"(?<![\w$])" + nm + r"\s*=(?![=>])", stmt) and not re.fullmatch(
                    r"\s*(?:(?:const|let|var)\s+)?" + nm + r"\s*=(?![=>])\s*\"\"\s*", stmt):
                return False
    return True


def _test_dir_names(cfg: dict) -> set:
    """Directory names that hold tests in this repo's test_globs (tests, __tests__, fixtures…)."""
    names = set()
    for g in cfg["test_globs"]:
        parts = g.split("/")
        # only single-name folder globs: `tests/*`, `*/fixtures/*` — a path glob
        # like `docs/graded-tapes/*` is NOT "every docs folder" (Iceman)
        if len(parts) == 2 and parts[1] == "*":
            name = parts[0]
        elif len(parts) == 3 and parts[0] == "*" and parts[2] == "*":
            name = parts[1]
        else:
            continue
        if name and not any(c in name for c in "*?["):
            names.add(name)
    return names


def inline_code_test_writes(cmd: str, cwd: str, cfg: dict, root: str) -> list:
    """Test paths written by inline interpreter code (python3 - <<EOF, node -e …).

    The 2026-10-03 hole: a python3 heredoc with a relative path wrote a test
    file while a lock was engaged — write_targets() only sees shell syntax.
    2026-10-04 (owner: "fix false positive"): for python/node the tripwire looks
    at what the code WRITES. When every write target resolves (a plain
    literal, Path(literal), or a name bound only to one literal), only those
    targets count — code writing a record that merely mentions a test passes.
    Otherwise (unresolved target, a write the scanner cannot read, or another
    interpreter) it is strict: every test path in the code counts, and so does
    a test DIRECTORY name (paths built from pieces: f'{d}/x', join('tests',…))."""
    found, test_dirs = [], _test_dir_names(cfg)
    for interp, code, here in _inline_regions(cmd, cwd):
        if not INLINE_WRITE.search(code):
            continue
        targets, unresolved, names = _write_targets_in(code)
        # Lenient only for straight-line python/node code (string contents
        # don't count: a record's text may say "for" or "case").
        strict = unresolved or not RESOLVING.fullmatch(interp) or not _lenient_ok(code, names)
        candidates = re.findall(r"[\w@./+-]+", code) if strict else targets
        for tok in candidates:
            if "/" not in tok and "." not in tok and not (strict and tok in test_dirs):
                continue
            rel = rel_to_root(tok, here, root)
            hit = rel and (matches(rel, cfg["test_globs"])
                           or (strict and any(p in test_dirs for p in rel.split("/"))))
            if hit and rel not in found:
                found.append(rel)
    return found


GREP_LONG = {"--recursive", "--dereference-recursive", "--directories", "--devices", "--exclude", "--exclude-dir",
             "--exclude-from", "--include", "--regexp", "--file", "--max-count", "--after-context",
             "--before-context", "--context", "--label", "--binary-files", "--group-separator", "--color",
             "--colour", "--line-number", "--files-with-matches", "--files-without-match", "--count",
             "--ignore-case", "--invert-match", "--word-regexp", "--line-regexp", "--null", "--null-data",
             "--only-matching", "--quiet", "--silent", "--no-messages", "--byte-offset", "--with-filename",
             "--no-filename", "--line-buffered", "--text", "--initial-tab", "--extended-regexp",
             "--fixed-strings", "--basic-regexp", "--perl-regexp", "--no-ignore-case"}
GREP_SHORT_VALUED = set("efmABCdD")


def _long_opt(name: str, known: set) -> str | None:
    """GNU-style: an exact long option, or the one it uniquely abbreviates."""
    if name in known:
        return name
    hits = [k for k in known if k.startswith(name)]
    return hits[0] if len(hits) == 1 else None


def _grep_spec(verb: str, args: list) -> dict | None:
    recursive, follow = verb == "rgrep", False
    filters, exc_dirs, positional, pattern_given = [], [], [], False
    valued = SEARCH_VALUE_OPTS["grep"]
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            positional += args[i + 1:]
            break
        if a.startswith("--"):
            raw, eq, value = a.partition("=")
            name = _long_opt(raw, GREP_LONG) or raw
            if not eq and name in valued and i + 1 < len(args):
                value, i = args[i + 1], i + 1
            if name in ("--recursive",):
                recursive = True
            elif name == "--dereference-recursive":
                recursive = follow = True
            elif name == "--directories" and value and "recurse".startswith(value):
                recursive = True
            elif name == "--exclude":
                filters.append(("exclude", value, False))
            elif name == "--include":
                filters.append(("include", value, False))
            elif name == "--exclude-dir":
                exc_dirs.append(value)
            elif name in ("--regexp", "--file"):
                pattern_given = True
        elif a.startswith("-") and len(a) > 1:
            k = 1
            while k < len(a):
                c = a[k]
                if c in GREP_SHORT_VALUED:
                    value = a[k + 1:]
                    if not value and i + 1 < len(args):
                        value, i = args[i + 1], i + 1
                    if c == "d" and value and "recurse".startswith(value):
                        recursive = True
                    if c in "ef":
                        pattern_given = True
                    break
                if c == "r":
                    recursive = True
                elif c == "R":
                    recursive = follow = True
                k += 1
        else:
            positional.append(a)
        i += 1
    paths = positional if pattern_given else positional[1:]
    if not recursive:
        # Not recursive, but a directory argument still gets read by some grep
        # wrappers (Claude Code's grep runs ugrep with --hidden); checked against
        # the event's cwd in secret_in_tree.
        return {"dir_args_only": paths} if paths else None
    return {"roots": paths or ["."], "filters": filters, "policy": "grep", "exc_dirs": exc_dirs,
            "skip_hidden": False, "follow": follow}


def _tree_spec(verb: str, args: list) -> dict | None:
    valued = SEARCH_VALUE_OPTS[verb]
    filters, exc_dirs, positional, pattern_given = [], [], [], False
    hidden, follow, u_count, files_only = False, False, 0, False
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            positional += args[i + 1:]
            break
        raw, eq, value = a.partition("=")
        if a.startswith("--") and eq:
            name = raw
        elif a in valued and i + 1 < len(args):
            name, value, i = a, args[i + 1], i + 1
        else:
            name, value = a, None
        if value is None and re.fullmatch(r"-[A-Za-z.]{2,}", a):  # a bundle: -nuu, -n., -iu, -eX
            for k, c in enumerate(a[1:], 1):
                if "-" + c in valued:
                    name, value = "-" + c, a[k + 1:] or (args[i + 1] if i + 1 < len(args) else "")
                    if not a[k + 1:]:
                        i += 1
                    break
                u_count += c == "u"
                hidden = hidden or c == "."
                follow = follow or c == "L"
        if value is not None:
            if name in ("-g", "--glob", "--iglob"):
                ci = name == "--iglob"
                neg, g = value.startswith("!"), value.lstrip("!")
                if any(t in g for t in ("/", "**", "{")):
                    # a path / ** / brace glob can't be judged on a name: an
                    # include counts as "may match anything", an exclude is ignored
                    if not neg:
                        filters.append(("include", "*", False))
                else:
                    filters.append(("exclude", g, ci) if neg else ("include", g, ci))
            elif name == "--ignore":
                filters.append(("exclude", value, False))
            elif name == "--ignore-dir":
                exc_dirs.append(value)
            elif name in ("-e", "--regexp", "-f", "--file", "--match"):
                pattern_given = True
        elif a in ("--hidden", "-.", "--unrestricted"):
            hidden = True
            u_count += a == "--unrestricted"
        elif a in ("-L", "--follow") or (verb == "ag" and a == "-f"):
            follow = True
        elif a == "--files":
            files_only = True
        elif re.fullmatch(r"-u+", a):
            u_count += len(a) - 1
        elif not a.startswith("-"):
            positional.append(a)
        i += 1
    if files_only and verb == "rg":
        return None  # `rg --files` lists names, reads no contents
    if verb in ("rg", "ag") and (u_count >= (2 if verb == "rg" else 1)):
        hidden = True
    paths = positional if pattern_given else positional[1:]
    return {"roots": paths or ["."], "filters": filters, "policy": "rg", "exc_dirs": exc_dirs,
            "skip_hidden": verb in ("rg", "ag") and not hidden, "follow": follow}


def _find_spec(args: list) -> dict | None:
    i, follow = 0, False
    while i < len(args) and (args[i] in ("-L", "-H", "-P") or re.fullmatch(r"-O\d", args[i]) or args[i] == "-D"):
        follow = follow or args[i] == "-L"
        i += 2 if args[i] == "-D" else 1
    roots = []
    while i < len(args) and not args[i].startswith(("-", "(", "!", ")")):
        roots.append(args[i])
        i += 1
    expr = args[i:]
    reads, deep = False, False
    for k, a in enumerate(expr):
        if a in ("-exec", "-execdir", "-ok", "-okdir") and k + 1 < len(expr):
            sub, subargs = verb_and_args(expr[k + 1:])
            if sub and sub not in FIND_SAFE_EXEC:
                reads = True
                inner = recursive_search(sub, subargs) if sub != "find" else None
                deep = deep or bool(inner and "roots" in inner)
    if not reads:
        return None
    filters = []
    if not deep and not any(a in ("-o", "-or", "-prune", ",") for a in expr):
        neg = False
        for k, a in enumerate(expr):
            if a in ("!", "-not"):
                neg = True
                continue
            if a in ("-name", "-iname") and k + 1 < len(expr):
                filters.append(("exclude" if neg else "include", expr[k + 1], a == "-iname"))
            neg = False
    return {"roots": roots or ["."], "filters": filters, "policy": "rg", "exc_dirs": [],
            "skip_hidden": False, "follow": follow}


def recursive_search(verb: str, args: list) -> dict | None:
    """How a command reads every file under a directory — roots, ordered
    include/exclude filters, excluded dirs, hidden-file and symlink handling —
    or None when it reads no tree. 2026-10-04 (owner: no searching into .env
    without permission; verifier round 1 for the bypass list)."""
    if verb == "find":
        return _find_spec(args)
    if verb == "git":
        i, base = 0, ""
        while i < len(args) and args[i].startswith("-"):
            if args[i] in ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path") and i + 1 < len(args):
                if args[i] == "-C":
                    base = os.path.join(base, args[i + 1])
                i += 2
            else:
                i += 1
        sub = args[i:]
        if sub[:1] == ["grep"] and any(a in ("--untracked", "--no-index", "--no-exclude-standard") for a in sub):
            rest = [a for a in sub[1:] if not a.startswith("-")]
            roots = [os.path.join(base, r) for r in rest[1:]] or [base or "."]
            return {"roots": roots, "filters": [], "policy": "grep", "exc_dirs": [],
                    "skip_hidden": False, "follow": False}
        return None  # plain git grep: tracked files only (already published)
    fam = search_family(verb)
    if fam == "grep":
        return _grep_spec(verb, args)
    if fam:
        return _tree_spec(verb, args)
    return None


def _dynamic(path: str) -> bool:
    return "$" in path or "`" in path


def _last_match(name: str, filters: list) -> str | None:
    last = None
    for kind, g, ci in filters:
        n, gg = (name.lower(), g.lower()) if ci else (name, g)
        if fnmatch.fnmatchcase(n, gg) or fnmatch.fnmatchcase(n, gg.rstrip("/")):
            last = kind
    return last


def _included(name: str, filters: list, policy: str) -> bool:
    """grep: the last matching --include/--exclude wins; with none matching, a
    file is read unless the first such option is --include. rg/find: the last
    matching glob wins; with none matching, a file is read unless any include
    glob was given."""
    last = _last_match(name, filters)
    if last:
        return last == "include"
    if policy == "grep":
        return not (filters and filters[0][0] == "include")
    return not any(kind == "include" for kind, _, _ in filters)


def secret_in_tree(spec: dict, cwd: str, cfg: dict) -> str | None:
    """An example secret file the search would read, or a reason it might
    (a tree too big to check, a path the guard cannot see). None = safe."""
    if "dir_args_only" in spec:
        roots = [p for p in spec["dir_args_only"] if os.path.isdir(os.path.join(cwd, os.path.expanduser(p)))]
        if not roots:
            return None
        spec = {"roots": roots, "filters": [], "policy": "grep", "exc_dirs": [], "skip_hidden": False,
                "follow": False}
    seen = 0
    filters, policy, skip_hidden = spec["filters"], spec["policy"], spec["skip_hidden"]

    def readable(path: str) -> bool:
        names = [os.path.basename(path)]
        if os.path.islink(path):
            names.append(os.path.basename(os.path.realpath(path)))
        if skip_hidden and names[0].startswith("."):
            return False
        return _included(names[0], filters, policy) and any(is_secret(n, cfg) for n in names)

    roots = []
    for r in spec["roots"]:
        roots += [cwd if x == "~+" else x for x in expand_braces(r)]
    for r in roots:
        if _dynamic(r):
            return "(the path `%s` is built at run time — the guard cannot see what it reads)" % r
        top = os.path.normpath(os.path.join(cwd, os.path.expanduser(r)))
        tops = glob.glob(top) if any(c in r for c in "*?[") else [top]
        for t in tops:
            if not os.path.exists(t):
                continue  # a literal path that does not exist reads nothing
            if os.path.isfile(t):
                if readable(t):
                    return t
                continue
            for d, dirs, files in os.walk(t, followlinks=True):
                if time.time() > _DEADLINE:
                    return "(too slow to check within the hook's time — %s)" % r
                dirs[:] = [x for x in dirs if x not in SECRET_WALK_SKIP
                           and not (skip_hidden and x.startswith("."))
                           and not any(fnmatch.fnmatchcase(x, g) for g in spec["exc_dirs"])
                           and not (policy == "rg" and _last_match(x, filters) == "exclude")]
                seen += len(files) + len(dirs)
                if seen > SECRET_WALK_BUDGET:
                    return "(over %d files under %s — too many to check)" % (SECRET_WALK_BUDGET, r)
                for f in files:
                    if readable(os.path.join(d, f)):
                        return os.path.join(d, f)
    return None


# ── decision ────────────────────────────────────────────────────────────────

RANK = {"allow": 0, "ask": 1, "deny": 2}
_BASE = None


def base_decide(event: dict, cfg: dict, root: str = ROOT, lock_present: bool | None = None,
                branch_fn=current_branch, relaxed: list | None = None) -> tuple:
    """The previous guard's decision. guard_base.py is a byte-for-byte copy of
    the last committed guard.py, run unchanged, so nothing it caught can be lost
    (verifier rounds 1–5 kept finding checks a rewrite had dropped)."""
    return _base_module().decide(event, cfg, root, lock_present=lock_present, branch_fn=branch_fn,
                                 relaxed=relaxed)


def _base_module():
    """guard_base.py, loaded once from beside this file."""
    global _BASE
    if _BASE is None:
        import importlib.util
        spec = importlib.util.spec_from_file_location("guard_base", os.path.join(HERE, "guard_base.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _BASE = mod
    return _BASE


def _filter_values(cmd: str) -> set:
    """Words that are the VALUE of a search filter option (`--exclude=*.env`, `-g '!.env'`)."""
    out = set()
    for seg in split_segments(cmd):
        verb, args = verb_and_args(words_of(seg))
        filt = FILTER_OPTS.get(search_family(verb), set())
        for k, a in enumerate(args):
            name, eq, val = a.partition("=")
            # only EXCLUDING filters: an --include / positive -g value names
            # exactly the file being read (verifier round 6)
            if eq and name in filt and name in EXCLUDE_OPTS and (
                    name not in ("-g", "--glob", "--iglob") or val.startswith("!")):
                out.add(val)
            elif a in filt and a in EXCLUDE_OPTS and k + 1 < len(args) and (
                    a not in ("-g", "--glob", "--iglob") or args[k + 1].startswith("!")):
                out.add(args[k + 1])
    return out


def _inline_all_lenient(cmd: str, cwd: str, cfg: dict, root: str) -> bool:
    """True only when every inline region is provably harmless: python/node,
    straight-line allowlisted code (`_lenient_ok`), every write target resolved
    and not a test — and no test path appears anywhere outside that code (an
    argument such as `python3 - tests/x.py`)."""
    # Only a command that is NOTHING but python/node calls, with no `$` or
    # backtick anywhere (verifier round 6: `T=tests/x; python3 -c "open('$T',…)"`
    # and `cd $D && …`, `builtin cd`, `eval cd`, functions, aliases all lifted
    # real test writes). The owner's case — a heredoc writing a record — fits.
    if "$" in cmd or "`" in cmd:
        return False
    shell, _bodies = split_heredocs(cmd)
    for seg in split_segments("\n".join(shell)):
        words = words_of(seg)
        if not words or not RESOLVING.fullmatch(os.path.basename(words[0])):
            return False
    regions = _inline_regions(cmd, cwd)
    if not regions:
        return False
    test_dirs = _test_dir_names(cfg)
    rest = cmd
    for interp, code, here in regions:
        if not RESOLVING.fullmatch(interp):
            return False
        targets, unresolved, names = _write_targets_in(code)
        if unresolved or not _lenient_ok(code, names):
            return False
        for t in targets:
            rel = rel_to_root(t, here, root)
            if rel and (matches(rel, cfg["test_globs"]) or any(p in test_dirs for p in rel.split("/"))):
                return False
        rest = rest.replace(code, " ")
    for tok in re.findall(r"[\w@./+-]+", rest):
        for here in {h for _i, _c, h in regions}:
            rel = rel_to_root(tok, here, root)
            if rel and matches(rel, cfg["test_globs"]):
                return False
    return True


def _overridable(reason: str, event: dict, cfg: dict, root: str, new_reasons: list) -> bool:
    """The only two previous-guard hits the new guard may lift (owner,
    2026-10-04): the inline tripwire's false positive on provably harmless
    code, and a "secret file" that was really a search filter's value."""
    if event.get("tool_name") != "Bash":
        return False
    cmd = (event.get("tool_input") or {}).get("command", "")
    cwd = event.get("cwd") or root
    if reason.startswith("fix-lock is engaged: inline code in this command writes test/baseline"):
        return _inline_all_lenient(cmd, cwd, cfg, root)
    m = re.fullmatch(r"`[^`]+` would print secret file (.+) into the transcript|command touches secret file (.+)",
                     reason)
    if m:
        # The new checks must have found no secret read at all (a grep whose
        # later --include re-admits the file reads it), and EVERY secret-looking
        # word the previous guard sees must be an excluding filter's value (it
        # reports only the first one — verifier round 6).
        if any("secret file" in r for r in new_reasons):
            return False
        filt = _filter_values(cmd)
        if (m.group(1) or m.group(2)) not in filt:
            return False
        base = _base_module()
        for seg in base.split_segments(cmd):
            verb, args = base.verb_and_args(base.words_of(seg))
            for t in base.file_args(verb, args) + base.redirect_targets(seg):
                if base.is_secret(t, cfg) and t not in filt:
                    return False
        return True
    return False


def decide(event: dict, cfg: dict, root: str = ROOT, lock_present: bool | None = None,
           branch_fn=current_branch, relaxed: list | None = None) -> tuple:
    """Return (decision, [reasons]): the STRICTER of the previous guard
    (guard_base.py, unchanged) and the new checks — the new code can only add.
    A stricter previous decision is set aside only when every one of its
    reasons is one of the two owner-approved overrides (_overridable)."""
    global _DEADLINE, _DEADLINE_ALL
    _DEADLINE = time.time() + SEARCH_TIME_BUDGET
    _DEADLINE_ALL = time.time() + CHECK_TIME_BUDGET
    if lock_present is None:
        lock_present = lock_held(root, event.get("session_id"))
    new_relaxed, base_relaxed = [], []
    timed_out = False
    try:
        new = _decide_new(event, cfg, root, lock_present=lock_present, branch_fn=branch_fn, relaxed=new_relaxed)
    except _TooSlow:
        timed_out = True
        new, new_relaxed = ("ask", ["this command is too complex for the guard to check within its time "
                                    "— owner approves"]), []
    base = base_decide(event, cfg, root, lock_present=lock_present, branch_fn=branch_fn, relaxed=base_relaxed)

    def overridable(r: str) -> bool:
        if timed_out:  # unchecked: nothing may lift the previous guard (verifier round 7)
            return False
        try:
            return _overridable(r, event, cfg, root, new[1])
        except _TooSlow:
            return False

    if RANK[base[0]] > RANK[new[0]] and not all(overridable(r) for r in base[1]):
        chosen, chosen_relaxed = base, base_relaxed
    else:
        chosen, chosen_relaxed = new, new_relaxed
    if relaxed is not None:
        relaxed.extend(chosen_relaxed)
    return chosen


def _decide_new(event: dict, cfg: dict, root: str = ROOT, lock_present: bool | None = None,
           branch_fn=current_branch, relaxed: list | None = None) -> tuple:
    """Return (decision, [reasons]). Pure apart from branch_fn / lock lookup.

    Each hit is (decision, reason, keep). `keep` marks an ask that stays in
    the development profile (money moves, secrets). Asks development lets
    through are appended to `relaxed`, so the caller can log them."""
    tool = event.get("tool_name", "")
    tin = event.get("tool_input") or {}
    cwd = event.get("cwd") or root
    if lock_present is None:
        lock_present = lock_held(root, event.get("session_id"))
    hits = []

    if tool in PATH_TOOLS:
        raw = tin.get(PATH_TOOLS[tool])
        if raw:
            rel = rel_to_root(raw, cwd, root)
            if is_secret(raw, cfg):
                hits.append(("deny" if tool in READ_TOOLS else "ask",
                             "%s is a secret file — its contents must not enter the transcript; "
                             "ask the owner for the one value you need" % raw, True))
            if rel is not None and tool not in READ_TOOLS:
                if is_lock_file(rel):
                    if tool != "Write":
                        hits.append(("ask", "editing the fix-lock ends the fix phase — owner approves", False))
                elif matches(rel, cfg["protected_globs"]):
                    hits.append(("ask", "%s is protected (constitution / gate) — owner approves every change" % rel,
                                 False))
                if lock_present and matches(rel, cfg["test_globs"]):
                    hits.append(("deny", "fix-lock is engaged: %s is a test/baseline. Fix the code, not the "
                                         "test (release with `guard.py fix-lock off`, owner approves)" % rel,
                                 True))
                elif lock_present and tool in EDIT_TOOLS:
                    hit = inline_edit_hit(tool, tin, rel, root, cfg)
                    if hit:
                        hits.append(hit)
    elif tool == "Bash":
        cmd = tin.get("command", "")
        hits += bash_hits(cmd, cwd, cfg, root, lock_present, branch_fn)
        if lock_present:
            for rel in inline_code_test_writes(cmd, cwd, cfg, root):
                hits.append(("deny", "fix-lock is engaged: inline code in this command writes test/baseline %s. "
                                     "Fix the code, not the test" % rel, True))

    if cfg.get("profile", "stable") == "development":
        let_through = [r for d, r, keep in hits if d == "ask" and not keep]
        if relaxed is not None:
            relaxed += let_through
        hits = [h for h in hits if not (h[0] == "ask" and not h[2])]
    if not hits:
        return "allow", []
    worst = max(hits, key=lambda h: RANK[h[0]])[0]
    return worst, [r for d, r, _keep in hits if d == worst]


def _substitutions(seg: str) -> list:
    """Command text inside $(…) and `…` — run before the command itself."""
    out = []
    for m in re.finditer(r"\$\(", seg):
        end = _balanced(seg, m.end() - 1)
        out.append(seg[m.end():end - 1])
    out += re.findall(r"`([^`]*)`", seg)
    return out


def bash_hits(cmd: str, cwd: str, cfg: dict, root: str, lock_present: bool, branch_fn) -> list:
    """Every hit in a command. A `cd`/`pushd` ADDS a folder to judge later
    paths from — it never replaces the original, because it may not take effect
    (`cd nowhere; …`, `cd x || true`, `if false; then cd x; fi` — verifier round
    4). Heredoc bodies stay commands (money moves via ssh / docker exec)."""
    hits, heres, prev = [], [cwd], None
    for seg in split_segments(cmd):
        _tick()
        words = words_of(seg)
        if words and words[0].startswith("(") and words[0] != "(":  # `(cat .env)`
            words = [words[0].lstrip("(")] + words[1:]
        if words and seg.lstrip().startswith("(") and words[-1].endswith(")") and words[-1] != ")":
            words = words[:-1] + [words[-1].rstrip(")")]
        verb, args = verb_and_args(words)
        subs = _substitutions(seg)
        if verb in ("cd", "pushd"):
            # the cd segment itself is checked like any other (`cd "$(lncli …)"`,
            # `cd . > tests/x` — verifier round 5), then ADDS a folder
            for here in list(heres):
                for sub in subs:
                    hits += bash_hits(sub, here, cfg, root, lock_present, branch_fn)
                hits += _segment_hits(seg, words, verb, args, here, cfg, root, lock_present, branch_fn)
            nxt = cd_target(heres[-1], args)
            if nxt not in heres:
                if len(heres) >= MAX_FOLDERS:
                    hits.append(("ask", "this command changes folder too many times for the guard to follow "
                                        "— owner approves", True))
                else:
                    heres.append(nxt)
            prev = None
            continue
        if verb in ("sh", "bash", "zsh", "dash", "ksh"):
            hs = HERESTRING.search(seg)
            if hs and words_of(hs.group(1)):
                subs.append(words_of(hs.group(1))[0])  # `sh <<< 'cmd'`
            elif prev and not [a for a in args if not a.startswith("-")]:
                subs.append(" ".join(prev))  # `echo 'cmd' | sh`: what the shell reads
        for here in heres:
            for sub in subs:
                hits += bash_hits(sub, here, cfg, root, lock_present, branch_fn)
            hits += _segment_hits(seg, words, verb, args, here, cfg, root, lock_present, branch_fn)
        prev = args if verb in ("echo", "printf", "cat") else None
    return hits


def _segment_hits(seg: str, words: list, verb: str, args: list, here: str, cfg: dict, root: str,
                  lock_present: bool, branch_fn) -> list:
    _tick()
    hits = []
    # Text another shell will run is checked as commands — and the segment's
    # own checks still run (only add).
    if verb == "eval":
        hits += bash_hits(" ".join(args), here, cfg, root, lock_present, branch_fn)
    sub = shell_string_of(verb, args)  # sh/bash/zsh/su/script -c '…'
    if sub is not None:
        hits += bash_hits(sub, here, cfg, root, lock_present, branch_fn)
    if verb == "find":  # what -exec runs is a command of its own
        for k, a in enumerate(args):
            if a in ("-exec", "-execdir", "-ok", "-okdir"):
                end = next((j for j in range(k + 1, len(args)) if args[j] in (";", "+", "\\;")), len(args))
                if end > k + 1:
                    hits += bash_hits(shlex.join(args[k + 1:end]), here, cfg, root, lock_present, branch_fn)
    # The outer command's own arguments too: a runner/prefix may name a
    # secret (`uv run --env-file .env …` — verifier round 3).
    outer = os.path.basename(words[0]) if words else ""
    named = (file_args(verb, args) + file_args(outer, words[1:])
             + [t.rstrip("'\"),;]") for t in redirect_targets(seg)])  # `>> .env',` inside code text
    for t in list(named):
        if any(c in t for c in "*?[") and not _dynamic(t):
            named += [os.path.relpath(x, here) for x in glob.glob(os.path.join(here, os.path.expanduser(t)))]
    secrets = [t for t in named if is_secret(t, cfg)]
    if secrets and verb not in METADATA_VERBS:
        if verb in READER_VERBS:
            hits.append(("deny", "`%s` would print secret file %s into the transcript" % (verb, secrets[0]),
                         True))
        else:
            hits.append(("ask", "command touches secret file %s" % secrets[0], True))
    search = recursive_search(verb, args)
    if search:
        found = secret_in_tree(search, here, cfg)
        if found:
            if found.startswith("("):
                what = "might read a secret file %s" % found
            else:
                what = "would also read secret file %s" % (
                    (rel_to_root(found, here, root) or found) if os.path.isabs(found) else found)
            hits.append(("ask", "this search %s — use `git grep` (tracked files only), a narrower "
                                "folder, or exclude it (--exclude / -g '!…'); owner approves" % what, True))
    if verb == "git":
        d, r = git_push_verdict(args, here, cfg, branch_fn)
        if d != "allow":
            hits.append((d, r, False))
    if "guard.py" in seg and "fix-lock" in words and "off" in words:
        if "--session" in words or "--global" in words:
            hits.append(("ask", "this releases a fix-lock another session (or the owner) holds — owner "
                                "approves", True))
        elif cfg.get("fix_lock_release_needs_owner", True):
            hits.append(("ask", "releasing the fix-lock ends the fix phase — owner approves", False))
    if ("guard.py" in seg and "profile" in words and "development" in words
            and cfg.get("profile", "stable") != "development"):
        hits.append(("ask", "switching the guard to 'development' stops most of its asks — owner "
                            "approves (switching back to stable is always free)", True))
    for target in write_targets(seg):
        rel = rel_to_root(target, here, root)
        if rel is None:
            continue
        if is_lock_file(rel) or matches(rel, cfg["protected_globs"]):
            hits.append(("ask", "command writes protected path %s — owner approves" % rel, False))
        if not lock_present:
            continue
        names = [n for n in (rel_to_root(t, here, root) for t in shell_names(target, here)) if n]
        # a whole test folder (`rm -rf <dir>`, `mv <dir> …`, `git checkout -- <dir>`)
        names += [n.rstrip("/") + "/__any__" for n in names]
        if any(matches(n, cfg["test_globs"]) for n in names):
            hits.append(("deny", "fix-lock is engaged: command writes test/baseline %s. "
                                 "Fix the code, not the test" % rel, True))
        elif any(inline_rules(n, cfg) for n in names):
            hits.append(("deny", "fix-lock is engaged: command writes %s, a file type that keeps tests "
                                 "inside the code (inline_tests). A shell write can't be checked line by "
                                 "line; make the change with Edit or Write, which the guard checks" % rel,
                         True))
    for p in cfg["funds_patterns"]:
        if re.search(p["regex"], seg):
            hits.append(("ask", p["reason"], p.get("always_ask", False)))
    return hits

def log_relaxed(root: str, event: dict, reasons: list) -> None:
    """Record an ask the development profile let through. Never raises."""
    tin = event.get("tool_input") or {}
    what = tin.get("command") if event.get("tool_name") == "Bash" else tin.get(PATH_TOOLS.get(event.get("tool_name"), ""))
    try:
        path = os.path.join(root, RELAXED_LOG_REL)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps({"at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "tool": event.get("tool_name"),
                                "why": reasons, "what": str(what or "")[:300]}) + "\n")
    except OSError:
        pass


def run_hook(stdin_text: str, config_path: str = CONFIG_PATH, root: str = ROOT) -> dict | None:
    """Hook output dict, or None for a silent allow. Never raises."""
    relaxed: list = []
    event: dict = {}
    try:
        event = json.loads(stdin_text)
        decision, reasons = decide(event, load_config(config_path), root, relaxed=relaxed)
    except Exception as e:  # noqa: BLE001 — a broken guard must be loud, not open
        decision, reasons = "ask", ["guard.py failed (%s: %s) — gates are NOT being checked; "
                                    "fix .claude/hooks before continuing" % (type(e).__name__, e)]
    if relaxed:
        log_relaxed(root, event, relaxed)
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


def _read_lock(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def fix_lock_cli(args: list, root: str = ROOT, config_path: str = CONFIG_PATH, session: str | None = None) -> int:
    """`session`: the caller's Claude Code session (main() passes
    CLAUDE_CODE_SESSION_ID); None = the global lock, which binds every session."""
    glob_lock = os.path.join(root, LOCK_REL)
    own = session_lock_path(root, session) if session else glob_lock
    if args[:1] == ["on"] and len(args) == 2:
        refused = fix_lock_preflight(root, config_path)
        if refused:
            print("fix-lock NOT engaged — %s\nNothing was changed. Fix it first, then engage." % refused,
                  file=sys.stderr)
            return 1
        os.makedirs(os.path.dirname(own), exist_ok=True)
        with open(own, "w") as f:
            json.dump({"record": args[1], "since": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "session": session}, f)
        scope = "this session" if session else "EVERY session (global lock)"
        print("fix-lock ENGAGED for %s (%s) — test files, inline tests and baselines are now read-only"
              % (args[1], scope))
        return 0
    if args[:1] == ["off"]:
        if args == ["off"]:
            target = own
        elif len(args) == 3 and args[1] == "--session":
            target = session_lock_path(root, args[2])
        elif args == ["off", "--global"]:
            target = glob_lock
        else:
            target = None
        if target is not None:
            if os.path.exists(target):
                held = _read_lock(target)
                with open(os.path.join(root, LOCK_LOG_REL), "a") as f:
                    f.write(json.dumps({"record": held.get("record"), "engaged_since": held.get("since"),
                                        "session": held.get("session"), "released_by": session,
                                        "released_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}) + "\n")
                os.remove(target)
                print("fix-lock released (%s)" % (held.get("record") or "?"))
            else:
                print("no fix-lock held there — nothing released")
            return 0
    if args == ["status"]:
        found = []
        if os.path.exists(glob_lock):
            found.append(("GLOBAL (binds every session)", _read_lock(glob_lock)))
        for path in sorted(glob.glob(os.path.join(root, LOCK_DIR_REL, "*.json"))):
            held = _read_lock(path)
            mine = bool(session) and os.path.abspath(path) == os.path.abspath(own)
            found.append(("session %s%s" % (held.get("session") or os.path.basename(path)[:-5],
                                            " (this session)" if mine else ""), held))
        if not found:
            print("fix-lock not engaged")
        for who, held in found:
            print("%s: %s since %s" % (who, held.get("record"), held.get("since")))
        return 0
    print("usage: guard.py fix-lock on <build-record> | off [--session <id> | --global] | status", file=sys.stderr)
    return 2


def profile_cli(args: list, root: str = ROOT, config_path: str = CONFIG_PATH) -> int:
    """Show or set the profile. Only the "profile" line of the config changes
    (no re-serialising: the file keeps its own layout), and every switch is
    logged."""
    try:
        with open(config_path) as f:
            text = f.read()
        current = json.loads(text).get("profile", "stable")
    except (OSError, ValueError) as e:
        print("cannot read %s: %s" % (config_path, e), file=sys.stderr)
        return 1
    if not args:
        print("profile: %s" % current)
        return 0
    if len(args) != 1 or args[0] not in PROFILES:
        print("usage: guard.py profile [%s]" % " | ".join(PROFILES), file=sys.stderr)
        return 2
    want = args[0]
    if want == current:
        print("profile already %s" % want)
        return 0
    line = re.compile(r'^(\s*)"profile"\s*:\s*"[^"]*"', re.M)
    if line.search(text):
        new = line.sub(lambda m: '%s"profile": "%s"' % (m.group(1), want), text, count=1)
    else:
        new = text.replace("{\n", '{\n  "profile": "%s",\n' % want, 1)
    if json.loads(new).get("profile") != want:
        print("could not set the profile in %s; nothing was changed" % config_path, file=sys.stderr)
        return 1
    tmp = config_path + ".tmp"
    with open(tmp, "w") as f:
        f.write(new)
    try:
        load_config(tmp)
    except Exception as e:  # noqa: BLE001 — never leave a config the guard cannot load
        os.remove(tmp)
        print("refused: the new config would not load (%s)" % e, file=sys.stderr)
        return 1
    os.replace(tmp, config_path)
    log = os.path.join(root, PROFILE_LOG_REL)
    os.makedirs(os.path.dirname(log), exist_ok=True)
    with open(log, "a") as f:
        f.write(json.dumps({"from": current, "to": want, "at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}) + "\n")
    print("profile: %s -> %s" % (current, want))
    return 0


def main() -> int:
    if sys.argv[1:2] == ["fix-lock"]:
        return fix_lock_cli(sys.argv[2:], session=os.environ.get("CLAUDE_CODE_SESSION_ID") or None)
    if sys.argv[1:2] == ["profile"]:
        return profile_cli(sys.argv[2:])
    out = run_hook(sys.stdin.read())
    if out:
        print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
