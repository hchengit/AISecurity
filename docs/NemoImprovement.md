Let me search to make sure — "Nemoclaw" doesn't match what I know of NVIDIA's releases, but I want to verify before giving you a comparison based on a guess:

Got it — NemoClaw shipped at GTC 2026 (weeks ago). I can see the shape of it now. Real comparison follows.

## What NemoClaw does that AISecurity doesn't

NemoClaw is a three-layer security stack for OpenClaw agents: **OpenShell** (sandboxed runtime with policy-based network controls), **Privacy Router** (strips PII before cloud model calls), and **Intent Verification** (validates what an agent wants to do before it does it).

AISecurity covers related ground — command policy engine, prompt injection detection, process monitor, model verifier — but it's **observational and endpoint-focused**. NemoClaw is **interpositional and agent-focused**: it sits in the execution path of an AI agent and enforces rather than alerts.

Five concrete things worth borrowing:

### 1. A Privacy Router for outbound LLM API calls (biggest ROI)

NemoClaw intercepts calls to cloud models and strips PII before the request leaves the machine. AISecurity already has the PII detection engine — `SensitiveDataDetector` scans files and the clipboard for keychain references, AWS creds, SSH keys, password manager data, etc. What's missing is the **interception layer**.

What this would look like:
- A local HTTPS proxy, with a per-install CA cert added to the user's Keychain
- Intercepts `api.anthropic.com`, `api.openai.com`, `api.groq.com`, `api.together.ai`, etc.
- Runs the existing sensitive-data detector on the outbound prompt body
- Policy: block, redact, warn, or allow — configurable per category
- Audit log of every outbound AI call

This is the single highest-value feature we could copy. Right now if someone using Cursor/Claude Code/Copilot pastes a file containing secrets into a chat, nothing on the machine catches it mid-flight. AISecurity's existing detector could power the check — we just need the interception.

**Cost:** Moderate. Needs the cert plumbing and a small Go/Rust proxy. Non-trivial but not research-grade. Works without any Apple entitlement.

### 2. Sandboxed agent execution via `sandbox-exec`

OpenShell enforces network/filesystem policy *around* the agent process. macOS has had the same primitive forever: `sandbox-exec` with a Seatbelt profile. It's underdocumented but fully functional.

AISecurity could ship an `ai-exec` wrapper that:
- Takes a sandbox profile declaring "this process can read `~/Documents/project`, write `/tmp`, connect to `api.anthropic.com`, and nothing else"
- Launches the agent binary (ollama, claude, aider, whatever) inside that sandbox
- Combines with the command policy engine: when the sandboxed agent tries to spawn a forbidden subprocess, we deny AND alert

**Cost:** Low-to-moderate. Seatbelt is already built into macOS. The UX work is translating "what the user wants to allow" into TinyScheme sandbox syntax.

### 3. Intent verification as a pre-action gate

Right now AISecurity's `threat_intent_parser.rs` reasons about the *intent* of inbound content (emails claiming authority, urgency, wire requests). NemoClaw flips that direction and reasons about the intent of *outbound agent actions* before they execute.

Adding this to AISecurity means:
- An API (local socket / HTTP) that an agent can call before executing a dangerous action: "I'm about to `rm -rf ~/Downloads/temp` — is that OK?"
- AISecurity compares the requested action against the agent's declared current task (which the agent also passes), and the existing command policy engine
- Returns allow / deny / ask (we already have this enum in `CommandDecision`)
- Integrations: Claude Code hooks, a wrapper CLI, an MCP server

**Cost:** Low for the API surface; the hard part is getting agents to actually call in. Start with a Claude Code hook that every user installs once, then build outward.

### 4. Policy-as-code for agent behavior

NemoClaw's OpenShell accepts declarative policy — AISecurity has `config.toml` but it's mostly flat flags. Worth upgrading to something like:

```toml
[agents.claude-code]
allowed_paths_read  = ["~/work/", "~/Documents/"]
allowed_paths_write = ["~/work/"]
allowed_network     = ["api.anthropic.com", "github.com"]
command_policy      = "restrictive"

[agents.ollama]
allowed_paths_read  = ["~/.ollama/"]
allowed_network     = []            # offline-only
```

This makes "which agent is doing what" auditable and lets users tighten per-agent rather than globally.

**Cost:** Low. Extends `config.toml` schema + adds `[agents.*]` resolution to the existing policy engine.

### 5. Model vetting feed (not just hashing)

AISecurity's `model_verifier.rs` hashes models and detects tampering — but doesn't know whether a model is *known-bad* (backdoored weights, malicious fine-tunes). NemoClaw ships with a curated catalog of NVIDIA-vetted models. AISecurity could do the light version:
- Subscribe to a "known-bad model SHA256" feed (HuggingFace has started publishing some; academic papers like BadNets list concrete hashes)
- Alert when a freshly-downloaded model matches
- Add a `models.allow_list` config section where users pin specific hashes they trust

**Cost:** Low. Piggybacks on the existing threat-feeds pipeline.

## What AISecurity does that NemoClaw doesn't

Worth naming so you don't throw out the baby:
- Real endpoint protection (email, Messages, file watching on disk)
- Active self-protection watchdog
- Encrypted user vault with portable export
- Works independent of any specific agent framework — NemoClaw is tightly coupled to OpenClaw

## Priority order if I were shipping this

1. **Privacy Router** (items 1 + 4 together) — unique value, no Apple entitlement needed, applies to every cloud-model-using app on the machine, not just one framework
2. **Sandboxed exec wrapper** — quick win using `sandbox-exec`
3. **Intent-verification API** — harder because it needs adoption; start as a Claude Code hook
4. **Known-bad model feed** — cheap extension to existing threat-feeds infrastructure

Sources:

- [What Is NemoClaw? Nvidia's Secure Wrapper for OpenClaw Agents — MindStudio](https://www.mindstudio.ai/blog/what-is-nemoclaw-nvidia-openclaw-wrapper)
- [NVIDIA NemoClaw: Deploy Safer AI Assistants with OpenClaw Safety Guardrails — nvidia.com](https://www.nvidia.com/en-us/ai/nemoclaw/)
- [GitHub — NVIDIA/NemoClaw](https://github.com/NVIDIA/NemoClaw)
- [What Is NVIDIA NeMoClaw? A Security Engineer's First Look — Repello AI](https://repello.ai/blog/nvidia-nemoclaw)
- [Nvidia's NemoClaw has three layers of agent security. None of them solve the real problem. — The New Stack](https://thenewstack.io/nvidia-nemoclaw-openclaw-security/)
- [NVIDIA OpenClaw Security — What NemoClaw Changes and What It Still Cannot Fix — Penligent](https://www.penligent.ai/hackinglabs/nvidia-openclaw-security-what-nemoclaw-changes-and-what-it-still-cannot-fix/)

The Nemoclaw grep search I kicked off earlier finished with no output — confirms what we saw live: nothing references "Nemoclaw" in your project files or `.claude/` config. Your memory system doesn't know about it yet, which is consistent with NemoClaw being a very new NVIDIA release (GTC 2026). The research-only comparison I gave you above stands.

No todos to update — this is all analysis/research, no code changes. Let me know if any of those five items (Privacy Router, sandbox-exec wrapper, intent verification API, policy-as-code config, model vetting feed) look worth spinning into real work later, and I'll plan a next session around it.