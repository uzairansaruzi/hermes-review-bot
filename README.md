# hermes-review-bot

A self-hosted GitHub PR review bot that runs **on your own machine, on your own
Hermes, with your own model subscriptions and settings**. Webhook or polling
trigger, sticky summary comment + line-anchored inline findings, `/hermes review`
follow-up rounds, and per-repo rules that a PR cannot rewrite about itself.

**Live example:** [hermex#606](https://github.com/uzairansaruzi/hermex/pull/606) —
sticky summary, confidence score, 2 inline findings, review footer
([hermex#546](https://github.com/uzairansaruzi/hermex/pull/546) shows a 3-inline-comment round).

```
GitHub event ─▶ your Hermes gateway ─▶ scripts/review.py ─▶ review engine ─▶ GitHub API
                 (route + HMAC)         (worktree, prompt,     (agy/claude/       (sticky + inline
                                          gating, state)        codex/...          comments + status)
```

---

## Engine status

Pick any engine in `config.yaml`. Same reviewer brain, different headless CLI.

| Engine      | Status on this build | Notes |
|-------------|----------------------|-------|
| `agy`       | **proven**           | Antigravity CLI with stream-json stdin input. Google sign-in or `GEMINI_API_KEY`. |
| `opencode`  | **smoke-tested**     | Headless invocation verified at build time. |
| `hermes`    | **smoke-tested**     | Uses your existing Hermes providers — zero extra subscriptions. |
| `claude`    | experimental         | CLI not on the build machine; argv unit-tested, `--allowedTools` read-only allowlist. |
| `codex`    | experimental         | Build machine's install was broken; argv unit-tested (`exec --sandbox read-only`). |
| `gemini`    | experimental         | CLI not on the build machine; argv unit-tested (`-p --yolo`). |

"Experimental" = the command shape is tested but no live run happened here. If
you use one, run its smoke command once yourself (see **Engines** below) and
please open an issue with the result so the table stays honest.

## Requirements

- macOS or Linux
- [Hermes](https://hermes-agent.nousresearch.com/docs) installed and running —
  this bot does **not** install or configure Hermes for you
- `python3` with PyYAML (usually already there), `git`, `openssl`
- A GitHub fine-grained PAT (scopes below)
- Optional: `gh` CLI (automated webhook creation), a tunnel for instant mode

## Quickstart (~15 minutes)

```bash
git clone https://github.com/uzairansaruzi/hermes-review-bot.git
cd hermes-review-bot

# 1. token — create a fine-grained PAT at https://github.com/settings/personal-access-tokens/new
#    Repositories: only the repos you want reviewed
#    Permissions:  Contents: read · Pull requests: read/write · Issues: read/write · Statuses: write · Metadata: read
#    then add it to ~/.hermes/.env (never commit it):
echo 'HERMES_PR_REVIEW_GITHUB_TOKEN=ghp_...' >> ~/.hermes/.env

# 2. install (interactive; answers the 4 questions, or pre-seed with flags)
./setup.sh --engine agy --repos you/your-repo
```

`setup.sh` writes `~/.hermes/review-bot/config.yaml`, installs the launcher
scripts, and creates the polling cron job. Then:

```bash
./setup.sh --check      # doctor: tools, token, engine, config, trigger — read-only
```

Open a draft PR on a configured repo → within the poll interval you get the
sticky review. Comment `/hermes review` (or `/hermes review full`) for another
round — only the PR author, the repo owner, or anyone with **write** access can
trigger it.

**Doctor first, install second:** `./setup.sh --check` works before any config
exists and never writes anything — use it to validate token/engine/Hermes before
answering a single prompt.

## Trigger modes

### Polling (default — recommended)

A Hermes cron job runs the review loop every 5 minutes (`poll.interval` in
config). **No public URL, no tunnel, no webhook setup** — this is the path that
actually fits the 15-minute bar. Comment commands are detected during polling
too, so follow-ups work with zero inbound infrastructure.

```
hermes cron list          # → hermes-review-bot   (silent when healthy)
# failures print one line to the cron output + log to ~/.hermes/logs/review-bot/poll.log
```

### Instant mode (webhook, advanced)

Needs a public URL pointing at your gateway (`http://127.0.0.1:8644`) and the
gateway running. `./setup.sh --mode both` does the Hermes side for you:

```bash
# a) tunnel, either:
cloudflared tunnel --url http://127.0.0.1:8644        # quick tunnel
ngrok http 8644                                        # or ngrok
# (named Cloudflare tunnel with a stable domain is nicer long-term)

# b) route + secret (setup.sh runs this; HMAC is enforced by the gateway itself):
hermes webhook subscribe hermes-review-bot \
  --events pull_request,issue_comment \
  --script ~/.hermes/scripts/hermes-review-bot-handler.py \
  --secret "$(openssl rand -hex 32)"

# c) GitHub webhook, automated (needs a token with Administration:write — the
#    review PAT intentionally does NOT have it), or printed manual steps:
python3 scripts/github_webhook.py --url https://YOUR-TUNNEL/webhooks/hermes-review-bot \
  --secret <from config.yaml webhook.secret> --repos owner/repo
```

Manual fallback (Settings → Webhooks → Add webhook): payload URL
`https://YOUR-TUNNEL/webhooks/hermes-review-bot`, content type
`application/json`, secret from `webhook.secret` in config, events **Pull
requests** + **Issue comments**.

Security is not optional: the gateway verifies `X-Hub-Signature-256` against
`webhook.secret` and **rejects the payload if the secret is missing or wrong**
(fail closed). No custom verification code exists in this repo because none is
needed — and none should be.

## Configuration

### Machine-global — `~/.hermes/review-bot/config.yaml`

Created from [`templates/config.example.yaml`](templates/config.example.yaml):

| Key | Default | What it does |
|---|---|---|
| `engine` / `model` | `agy` / `gemini-3.8-flash-high` | Which CLI runs the analysis; `model: ""` = engine default |
| `repos` | — | Everything the bot serves; one install covers all |
| `events` / `actions` | PR open/reopen/sync/ready | Which GitHub events trigger review |
| `skip_drafts` | `true` | Draft PRs wait until ready |
| `output_style` | `comment` | `comment` or `request_changes` (formal changes-requested review) |
| `followup_commands` | `true` | `/hermes review` comment commands on/off |
| `timeout_minutes` | `30` | Per-review wall clock |
| `status_context` | `Hermes Review Bot` | Commit status context name |
| `prompt_file` | `""` | Custom prompt (empty = bundled default) |
| `install_path` | written by setup | Where the clone lives (launchers use it) |
| `poll.interval` / `poll.max_prs` | `5m` / `3` | Poll cadence and per-tick budget |
| `webhook.url` / `webhook.secret` | — | Instant mode (setup manages the secret) |

### Per-repo — committed in the target repo

- `.hermes-review.yml` — strictness, confidence threshold, comment types,
  ignore patterns, author/branch/label filters, custom rules, `enabled`,
  optional `engine`/`model`/`output_style` overrides
  (see [`templates/repo-config.yaml`](templates/repo-config.yaml))
- `.hermes-review/rules.md` — free-form review criteria for your codebase
  (see [`templates/rules.md`](templates/rules.md))
- `CLAUDE.md` / `AGENTS.md` / `.cursorrules` — picked up as context docs

**Trust boundary:** all of these are read from the PR's **base branch**, never
from the PR head. A contributor cannot loosen the rules used to review their own
PR — config changes take effect when merged.

### Prompt

The bundled [`prompts/review-default.md`](prompts/review-default.md) is
language-agnostic (passes: intent → trace → grounding search → before/after →
surface checklist → challenge → test rigor, with severity/type/voice/threshold
rules and the machine-readable findings contract). Override it per machine with
`prompt_file:` — a Swift/iOS example that drives the live demo ships at
[`prompts/examples/ios-review.md`](prompts/examples/ios-review.md).

## Engines

Install one (or bring your own — the roster is interchangeable):

```bash
agy:      curl -fsSL https://antigravity.google/cli/install.sh | bash   # then run `agy` once to sign in
claude:   npm install -g @anthropic-ai/claude-code                      # then `claude` once
codex:    npm install -g @openai/codex                                  # then `codex login`
opencode: curl -fsSL https://opencode.ai/install | bash                 # then `opencode auth login`
gemini:   npm install -g @google/gemini-cli                             # then `gemini` once
hermes:   already installed if you're running this                       # no extra auth
```

`setup.sh` offers to run the install command for you (explicit confirmation
required — it never installs anything on its own) and **auth is always manual**:
the bot only checks that auth succeeded (`agy` also gets a real
`agy models | grep <model>` check when `model:` is set) and fails loudly if not.

Headless auth alternatives: `GEMINI_API_KEY` (agy/gemini), `ANTHROPIC_API_KEY`
(claude), `OPENAI_API_KEY` (codex) in `~/.hermes/.env`. Smoke any engine without
touching GitHub:

```bash
HERMES_PR_REVIEW_BOT_HOME=$PWD python3 - <<'EOF'
import importlib.util, sys, os
spec = importlib.util.spec_from_file_location("r", "scripts/review.py")
m = importlib.util.module_from_spec(spec); sys.modules["r"] = m; spec.loader.exec_module(m)
import subprocess; subprocess.run(m.build_engine_command("hermes", "Reply with exactly: OK", os.getcwd(), "", 5), check=False)
EOF
```

## How a review runs

1. Event arrives (or poll tick) → `scripts/review.py` validates action, draft,
   dedupe (head SHA already reviewed → skip), and labels/keywords.
2. Isolated temp worktree from a cached bare mirror; config + rules loaded from
   the **base branch**.
3. The prompt assembles trust boundary, hard limits (read-only), repo search
   grounding, review depth, your rules — then the engine runs headless **in an
   env scrubbed of GitHub credentials** (engines only ever see their own auth).
4. Output is cleaned/validated; findings pass the gate (strictness floor,
   confidence threshold, comment-type allowlist — `P0`/`P1`/security always
   kept); inline comments anchor to real diff lines; one sticky summary comment
   is created/updated; commit status posted.
5. `/hermes review` re-runs with prior rounds as context (resolved/unresolved/
   regressed tracking against your own previous findings only).

State: `~/.hermes/data/review-bot/<repo>/state.json` ·
Logs: `~/.hermes/logs/review-bot/` ·
Launchers: `~/.hermes/scripts/hermes-review-bot-{handler,poll}.py` (copied, not
symlinked — the gateway rejects symlinks for route scripts).

## Security model (short version)

- **Inbound webhooks:** HMAC `X-Hub-Signature-256` verified by the gateway,
  fail-closed; missing secret = payload rejected.
- **Config trust:** repo rules read from base branch only.
- **Outbound engine:** env allowlist per engine; `GH_TOKEN` / `GITHUB_TOKEN` /
  `HERMES_PR_REVIEW_GITHUB_TOKEN` never reach the model process.
- **Repo content is untrusted input:** the prompt tells the model that diffs,
  docs, config, and context files can attempt prompt injection and must be
  treated as review criteria only, never as instructions.
- **Credential hygiene:** one scoped PAT in `~/.hermes/.env`; this repo never
  prints or commits secrets; webhook Administration rights stay separate (gh
  CLI or manual), so the review token cannot be widened by accident.

## What was verified at build time

Component-level smoke, honest to the end of the chain (the final GitHub POST
runs your credentials on your machine — not something CI here can prove):

- 51 unit/integration tests: engine argv for all six engines, env scrubbing,
  findings parse/gate/replace/compact, **base-branch trust against a real git
  fixture**, global config layering, webhook handler routing on fixture
  payloads, signature contract, prompt↔parser contract — `python3 -m pytest tests/`
- live headless runs of the `agy`, `opencode`, `hermes` engines with a trivial
  prompt on this build machine
- dry-run of the full fetch → worktree → prompt assembly against a real PR with
  **nothing posted** (`--dump-prompt` / `--preflight-only`, isolated state dir)
- `bash -n setup.sh` + read-only `./setup.sh --check`

## Troubleshooting

- `./setup.sh --check` first — it names the failing layer.
- No review after a push: check cron (`hermes cron list`, scheduler running?)
  and logs (`~/.hermes/logs/review-bot/poll.log`).
- Review failed comment on the PR: the sticky comment names the failure phase
  and safe error summary; full stdout/stderr is in the log.
- Model rejected: `model:` must be offered by your engine (`agy models`).
- Two bots fighting on one repo: markers are brand-specific — don't run this
  alongside another reviewer instance on the same PR.
- Webhook 404: route name must match the payload URL
  (`/webhooks/hermes-review-bot`) and the gateway must be running.

## Uninstall

```bash
hermes cron remove hermes-review-bot          # or: hermes cron edit
hermes webhook remove hermes-review-bot       # instant mode only
rm -f ~/.hermes/scripts/hermes-review-bot-*.py
rm -rf ~/.hermes/review-bot ~/.hermes/data/review-bot ~/.hermes/logs/review-bot
```

Your existing Hermes setup is untouched by all of the above — this repo only
adds its own namespaced files.

## License

MIT — see [LICENSE](LICENSE).


### Large reviews and failed retries

The AGY adapter sends one JSON user event over stdin rather than putting the
review prompt in a command-line argument. This avoids Linux's single-argument
size limit without truncating the review. Use an AGY version supporting
`--input-format stream-json` and `--output-format stream-json`. The bot publishes
only a final `SUCCESS` result; partial output or an engine error cannot become
a successful verdict. Logs retain input sizes and a digest, not prompt contents.

Automatic retries for a failed head wait 5, 10, 20, 40, then 60 minutes. The delay
stays at one hour for later failures. Initial and follow-up failures have separate
state. A new head starts immediately, successful reviews clear their failure
state, and `--force` or a validated manual follow-up command bypasses the delay.

GitHub's Python tests workflow runs the full suite, including an actual child
process receiving a multiline Unicode prompt larger than 128 KiB via stdin.
