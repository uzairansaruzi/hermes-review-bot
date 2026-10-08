"""Engine command construction, env scrubbing, labels, and output redaction."""
import hashlib
import json
import sys

import pytest


def which_all(monkeypatch, path="/mock/bin"):
    monkeypatch.setattr("shutil.which", lambda name: f"{path}/{name}")


def test_agy_argv(make_review, monkeypatch):
    which_all(monkeypatch)
    m = make_review()
    argv = m.build_engine_command("agy", "THE PROMPT", "/tmp/wt", "gemini-3.8-flash-high", 30)
    assert argv[0] == "/mock/bin/agy"
    assert "THE PROMPT" not in argv
    assert argv[-2:] == ["--print", ""]
    assert argv[argv.index("--input-format") + 1] == "stream-json"
    assert argv[argv.index("--output-format") + 1] == "stream-json"
    assert "--model" in argv and argv[argv.index("--model") + 1] == "gemini-3.8-flash-high"
    assert "--print-timeout" in argv and "30m0s" in argv
    assert "--sandbox" in argv and "--add-dir" in argv


def test_agy_argv_without_model(make_review, monkeypatch):
    which_all(monkeypatch)
    m = make_review()
    argv = m.build_engine_command("agy", "P", "/tmp/wt", "", 10)
    assert "--model" not in argv
    assert "10m0s" in argv
    assert "P" not in argv and argv[-1] == ""


def test_claude_argv(make_review, monkeypatch):
    which_all(monkeypatch)
    m = make_review()
    argv = m.build_engine_command("claude", "P", "/tmp/wt", "claude-sonnet-4-5", 30)
    assert argv[:2] == ["/mock/bin/claude", "--print"]
    assert "--output-format" in argv and "--allowedTools" in argv
    assert argv[argv.index("--allowedTools") + 1] == "Bash(git:*),Read,Glob,Grep"
    assert argv[argv.index("--model") + 1] == "claude-sonnet-4-5"
    assert argv[-1] == "P"


def test_codex_argv(make_review, monkeypatch):
    which_all(monkeypatch)
    m = make_review()
    argv = m.build_engine_command("codex", "P", "/tmp/wt", "", 30)
    assert argv[:4] == ["/mock/bin/codex", "exec", "--sandbox", "read-only"]
    assert argv[-1] == "P" and "--model" not in argv


def test_opencode_argv(make_review, monkeypatch):
    which_all(monkeypatch)
    m = make_review()
    argv = m.build_engine_command("opencode", "P", "/tmp/wt", "anthropic/claude", 30)
    assert argv[:4] == ["/mock/bin/opencode", "run", "--format", "json"]
    assert argv[argv.index("-m") + 1] == "anthropic/claude"
    assert argv[-1] == "P"


def test_opencode_events_flatten(make_review):
    m = make_review()
    ndjson = "\n".join([
        '{"type":"step_start"}',
        '{"type":"text","part":{"text":"### Summary\\n\\nfine"}}',
        '{"type":"step_finish","part":{"id":"x"}}',
        "",
    ])
    assert m.opencode_events_to_text(ndjson) == "### Summary\n\nfine"
    # non-JSON passthrough (so validation reports the real failure)
    assert m.opencode_events_to_text("plain prose output") == "plain prose output"


def test_gemini_argv(make_review, monkeypatch):
    which_all(monkeypatch)
    m = make_review()
    argv = m.build_engine_command("gemini", "P", "/tmp/wt", "gemini-2.5-pro", 30)
    assert argv[0] == "/mock/bin/gemini" and "--yolo" in argv
    assert argv[argv.index("--model") + 1] == "gemini-2.5-pro"
    assert argv[-1] == "P" and argv[argv.index("-p") + 1] == "P"


def test_hermes_argv(make_review, monkeypatch):
    which_all(monkeypatch)
    m = make_review()
    argv = m.build_engine_command("hermes", "P", "/tmp/wt", "", 30)
    assert argv[:5] == ["/mock/bin/hermes", "chat", "-Q", "--format", "text"]
    assert argv[-2] == "-q" and argv[-1] == "P"
    argv2 = m.build_engine_command("hermes", "P", "/tmp/wt", "openrouter/x", 30)
    assert argv2[argv2.index("-m") + 1] == "openrouter/x"


def test_unknown_engine_raises(make_review, monkeypatch):
    which_all(monkeypatch)
    m = make_review()
    with pytest.raises(RuntimeError, match="Unsupported engine"):
        m.build_engine_command("deepseek", "P", "/tmp/wt", "", 30)


def test_env_never_leaks_github_tokens(make_review, monkeypatch):
    m = make_review()
    for key in ("GH_TOKEN", "GITHUB_TOKEN", "HERMES_PR_REVIEW_GITHUB_TOKEN"):
        monkeypatch.setenv(key, "sekret")
    for engine in m.VALID_ENGINES:
        env = m.engine_env(engine)
        assert not any(k in ("GH_TOKEN", "GITHUB_TOKEN", "HERMES_PR_REVIEW_GITHUB_TOKEN") for k in env), engine
        assert "sekret" not in env.values(), engine


def test_env_per_engine_credentials(make_review, monkeypatch):
    m = make_review()
    monkeypatch.setenv("GEMINI_API_KEY", "g-key")
    assert m.engine_env("agy")["GEMINI_API_KEY"] == "g-key"
    assert m.engine_env("agy")["AGY_CLI_HIDE_ACCOUNT_INFO"] == "1"
    assert "GEMINI_API_KEY" not in m.engine_env("opencode")
    assert "AGY_CLI_HIDE_ACCOUNT_INFO" not in m.engine_env("hermes")
    assert m.engine_env("hermes")["HERMES_HOME"]


def test_preflight_missing_binary_fails_loudly(make_review, monkeypatch, tmp_path):
    m = make_review()
    monkeypatch.setattr("shutil.which", lambda name: None)
    monkeypatch.setattr(m, "HOME", tmp_path)  # no .local/bin/<name> under tmp_path
    with pytest.raises(RuntimeError, match="not found"):
        m.preflight_engine("claude")


def test_display_cmd_digests_prompt(make_review):
    m = make_review()
    out = m.display_cmd(["agy", "--print", "x" * 5000])
    assert "x" * 100 not in out and "<prompt chars=5000 sha256=" in out
    assert m.display_cmd(["agy", "--sandbox"]) == "agy --sandbox"


def test_model_label_and_events(make_review):
    m = make_review()
    assert m.model_label() == "agy"
    m.ACTIVE_MODEL = "gemini-3.8-flash-high"
    assert m.model_label() == "agy/gemini-3.8-flash-high"
    assert m.review_event(m.RepoConfig()) == "COMMENT"
    assert m.review_event(m.RepoConfig(output_style="request_changes")) == "REQUEST_CHANGES"


REVIEW = "### Summary\nThe review transport accepts the complete multiline prompt without truncation and returns a single final verdict. The implementation preserves Unicode, avoids operating-system argument limits, and keeps intermediate tool narration out of the published review.\n\n### Confidence Score: 5/5\n\n### Important Files Changed\nNone.\n\n### Findings\nNo findings.\n\n### Sequence Diagram\nNot applicable.\n"


def test_large_unicode_prompt_reaches_engine_intact_via_stdin(make_review, monkeypatch, tmp_path):
    m = make_review()
    # Run a real child process with more than Linux's 128 KiB single-argument
    # limit. The receiver independently checks the exact decoded content hash.
    prompt = "line one\nquotes \" and unicode 雪😀\n" * 10000
    digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    receiver = tmp_path / "receiver.py"
    receiver.write_text(f"#!{sys.executable}\n"
                        "import hashlib,json,sys\n"
                        "assert sys.argv[sys.argv.index('--input-format')+1]=='stream-json'\n"
                        "assert sys.argv[-2:]==['--print','']\n"
                        "events=sys.stdin.read().splitlines()\n"
                        "assert len(events)==1\n"
                        "event=json.loads(events[0])\n"
                        "assert event['event']=='user' and event['message']['role']=='user'\n"
                        f"assert hashlib.sha256(event['message']['content'].encode('utf-8')).hexdigest()=={digest!r}\n"
                        f"print(json.dumps({{'event':'result','result':{{'status':'SUCCESS','response':{REVIEW!r}}}}}))\n")
    receiver.chmod(0o755)
    monkeypatch.setattr(m.shutil, "which", lambda name: str(receiver) if name == "agy" else None)
    assert m.run_engine_review(prompt, tmp_path) == REVIEW.strip()
    log = m.LOG_FILE.read_text()
    events = [json.loads(line[line.index("{"):]) for line in log.splitlines() if "{" in line]
    input_event = next(event for event in events if event.get("event") == "command_input")
    assert input_event["input_bytes"] > 131072
    assert len(input_event["sha256"]) == 12
    assert "quotes" not in log and "雪" not in log


def test_agy_result_ignores_tool_narration_and_uses_final_verdict(make_review):
    m = make_review()
    stream = "\n".join(json.dumps(event) for event in [
        {"event": "init", "init": {}},
        {"event": "step_update", "step_update": {"text_delta": "I will inspect files"}},
        {"event": "result", "result": {"status": "SUCCESS", "response": REVIEW}},
    ])
    assert m.agy_events_to_text(stream) == REVIEW


@pytest.mark.parametrize("stream", [
    '{"event":"step_update","step_update":{"text_delta":"partial review"}}',
    '{"event":"result","result":{"status":"ERROR","response":"partial review","error":"timeout"}}',
    '{"event":"result","result":{"status":"SUCCESS"}}',
    '{bad json',
    '{"event":"result","result":{"status":"SUCCESS","response":"one"}}\n{"event":"result","result":{"status":"SUCCESS","response":"two"}}',
])
def test_agy_partial_or_invalid_result_cannot_become_a_successful_review(make_review, stream):
    with pytest.raises(RuntimeError):
        make_review().agy_events_to_text(stream)
