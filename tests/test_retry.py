"""Failed reviews persist bounded retry delays without marking a head reviewed."""
import argparse


def args(**overrides):
    values = dict(event_action=None, include_drafts=False, head_sha=None,
                  force=False, dry_run=False, dump_prompt=False, preflight_only=False,
                  keep_worktree=False, trigger_comment_id=None, followup_scope="incremental")
    return argparse.Namespace(**(values | overrides))


def pr(head="head-one"):
    return {"number": 377, "state": "open", "draft": False, "head": {"sha": head},
            "base": {"ref": "main", "sha": "base"}, "html_url": "https://example.test/pr/377"}


def test_real_failure_path_persists_delay_and_prevents_next_poll(make_review, monkeypatch):
    m = make_review()
    monkeypatch.setattr(m.time, "time", lambda: 1000)
    monkeypatch.setattr(m, "get_pr", lambda *unused: pr())
    calls = []
    def broken_engine():
        calls.append(True)
        raise OSError(7, "Argument list too long")
    monkeypatch.setattr(m, "preflight_engine", broken_engine)
    monkeypatch.setattr(m, "post_failure_comment", lambda *unused: (1, "https://example.test/comment"))
    monkeypatch.setattr(m, "post_commit_status_best_effort", lambda *unused: True)
    state = {}
    assert m.process_one("fixture", 377, args(), state) is False
    persisted = m.load_state()
    assert persisted["377"]["review_failure"]["retry_after"] == 1300
    assert "last_reviewed_sha" not in persisted["377"]
    assert m.process_one("fixture", 377, args(), persisted) is False
    assert len(calls) == 1
    monkeypatch.setattr(m.time, "time", lambda: 1300)
    assert m.process_one("fixture", 377, args(), persisted) is False
    assert len(calls) == 2
    assert m.load_state()["377"]["review_failure"]["retry_after"] == 1900


def test_backoff_caps_at_one_hour_and_changed_head_resets_it(make_review, monkeypatch):
    m = make_review()
    now = [1000]
    monkeypatch.setattr(m.time, "time", lambda: now[0])
    state = {}
    for expected in [300, 600, 1200, 2400, 3600, 3600]:
        m.record_review_failure(state, 377, "head-one", "engine")
        assert m.review_retry_remaining(state, 377, "head-one") == expected
        now[0] += expected
    assert m.review_retry_remaining(state, 377, "head-two") == 0
    m.record_review_failure(state, 377, "head-two", "engine")
    assert state["377"]["review_failure"]["attempts"] == 1
    assert m.review_retry_remaining(state, 377, "head-two") == 300


def test_explicit_retry_and_new_head_bypass_initial_delay(make_review, monkeypatch):
    m = make_review()
    monkeypatch.setattr(m.time, "time", lambda: 1000)
    state = {}
    m.record_review_failure(state, 377, "head-one", "engine")
    assert m.should_process(pr(), args(), state)[0] is False
    assert m.should_process(pr(), args(force=True), state)[0] is True
    assert m.should_process(pr(), args(dry_run=True), state)[0] is True
    assert m.should_process(pr(), args(preflight_only=True), state)[0] is True
    assert m.should_process(pr("head-two"), args(), state)[0] is True


def test_followup_poll_delay_does_not_block_initial_review_or_manual_command(make_review, monkeypatch):
    m = make_review()
    monkeypatch.setattr(m.time, "time", lambda: 1000)
    monkeypatch.setattr(m, "get_pr", lambda *unused: pr())
    monkeypatch.setattr(m, "preflight_engine", lambda: None)
    monkeypatch.setattr(m, "load_prompt", lambda: "fixture")
    state = {}
    m.record_review_failure(state, 377, "head-one", "engine", followup=True)
    assert m.should_process(pr(), args(), state)[0] is True
    assert m.process_followup("fixture", 377, args(), state) is False
    monkeypatch.setattr(m, "validate_review_command", lambda *unused: ({}, "incremental"))
    monkeypatch.setattr(m, "react_to_comment_best_effort", lambda *unused: None)
    checkpoint_calls = []
    def no_checkpoint(*unused):
        checkpoint_calls.append(True)
        return None
    monkeypatch.setattr(m, "get_checkpoint_sha", no_checkpoint)
    monkeypatch.setattr(m, "post_commit_status_best_effort", lambda *unused: True)
    # A validated user command bypasses the delay and reaches checkpoint lookup.
    assert m.process_followup("fixture", 377, args(trigger_comment_id="42", since_sha=None), state) is False
    assert checkpoint_calls == [True]
    assert state["377"]["last_command_comment_id"] == 42
