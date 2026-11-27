from __future__ import annotations

from pathlib import Path

from pipeline.calibrate import _append_history


def test_append_history_is_idempotent(tmp_path: Path) -> None:
    history = tmp_path / "history.jsonl"
    _append_history(history, '{"a": 1}')
    _append_history(history, '{"a": 1}')
    assert history.read_text().splitlines() == ['{"a": 1}']

    _append_history(history, '{"a": 2}')
    assert history.read_text().splitlines() == ['{"a": 1}', '{"a": 2}']
