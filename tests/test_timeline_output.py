import sys
from argparse import Namespace
from collections.abc import Generator
from pathlib import Path

import pytest

import journalparser.common as common_module
from journalparser.common import Actions, EntryInfo, JournalParserCommon, JournalTransaction, TimelineEventInfo


class _DummyImage:
    def read(self, offset: int, size: int) -> bytes:
        _ = offset, size
        return b""

    def get_size(self) -> int:
        return 0

    def close(self) -> None:
        return


class _DummyParser(JournalParserCommon[JournalTransaction[EntryInfo], EntryInfo]):
    def _create_transaction(self, tid: int) -> JournalTransaction[EntryInfo]:
        return JournalTransaction(tid=tid)

    def infer_timeline_events(self) -> Generator[TimelineEventInfo, None, None]:
        yield TimelineEventInfo(
            transaction_id=1,
            action=Actions.CREATE_INODE,
            inode=12,
        )


def _build_args(output: str | None = None) -> Namespace:
    return Namespace(
        offset=0,
        debug=False,
        special_inodes=False,
        no_progress=False,
        output=output,
    )


def test_timeline_writes_stdout_when_output_is_not_set(capsys: pytest.CaptureFixture[str]) -> None:
    parser = _DummyParser(_DummyImage(), None, _build_args())

    parser.timeline()

    captured = capsys.readouterr()
    assert '"transaction_id": 1' in captured.out
    assert captured.err == ""


def test_timeline_writes_file_when_output_is_set(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output_file = tmp_path / "timeline.ndjson"
    parser = _DummyParser(_DummyImage(), None, _build_args(str(output_file)))

    parser.timeline()

    captured = capsys.readouterr()
    assert captured.out == ""
    assert output_file.exists()
    assert '"transaction_id": 1' in output_file.read_text(encoding="utf-8")


def test_progress_uses_yaspin_with_stderr_stream(monkeypatch: pytest.MonkeyPatch) -> None:
    parser = _DummyParser(_DummyImage(), None, _build_args("timeline.ndjson"))
    created: dict[str, object] = {}

    class _FakeYaspin:
        def __init__(self, _spinner: object, *, text: str, stream: object) -> None:
            created["text"] = text
            created["spinner"] = _spinner
            created["stream"] = stream
            self.text = text
            self.color = None

        def start(self) -> None:
            return

        def ok(self, _text: str) -> None:
            created["success_text"] = self.text

    monkeypatch.setattr(common_module, "yaspin", _FakeYaspin)

    progress = parser.progress("Generating timeline")
    progress.start()
    progress.succeed("Generated timeline (1 transactions)")

    assert created["text"] == "Generating timeline (0 item)"
    assert created["spinner"].frames == common_module.Spinners.dots.frames
    assert created["spinner"].interval == 200
    assert created["stream"] is sys.stderr
    assert created["success_text"] == "Generated timeline (1 transactions)"


def test_progress_is_disabled_when_no_progress_is_set() -> None:
    parser = _DummyParser(_DummyImage(), None, _build_args())
    parser.no_progress = True

    progress = parser.progress("Generating timeline")

    assert isinstance(progress, common_module.YaspinSpinner)
    assert isinstance(progress.backend, common_module.NoOpSpinner)


def test_progress_iter_updates_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    parser = _DummyParser(_DummyImage(), None, _build_args("timeline.ndjson"))
    snapshots: list[str] = []

    class _FakeYaspin:
        def __init__(self, _spinner: object, *, text: str, stream: object) -> None:
            self._text = text
            self.color = None
            self._stream = stream
            snapshots.append(text)

        @property
        def text(self) -> str:
            return self._text

        @text.setter
        def text(self, value: str) -> None:
            self._text = value
            snapshots.append(value)

        def start(self) -> None:
            return

        def ok(self, _text: str) -> None:
            snapshots.append(self._text)

    monkeypatch.setattr(common_module, "yaspin", _FakeYaspin)

    observed = list(parser.progress_iter([1, 2, 3], desc="Parsing log records", unit="record"))

    assert observed == [1, 2, 3]
    assert snapshots[0] == "Parsing log records (0/3 record)"
    assert "Parsing log records (3/3 record)" in snapshots


def test_nested_progress_is_suppressed(monkeypatch: pytest.MonkeyPatch) -> None:
    parser = _DummyParser(_DummyImage(), None, _build_args("timeline.ndjson"))
    created: list[str] = []

    class _FakeYaspin:
        def __init__(self, _spinner: object, *, text: str, stream: object) -> None:
            created.append(text)
            self.text = text
            self.color = None
            self._stream = stream

        def start(self) -> None:
            return

        def ok(self, _text: str) -> None:
            return

    monkeypatch.setattr(common_module, "yaspin", _FakeYaspin)

    outer = parser.progress("Outer", total=2)
    outer.start()
    inner = parser.progress("Inner", total=2)
    inner.start()
    inner.close()
    outer.close()

    assert created == ["Outer (0/2 item)"]
