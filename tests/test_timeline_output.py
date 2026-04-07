import sys
from argparse import Namespace
from collections.abc import Generator

import journalparser.common as common_module
from journalparser.common import Actions, EntryInfo, JournalParserCommon, JournalTransaction, TimelineEventInfo


class _DummyImage:
    def read(self, offset: int, size: int) -> bytes:
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


def test_timeline_writes_stdout_when_output_is_not_set(capsys) -> None:
    parser = _DummyParser(_DummyImage(), None, _build_args())

    parser.timeline()

    captured = capsys.readouterr()
    assert '"transaction_id": 1' in captured.out
    assert captured.err == ""


def test_timeline_writes_file_when_output_is_set(tmp_path, capsys) -> None:
    output_file = tmp_path / "timeline.ndjson"
    parser = _DummyParser(_DummyImage(), None, _build_args(str(output_file)))

    parser.timeline()

    captured = capsys.readouterr()
    assert captured.out == ""
    assert output_file.exists()
    assert '"transaction_id": 1' in output_file.read_text(encoding="utf-8")


def test_progress_uses_halo_with_stderr_stream(monkeypatch) -> None:
    parser = _DummyParser(_DummyImage(), None, _build_args("timeline.ndjson"))
    created: dict[str, object] = {}

    class _FakeHalo:
        def __init__(self, *, text: str, spinner: str, stream) -> None:
            created["text"] = text
            created["spinner"] = spinner
            created["stream"] = stream

        def start(self) -> None:
            return

        def succeed(self, text: str | None = None) -> None:
            created["success_text"] = text

    monkeypatch.setattr(common_module, "Halo", _FakeHalo)

    progress = parser.progress("Generating timeline")
    progress.start()
    progress.succeed("Generated timeline (1 transactions)")

    assert created["text"] == "Generating timeline (0 item)"
    assert created["spinner"] == "dots"
    assert created["stream"] is sys.stderr
    assert created["success_text"] == "Generated timeline (1 transactions)"


def test_progress_is_disabled_when_no_progress_is_set() -> None:
    parser = _DummyParser(_DummyImage(), None, _build_args())
    parser.no_progress = True

    progress = parser.progress("Generating timeline")

    assert isinstance(progress, common_module.HaloProgress)
    assert isinstance(progress._spinner, common_module.NoOpSpinner)


def test_progress_iter_updates_counts(monkeypatch) -> None:
    parser = _DummyParser(_DummyImage(), None, _build_args("timeline.ndjson"))
    snapshots: list[str] = []

    class _FakeHalo:
        def __init__(self, *, text: str, spinner: str, stream) -> None:
            self._text = text
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

        def succeed(self, text: str | None = None) -> None:
            if text is not None:
                snapshots.append(text)

    monkeypatch.setattr(common_module, "Halo", _FakeHalo)

    observed = list(parser.progress_iter([1, 2, 3], desc="Parsing log records", unit="record"))

    assert observed == [1, 2, 3]
    assert snapshots[0] == "Parsing log records (0/3 record)"
    assert "Parsing log records (3/3 record)" in snapshots


def test_nested_progress_is_suppressed(monkeypatch) -> None:
    parser = _DummyParser(_DummyImage(), None, _build_args("timeline.ndjson"))
    created: list[str] = []

    class _FakeHalo:
        def __init__(self, *, text: str, spinner: str, stream) -> None:
            created.append(text)

        def start(self) -> None:
            return

        def succeed(self, text: str | None = None) -> None:
            return

    monkeypatch.setattr(common_module, "Halo", _FakeHalo)

    outer = parser.progress("Outer", total=2)
    outer.start()
    inner = parser.progress("Inner", total=2)
    inner.start()
    inner.close()
    outer.close()

    assert created == ["Outer (0/2 item)"]
