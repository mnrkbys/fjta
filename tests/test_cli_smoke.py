import importlib
from argparse import Namespace
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest

import fjta


def _build_args(image: str | None = None) -> Namespace:
    return Namespace(
        image=image,
        offset=0,
        debug=False,
        special_inodes=False,
        no_progress=False,
        output=None,
    )


def test_parse_arguments_defaults() -> None:
    args = fjta.parse_arguments([])
    assert args.image is None
    assert args.offset == 0
    assert args.debug is False
    assert args.special_inodes is False
    assert args.no_progress is False
    assert args.output is None


def test_parse_arguments_output_path() -> None:
    args = fjta.parse_arguments(["--output", "timeline.ndjson"])
    assert args.output == "timeline.ndjson"


def test_parse_arguments_version_exits_zero() -> None:
    with pytest.raises(SystemExit) as exc_info:
        _ = fjta.parse_arguments(["--version"])
    assert exc_info.value.code == 0


def test_run_without_image_returns_error_and_writes_stderr() -> None:
    args = _build_args(image=None)
    err_stream = StringIO()

    exit_code = fjta.run(args, err_stream=err_stream)

    assert exit_code == 1
    assert "ERROR: Please specify a disk image file." in err_stream.getvalue()


def test_main_without_image_returns_error(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = fjta.main([])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "ERROR: Please specify a disk image file." in captured.err


def test_run_reports_missing_dependency(monkeypatch: pytest.MonkeyPatch) -> None:
    args = _build_args(image="dummy.img")
    err_stream = StringIO()

    def _raise_module_not_found(_name: str) -> None:
        raise ModuleNotFoundError("No module named 'pytsk3'", name="pytsk3")

    monkeypatch.setattr(importlib, "import_module", _raise_module_not_found)

    exit_code = fjta.run(args, err_stream=err_stream)

    assert exit_code == 1
    assert "ERROR: Required dependency is not available: pytsk3" in err_stream.getvalue()


def test_run_warns_when_output_file_already_exists(tmp_path: Path) -> None:
    args = _build_args(image="dummy.img")
    output_file = tmp_path / "timeline.ndjson"
    output_file.write_text("existing\n", encoding="utf-8")
    args.output = str(output_file)
    err_stream = StringIO()

    exit_code = fjta.run(args, err_stream=err_stream)

    assert exit_code == 1
    assert f"WARNING: Output file already exists: {output_file}" in err_stream.getvalue()


def test_run_propagates_output_and_executes_parser(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    args = _build_args(image="dummy.img")
    output_file = tmp_path / "timeline.ndjson"
    args.output = str(output_file)
    err_stream = StringIO()
    called: dict[str, object] = {}

    class _DummyJournalParser:
        def __init__(self, image: str, cli_args: Namespace) -> None:
            called["image"] = image
            called["output"] = cli_args.output

        def parse_journal(self) -> None:
            called["parse_journal"] = True

        def timeline(self) -> None:
            called["timeline"] = True
            output_file.write_text('{"transaction_id": 1}\n', encoding="utf-8")

    fake_module = SimpleNamespace(
        JournalParser=_DummyJournalParser,
        UnsupportedImageError=ValueError,
        UnsupportedFilesystemError=ValueError,
    )
    monkeypatch.setattr(importlib, "import_module", lambda _name: fake_module)

    exit_code = fjta.run(args, err_stream=err_stream)

    assert exit_code == 0
    assert err_stream.getvalue() == ""
    assert called["image"] == "dummy.img"
    assert called["output"] == str(output_file)
    assert called["parse_journal"] is True
    assert called["timeline"] is True
    assert output_file.exists()
