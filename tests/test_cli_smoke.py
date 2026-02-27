from argparse import Namespace
from io import StringIO

import pytest

import fjta


def _build_args(image: str | None = None) -> Namespace:
    return Namespace(
        image=image,
        offset=0,
        debug=False,
        special_inodes=False,
        no_progress=False,
    )


def test_parse_arguments_defaults() -> None:
    args = fjta.parse_arguments([])
    assert args.image is None
    assert args.offset == 0
    assert args.debug is False
    assert args.special_inodes is False
    assert args.no_progress is False


def test_parse_arguments_version_exits_zero() -> None:
    with pytest.raises(SystemExit) as exc_info:
        _ = fjta.parse_arguments(["--version"])
    assert exc_info.value.code == 0


def test_run_without_image_returns_error_and_writes_stderr() -> None:
    args = _build_args(image=None)
    err_stream = StringIO()

    exit_code = fjta.run(args, err_stream=err_stream)

    assert exit_code == 1
    assert "Please specify a disk image file." in err_stream.getvalue()


def test_main_without_image_returns_error(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = fjta.main([])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Please specify a disk image file." in captured.err
