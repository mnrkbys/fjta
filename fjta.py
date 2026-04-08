#!/usr/bin/env python3
#
# fjta.py
# Forensic Journal Timeline Analyzer (FJTA) can parse and analyze journal log of ext4 and XFS file systems.
#
# Copyright 2025-2026 Minoru Kobayashi <unknownbit@gmail.com> (@unkn0wnbit)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import argparse
import importlib
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from journalparser.version import VERSION


def emit_diagnostic(message: str, stream: TextIO, level: str = "ERROR") -> None:
    print(f"{level}: {message}", file=stream)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a timeline of file system activities from the filesystem journal log.",
    )
    parser.add_argument(
        "-i",
        "--image",
        type=str,
        help="Path to a disk image file.",
    )
    parser.add_argument(
        "-s",
        "--offset",
        type=int,
        default=0,
        help="Filesystem offset in bytes. (Default: 0)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode. (Default: False)",
    )
    parser.add_argument(
        "--special-inodes",
        action="store_true",
        help="Include special inodes in the timeline. (Default: False)",
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Hide progress bars. (Default: False)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Write timeline output to a file instead of stdout.",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )
    return parser


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def run(args: argparse.Namespace, err_stream: TextIO | None = None) -> int:
    target_err = err_stream if err_stream is not None else sys.stderr

    if not args.image:
        emit_diagnostic("Please specify a disk image file.", target_err)
        return 1

    if args.output:
        output_path = Path(args.output).expanduser()
        if output_path.exists():
            emit_diagnostic(f"Output file already exists: {output_path}", target_err, level="WARNING")
            return 1

    try:
        jp_module = importlib.import_module("journalparser.journalparser")
    except ModuleNotFoundError as err:
        missing_name = err.name or "unknown module"
        emit_diagnostic(f"Required dependency is not available: {missing_name}", target_err)
        return 1

    unsupported_image_error = jp_module.UnsupportedImageError
    unsupported_filesystem_error = jp_module.UnsupportedFilesystemError

    try:
        parser = jp_module.JournalParser(args.image, args)
    except (FileNotFoundError, ValueError, unsupported_image_error, unsupported_filesystem_error) as err:
        emit_diagnostic(str(err), target_err)
        return 1
    else:
        parser.parse_journal()
        parser.timeline()
        return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_arguments(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
