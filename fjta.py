#!/usr/bin/env python3
#
# fjta.py
# Forensic Journal Timeline Analyzer (FJTA) can parse and analyze journal log of EXT4 and XFS file systems.
#
# Copyright 2024 Minoru Kobayashi <unknownbit@gmail.com> (@unkn0wnbit)
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
import os
import sys

from journalparser import journalparser

VERSION = "20250225"


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="Forensic Journal Timeline Analyzer (FJTA)",
        description="Generate a timeline of file system events from the journal log.",
    )
    parser.add_argument(
        "-i",
        "--image",
        type=str,
        help="Path to a disk image file.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Enable debug mode. (Default: False)",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )
    return parser.parse_args()


def main() -> None:
    if not args.image:
        print("Please specify a disk image file.")
        sys.exit(1)

    full_path = os.path.abspath(os.path.expanduser(args.image))
    parser = journalparser.JournalParser(full_path)
    parser.parse_journal()
    parser.timeline()


if __name__ == "__main__":
    args = parse_arguments()
    main()
