#
# Copyright 2025 Minoru Kobayashi <unknownbit@gmail.com> (@unkn0wnbit)
#
#    This file is part of Forensic Journal Timeline Analyzer (FJTA).
#    Usage or distribution of this code is subject to the terms of the Apache License, Version 2.0.
#

import sys
from argparse import Namespace
from pathlib import Path

import pytsk3

from journalparser import ext4, xfs


class JournalParser:
    def __init__(self, img_file: str | Path, args: Namespace) -> None:
        full_path = Path(img_file).expanduser().resolve()
        if not (full_path.is_file() or full_path.is_block_device()):
            print(f"Error: The specified file '{full_path}' is neither a regular file nor block device.", file=sys.stderr)
            sys.exit(1)
        self.img_info = pytsk3.Img_Info(str(full_path))
        self.fs_info = pytsk3.FS_Info(self.img_info, args.offset)
        if self.fs_info.info.ftype == pytsk3.TSK_FS_TYPE_EXT4:
            self.journal_parser = ext4.JournalParserExt4(self.img_info, self.fs_info, args)
        elif self.fs_info.info.ftype == pytsk3.TSK_FS_TYPE_XFS:  # pytsk3.TSK_FS_TYPE_XFS = 0x80000
            self.journal_parser = xfs.JournalParserXfs(self.img_info, self.fs_info, args)
        else:
            msg = "Unsupported file system is contained."
            raise TypeError(msg)

    def parse_journal(self) -> None:
        self.journal_parser.parse_journal()

    def timeline(self) -> None:
        self.journal_parser.timeline()
