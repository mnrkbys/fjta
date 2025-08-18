#
# Copyright 2025 Minoru Kobayashi <unknownbit@gmail.com> (@unkn0wnbit)
#
#    This file is part of Forensic Journal Timeline Analyzer (FJTA).
#    Usage or distribution of this code is subject to the terms of the Apache License, Version 2.0.
#

import os
import sys
from argparse import Namespace
from pathlib import Path
from typing import BinaryIO, Self

import pytsk3
from construct import ConstError

from journalparser import ext4, xfs
from journalparser.structs.xfs_structs import xfs_dsb


class JournalParser:
    # Attribute annotations for static type checking
    img_info: pytsk3.Img_Info | BinaryIO
    fs_info: pytsk3.FS_Info | None
    journal_parser: ext4.JournalParserExt4 | xfs.JournalParserXfs

    def __new__(cls, img_file: str | Path, args: Namespace) -> Self | None:
        full_path = Path(img_file).expanduser().resolve()
        if not (full_path.is_file() or full_path.is_block_device()):
            print(f"Error: The specified file '{full_path}' is neither a regular file nor block device.", file=sys.stderr)
            return None

        # Try pytsk3 first (EXT4 supported, XFS maybe in future)
        try:
            img_info = pytsk3.Img_Info(str(full_path))
            fs_info = pytsk3.FS_Info(img_info, args.offset)
            if fs_info.info.ftype == pytsk3.TSK_FS_TYPE_EXT4:
                self = super().__new__(cls)
                self.img_info = img_info
                self.fs_info = fs_info
                self.journal_parser = ext4.JournalParserExt4(self.img_info, self.fs_info, args)
                return self
        except OSError:
            # Fall through to raw XFS detection
            pass
        else:
            # If filesystem recognized but not EXT4 (and not XFS yet) => unsupported
            return None

        # Raw image fallback (for XFS)
        try:
            img_info = Path(full_path).open("rb")
            img_info.seek(args.offset, os.SEEK_SET)
            first_sector = img_info.read(0x200)
            img_info.seek(args.offset, os.SEEK_SET)
            try:
                # Probe XFS superblock
                if xfs_dsb.parse(first_sector):
                    self = super().__new__(cls)
                    self.img_info = img_info
                    self.fs_info = None
                    self.journal_parser = xfs.JournalParserXfs(self.img_info, self.fs_info, args)
                    return self
            except ConstError:
                pass
        except (OSError, ConstError):
            return None
        else:
            return None

    def parse_journal(self) -> None:
        self.journal_parser.parse_journal()

    def timeline(self) -> None:
        self.journal_parser.timeline()
