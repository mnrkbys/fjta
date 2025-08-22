#
# Copyright 2025 Minoru Kobayashi <unknownbit@gmail.com> (@unkn0wnbit)
#
#    This file is part of Forensic Journal Timeline Analyzer (FJTA).
#    Usage or distribution of this code is subject to the terms of the Apache License, Version 2.0.
#

from argparse import Namespace
from pathlib import Path
from typing import BinaryIO, Self

import magic
import pyewf
import pytsk3
import pyvhdi
import pyvmdk
from construct import ConstError

from journalparser import ext4, xfs
from journalparser.common import DiskImgTypes, EWFImgInfo, FsTypes, ImageLike, RAWImgInfo, VHDIImgInfo, VMDKImgInfo
from journalparser.structs.xfs_structs import xfs_dsb

MAGIC_PATTERNS = {
    "RAW": r"DOS/MBR boot sector",
    "EWF": r"EWF/Expert Witness/EnCase",
    "VMDK": r"VMware",
    "VHDI": r"Microsoft Disk Image",
    "BLOCK": r"block special",
    "EXT4": r"Linux rev 1.0 ext4 filesystem data",
    "XFS": r"SGI XFS filesystem data",
}


class JournalParser:
    # Attribute annotations for static type checking
    img_info: pytsk3.Img_Info | EWFImgInfo | VMDKImgInfo | VHDIImgInfo | RAWImgInfo | BinaryIO | None
    fs_info: pytsk3.FS_Info | None
    journal_parser: ext4.JournalParserExt4 | xfs.JournalParserXfs

    def __new__(cls, img_file: str | Path, args: Namespace) -> Self | None:
        path = Path(img_file).expanduser().resolve()
        if not (path.is_file() or path.is_block_device()):
            return None

        magic_sig = cls._probe_magic(path)
        img_info, img_type = cls._wrap_image(path, magic_sig)
        if img_info is None:
            return None

        fs = cls._detect_fs(img_info, img_type, args)
        if fs == FsTypes.EXT4:
            try:
                fs_info = pytsk3.FS_Info(img_info, args.offset)
            except OSError:
                img_info.close()
                return None
            self = super().__new__(cls)
            self.img_info = img_info
            self.fs_info = fs_info
            self.journal_parser = ext4.JournalParserExt4(self.img_info, self.fs_info, args)
            return self

        if fs == FsTypes.XFS:
            self = super().__new__(cls)
            self.img_info = img_info
            self.fs_info = None
            self.journal_parser = xfs.JournalParserXfs(self.img_info, None, args)
            return self

        return None

    @staticmethod
    def _probe_magic(path: Path) -> str:
        return magic.from_file(str(path))

    @staticmethod
    def _wrap_image(path: Path, magic_sig: str) -> tuple[ImageLike | None, DiskImgTypes]:
        if magic_sig.startswith(MAGIC_PATTERNS["EWF"]):
            ewf_files = pyewf.glob(str(path))
            handle = pyewf.handle()
            handle.open(ewf_files)
            return EWFImgInfo(handle), DiskImgTypes.EWF
        if magic_sig.startswith(MAGIC_PATTERNS["VMDK"]):
            handle = pyvmdk.handle()
            handle.open(str(path))
            handle.open_extent_data_files()
            return VMDKImgInfo(handle), DiskImgTypes.VMDK
        if magic_sig.startswith(MAGIC_PATTERNS["VHDI"]):
            handle = pyvhdi.file()  # Doesn't pyvhdi have a handle method?
            handle.open(str(path))
            return VHDIImgInfo(handle), DiskImgTypes.VHDI
        if magic_sig.startswith((MAGIC_PATTERNS["RAW"], MAGIC_PATTERNS["BLOCK"], MAGIC_PATTERNS["EXT4"])):
            return pytsk3.Img_Info(str(path)), DiskImgTypes.RAW
        if magic_sig.startswith(MAGIC_PATTERNS["XFS"]):
            return RAWImgInfo(path), DiskImgTypes.RAW
        return None, DiskImgTypes.UNKNOWN

    @staticmethod
    def _detect_fs(img_info: ImageLike, img_type: DiskImgTypes, args: Namespace) -> FsTypes:
        # Try EXT4 via pytsk3
        if isinstance(img_info, pytsk3.Img_Info):
            try:
                fs_info = pytsk3.FS_Info(img_info, args.offset)
                if fs_info.info.ftype == pytsk3.TSK_FS_TYPE_EXT4:
                    return FsTypes.EXT4
            except OSError:
                pass
        # Probe XFS manually
        try:
            first = img_info.read(args.offset, 0x200)
            xfs_dsb.parse(first)
        except (OSError, ConstError):
            return FsTypes.UNKNOWN
        else:
            return FsTypes.XFS

    def _cleanup(self) -> None:
        self.img_info.close()
        self.img_info = None
        self.fs_info = None

    def parse_journal(self) -> None:
        self.journal_parser.parse_journal()

    def timeline(self) -> None:
        self.journal_parser.timeline()
