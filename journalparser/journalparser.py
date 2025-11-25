#
# Copyright 2025 Minoru Kobayashi <unknownbit@gmail.com> (@unkn0wnbit)
#
#    This file is part of Forensic Journal Timeline Analyzer (FJTA).
#    Usage or distribution of this code is subject to the terms of the Apache License, Version 2.0.
#

import contextlib
from argparse import Namespace
from pathlib import Path
from typing import Self

import magic
import pyewf
import pytsk3
import pyvhdi
import pyvmdk
from construct import ConstError

from journalparser import ext4, xfs
from journalparser.common import DiskImgTypes, EWFImgInfo, FsTypes, ImageLike, RAWImgInfo, VHDIImgInfo, VMDKImgInfo
from journalparser.structs.ext4_structs import journal_header_s
from journalparser.structs.xfs_structs import xfs_dsb, xlog_rec_header

MAGIC_PATTERNS = {
    "RAW": r"DOS/MBR boot sector",
    "EWF": r"EWF/Expert Witness/EnCase",
    "VMDK": r"VMware",
    "VHDI": r"Microsoft Disk Image",
    "BLOCK": r"block special",
    "EXT4": r"Linux rev 1.0 ext4 filesystem data",
    "XFS": r"SGI XFS filesystem data",
    "JOURNAL": r"data",
}


class UnsupportedImageError(ValueError):
    """Unsupported disk image format."""


class UnsupportedFilesystemError(UnsupportedImageError):
    """Unsupported filesystem (not EXT4/XFS)."""


class JournalParser:
    # Attribute annotations for static type checking
    # img_info: pytsk3.Img_Info | EWFImgInfo | VMDKImgInfo | VHDIImgInfo | RAWImgInfo | BinaryIO | None
    img_info: ImageLike
    fs_info: pytsk3.FS_Info | None
    journal_parser: ext4.JournalParserExt4 | xfs.JournalParserXfs

    def __new__(cls, img_file: str | Path, args: Namespace) -> Self:
        path = Path(img_file).expanduser().resolve()
        if not path.exists():
            msg = f"File does not exist: {img_file}"
            raise FileNotFoundError(msg)
        if not (path.is_file() or path.is_block_device()):
            msg = f"File must be a regular file or block device: {img_file}"
            raise ValueError(msg)

        magic_sig = cls._probe_magic(path)
        img_info, img_type = cls._detect_image(path, magic_sig)
        if img_info is None:
            msg = f"Unsupported disk image format: {path}"
            raise UnsupportedImageError(msg)

        fs = cls._detect_fs(img_info, img_type, args)
        self = super().__new__(cls)
        self.img_info = img_info

        if fs == FsTypes.EXT4:
            self.fs_info = pytsk3.FS_Info(img_info, args.offset)
            self.journal_parser = ext4.JournalParserExt4(self.img_info, self.fs_info, args)
            return self

        if fs == FsTypes.XFS:
            self.fs_info = None
            self.journal_parser = xfs.JournalParserXfs(self.img_info, None, args)
            return self

        if fs == FsTypes.EXPORTED_EXT4_JOURNAL:
            self.fs_info = None
            self.journal_parser = ext4.JournalParserExt4(self.img_info, None, args, FsTypes.EXPORTED_EXT4_JOURNAL)
            self.journal_parser.dumpe2fs_path = path.with_suffix(".dumpe2fs")
            if not (self.journal_parser.dumpe2fs_path.exists() and self.journal_parser.dumpe2fs_path.is_file()):
                msg = f"dumpe2fs file not found: {self.journal_parser.dumpe2fs_path}"
                raise FileNotFoundError(msg)
            return self

        if fs == FsTypes.EXPORTED_XFS_JOURNAL:
            self.fs_info = None
            self.journal_parser = xfs.JournalParserXfs(self.img_info, None, args, FsTypes.EXPORTED_XFS_JOURNAL)
            self.journal_parser.xfs_info_path = path.with_suffix(".xfs_info")
            if not (self.journal_parser.xfs_info_path.exists() and self.journal_parser.xfs_info_path.is_file()):
                msg = f"xfs_info file not found: {self.journal_parser.xfs_info_path}"
                raise FileNotFoundError(msg)
            return self

        with contextlib.suppress(Exception):
            img_info.close()
        msg = f"Unsupported filesystem: {path}"
        raise UnsupportedFilesystemError(msg)

    @staticmethod
    def _probe_magic(path: Path) -> str:
        return magic.from_file(str(path))

    @staticmethod
    def _detect_image(path: Path, magic_sig: str) -> tuple[ImageLike | None, DiskImgTypes]:
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

        if magic_sig.startswith(MAGIC_PATTERNS["JOURNAL"]):
            return RAWImgInfo(path), DiskImgTypes.EXPORTED_JOURNAL

        return None, DiskImgTypes.UNKNOWN

    @staticmethod
    def _detect_fs_img(img_info: ImageLike, args: Namespace) -> FsTypes:
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
            _ = xfs_dsb.parse(first)
        except (OSError, ConstError):
            return FsTypes.UNKNOWN
        else:
            return FsTypes.XFS

    @staticmethod
    def _detect_fs_exported_journal(img_info: ImageLike) -> FsTypes:
        try:
            _ = journal_header_s.parse(img_info.read(0, journal_header_s.sizeof()))
        except ConstError:
            try:
                _ = xlog_rec_header.parse(img_info.read(0, xlog_rec_header.sizeof()))
            except ConstError:
                return FsTypes.UNKNOWN
            else:
                return FsTypes.EXPORTED_XFS_JOURNAL
        else:
            return FsTypes.EXPORTED_EXT4_JOURNAL

    @classmethod
    def _detect_fs(cls, img_info: ImageLike, img_type: DiskImgTypes, args: Namespace) -> FsTypes:
        if img_type != DiskImgTypes.EXPORTED_JOURNAL:
            return cls._detect_fs_img(img_info, args)

        if img_type == DiskImgTypes.EXPORTED_JOURNAL:
            return cls._detect_fs_exported_journal(img_info)

        return FsTypes.UNKNOWN

    def _cleanup(self) -> None:
        self.img_info.close()
        self.img_info = None
        self.fs_info = None

    def parse_journal(self) -> None:
        self.journal_parser.parse_journal()

    def timeline(self) -> None:
        self.journal_parser.timeline()
