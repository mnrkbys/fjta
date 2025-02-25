#
# Copyright 2024 Minoru Kobayashi <unknownbit@gmail.com> (@unkn0wnbit)
#
#    This file is part of Forensic Journal Timeline Analyzer (FJTA).
#    Usage or distribution of this code is subject to the terms of the Apache License, Version 2.0.
#

# References:
# https://www.kernel.org/pub/linux/utils/fs/xfs/docs/xfs_filesystem_structure.pdf
# https://docs.kernel.org/filesystems/xfs/index.html
# https://blogs.oracle.com/linux/post/formatting-an-xfs-filesystem
# https://github.com/libyal/libfsxfs/blob/main/documentation/X%20File%20System%20(XFS).asciidoc
# https://righteousit.com/2018/05/21/xfs-part-1-superblock/
# https://righteousit.com/2018/05/23/xfs-part-2-inodes/
# https://righteousit.com/2018/05/25/xfs-part-3-short-form-directories/
# https://righteousit.com/2018/05/31/xfs-part-4-block-directories/
# https://righteousit.com/2018/06/06/xfs-part-5-multi-block-directories/
# https://righteousit.com/2022/01/13/xfs-part-6-btree-directories/
# https://righteousit.com/2024/07/09/recovering-deleted-files-in-xfs/
# https://righteousit.com/wp-content/uploads/2024/04/xfsbitbybit.pdf
# https://righteousit.com/wp-content/uploads/2024/04/xfs_db-ftw.pdf
# https://righteousit.com/wp-content/uploads/2024/04/comfycon.pptx
# https://digikogu.taltech.ee/et/Download/d8bca853-02d7-463f-b83c-048d4758af12

import copy
import json
from collections.abc import Generator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntEnum, auto

import pytsk3
from construct import Container, Int32ub, Struct

from .common import Actions, EntryInfo, ExtendedAttribute, FileTypes, JournalParserCommon, JournalTransaction, TimelineEventInfo
from .structs import xfs_structs
from .structs.xfs_structs import (
    XfsBlft,
    xfs_attr_sf_entry,
    xfs_attr_sf_hdr,
    xfs_buf_log_format_be,
    xfs_buf_log_format_le,
    xfs_dinode_core_be,
    xfs_dinode_core_le,
    xfs_dir2_data_entry,
    xfs_dir2_sf_entry_4,
    xfs_dir2_sf_entry_8,
    xfs_dir2_sf_hdr_4,
    xfs_dir2_sf_hdr_8,
    xfs_dir3_data_hdr,
    xfs_dsb,
    xfs_inode_log_format_64_be,
    xfs_inode_log_format_64_le,
    xfs_log_item_be,
    xfs_log_item_le,
    xfs_trans_header_be,
    xfs_trans_header_le,
    xlog_op_header,
    xlog_rec_header,
    xsf_dir2_sf_hdr_x,
)


@dataclass(frozen=True)
class XfsLogOperation:
    op_header: Container
    item_data: bytes


@dataclass(frozen=True)
class SfDirEntry:
    inode_num: int = 0
    name: str = ""
    file_type: int = FileTypes.UNKNOWN

    def __hash__(self) -> int:
        return hash((self.inode_num, self.name, self.file_type))


class TransState(IntEnum):
    UNKNOWN = auto()
    START_TRANS = auto()
    TRANS_DESC = auto()
    INODE_UPDATE = auto()
    INODE_CORE = auto()
    INODE_DFORK = auto()
    INODE_AFORK = auto()
    INODE_CREATION = auto()
    EATTRS_UPDATE = auto()


@dataclass
class JournalTransactionXfs(JournalTransaction):
    record_len: int = 0
    record_format: int = 0
    trans_state = TransState.UNKNOWN
    sf_dir_entries: dict[int, list[SfDirEntry]] = field(default_factory=dict)  # dict[dir_inode, list[SfDirEntry]]
    block_directory_entries: dict[int, list[EntryInfo]] = field(default_factory=dict)  # dict[]

    def set_dir_inode(self, inode_num: int, dir_inode_num: int) -> None:
        if not self.entries.get(inode_num):
            self.entries[inode_num] = EntryInfo()
        self.entries[inode_num].dir_inode = dir_inode_num

    def set_parent_inode(self, inode_num: int, parent_inode_num: int) -> None:
        if not self.entries.get(inode_num):
            self.entries[inode_num] = EntryInfo()
        self.entries[inode_num].parent_inode = parent_inode_num

    @staticmethod
    def _convert_to_epoch(seconds: int) -> int:
        base_datetime = datetime(1901, 12, 13, 20, 45, 52, tzinfo=UTC)  # XFS starts from 1901-12-13 20:45:52
        unix_epoch = datetime(1970, 1, 1, 0, 0, 0, tzinfo=UTC)
        delta = unix_epoch - base_datetime
        seconds -= int(delta.total_seconds())
        return seconds

    @classmethod
    def _split_nanoseconds(cls, nanoseconds: int) -> tuple[int, int]:
        seconds = nanoseconds // 1_000_000_000
        nanoseconds_remainder = nanoseconds % 1_000_000_000
        seconds = cls._convert_to_epoch(seconds)
        return seconds, nanoseconds_remainder

    def set_inode_info(self, inode_num: int, inode: Container, eattrs: list[ExtendedAttribute]) -> None:
        spectial_inodes = {
            128: "Root directory",
        }

        if not self.entries.get(inode_num):
            self.entries[inode_num] = EntryInfo()
        entry = self.entries[inode_num]
        entry.inode = inode_num
        if spectial_inodes.get(inode_num):
            entry.name.append(spectial_inodes[inode_num])
        match inode.di_mode & 0xF000:
            case xfs_structs.S_IFREG:
                entry.file_type = FileTypes.REGULAR_FILE
            case xfs_structs.S_IFDIR:
                entry.file_type = FileTypes.DIRECTORY
            case xfs_structs.S_IFCHR:
                entry.file_type = FileTypes.CHARACTER_DEVICE
            case xfs_structs.S_IFBLK:
                entry.file_type = FileTypes.BLOCK_DEVICE
            case xfs_structs.S_IFIFO:
                entry.file_type = FileTypes.FIFO
            case xfs_structs.S_IFSOCK:
                entry.file_type = FileTypes.SOCKET
            case xfs_structs.S_IFLNK:
                entry.file_type = FileTypes.SYMBOLIC_LINK
                # TODO: Need to set the target of the symbolic link
                entry.symlink_target = "dummy_symlink_target"
        entry.mode = inode.di_mode & 0o7777  # Remove file type bits
        entry.uid = inode.di_uid
        entry.gid = inode.di_gid
        entry.size = inode.di_size
        if inode.di_flags2 & xfs_structs.XFS_DIFLAG2_BIGTIME:
            entry.atime, entry.atime_nanoseconds = self._split_nanoseconds(inode.di_atime.bigtime)
            entry.ctime, entry.ctime_nanoseconds = self._split_nanoseconds(inode.di_ctime.bigtime)
            entry.mtime, entry.mtime_nanoseconds = self._split_nanoseconds(inode.di_mtime.bigtime)
            entry.crtime, entry.crtime_nanoseconds = self._split_nanoseconds(inode.di_crtime.bigtime)
        else:
            entry.atime = self._convert_to_epoch(inode.di_atime.legacy.t_sec)
            entry.atime_nanoseconds = inode.di_atime.legacy.t_nsec
            entry.ctime = self._convert_to_epoch(inode.di_ctime.legacy.t_sec)
            entry.ctime_nanoseconds = inode.di_ctime.legacy.t_nsec
            entry.mtime = self._convert_to_epoch(inode.di_mtime.legacy.t_sec)
            entry.mtime_nanoseconds = inode.di_mtime.legacy.t_nsec
            entry.crtime = self._convert_to_epoch(inode.di_crtime.legacy.t_sec)
            entry.crtime_nanoseconds = inode.di_crtime.legacy.t_nsec
        entry.flags = inode.di_flags
        entry.extended_attributes = eattrs

    def set_dir_entry_info(self, inode_num: int, dir_entry: Container) -> None:
        if not self.entries.get(inode_num):
            self.entries[inode_num] = EntryInfo()
        entry = self.entries[inode_num]
        if entry.inode == 0:
            entry.inode = inode_num
        if not entry.name or dir_entry.name.decode("utf-8") not in entry.name:
            entry.name.append(dir_entry.name.decode("utf-8"))

        if entry.file_type == FileTypes.UNKNOWN:
            match dir_entry.ftype:
                case xfs_structs.XFS_DIR3_FT_UNKNOWN:
                    entry.file_type = FileTypes.UNKNOWN
                case xfs_structs.XFS_DIR3_FT_REG_FILE:
                    entry.file_type = FileTypes.REGULAR_FILE
                case xfs_structs.XFS_DIR3_FT_DIR:
                    entry.file_type = FileTypes.DIRECTORY
                case xfs_structs.XFS_DIR3_FT_CHRDEV:
                    entry.file_type = FileTypes.CHARACTER_DEVICE
                case xfs_structs.XFS_DIR3_FT_BLKDEV:
                    entry.file_type = FileTypes.BLOCK_DEVICE
                case xfs_structs.XFS_DIR3_FT_FIFO:
                    entry.file_type = FileTypes.FIFO
                case xfs_structs.XFS_DIR3_FT_SOCK:
                    entry.file_type = FileTypes.SOCKET
                case xfs_structs.XFS_DIR3_FT_SYMLINK:
                    entry.file_type = FileTypes.SYMBOLIC_LINK


class LogRecordNotFoundError(Exception):
    pass


class JournalParserXfs(JournalParserCommon[JournalTransactionXfs, EntryInfo]):
    def __init__(self, img_info: pytsk3.Img_Info, fs_info: pytsk3.FS_Info) -> None:
        super().__init__(img_info, fs_info)

    def _convert_block_to_absaddr(self, block_num: int, log2val: int) -> int:
        if self.sb_agblocks:
            agno = block_num >> log2val
            rel_offset = block_num & ((1 << log2val) - 1)
            return (agno * self.sb_agblocks + rel_offset) * self.block_size
        return 0

    def _create_transaction(self, tid: int) -> JournalTransactionXfs:
        return JournalTransactionXfs(tid)

    def _parse_xfs_superblock(self) -> None:
        self.xfs_superblock = xfs_dsb.parse(self.img_info.read(0x0, 0x200))
        self.sb_agblocks = self.xfs_superblock.sb_agblocks
        self.sb_logstart_addr = self._convert_block_to_absaddr(self.xfs_superblock.sb_logstart, self.xfs_superblock.sb_agblklog)
        self.sb_rootino = self.xfs_superblock.sb_rootino
        self.sb_inodesize = self.xfs_superblock.sb_inodesize

    def _find_first_log_record(self) -> int:
        xfs_sb = self.xfs_superblock
        for log_rec_addr in range(self.sb_logstart_addr, self.sb_logstart_addr + xfs_sb.sb_logblocks * self.block_size):
            data = self.img_info.read(log_rec_addr, self.block_size)
            xlog_record_header = xlog_rec_header.parse(data)
            if xlog_record_header.h_magicno == xfs_structs.XLOG_HEADER_MAGIC:
                return log_rec_addr
            log_rec_addr += 4
        return -1

    def _read_journal_data(self, journal_addr: int, read_len: int = 4096) -> bytes:
        xfs_sb = self.xfs_superblock
        if journal_addr < self.sb_logstart_addr:
            return b""
        # journal_data_len = (xfs_sb.sb_logblocks - xfs_sb.sb_logstart) * self.block_size
        journal_data_len = xfs_sb.sb_logblocks * self.block_size
        read_pos = (journal_addr - self.sb_logstart_addr) % journal_data_len
        if self.sb_logstart_addr + read_pos + read_len > self.sb_logstart_addr + journal_data_len:
            read_len_1 = self.sb_logstart_addr + journal_data_len - self.sb_logstart_addr + read_pos
            read_len_2 = read_len - read_len_1
            data_1 = self.img_info.read(self.sb_logstart_addr + read_pos, read_len_1)
            data_2 = self.img_info.read(self.sb_logstart_addr, read_len_2)
            return data_1 + data_2
        return self.img_info.read(self.sb_logstart_addr + read_pos, read_len)

    @staticmethod
    def _find_next_xlog_op_header(tid: int, data: int) -> int:
        idx = 0
        tid_stuct = Struct("tid" / Int32ub)
        while idx < len(data):
            if tid_stuct.parse(data[idx : idx + 4]).tid == tid:
                return idx
            idx += 4
        return 0

    def _parse_log_operations(self, data: bytes) -> list[XfsLogOperation]:
        idx = 0
        log_ops: list[XfsLogOperation] = []
        while idx < len(data):
            op_header = xlog_op_header.parse(data[idx : idx + xlog_op_header.sizeof()])
            if op_header.oh_tid == 0:
                break
            if op_header.oh_len == 1:  # Why is oh_len 1?
                if guessed_oh_len := self._find_next_xlog_op_header(op_header.oh_tid, data[idx + xlog_op_header.sizeof() :]):
                    # print(f"oh_len = 1, guessed_oh_len = {guessed_oh_len}")
                    op_header.oh_len = guessed_oh_len
                else:
                    op_header.oh_len = 0x18  # I have confirmed that the actual length is 0x18. However, different lengths may be used in other cases.
            item_data = data[idx + xlog_op_header.sizeof() : idx + xlog_op_header.sizeof() + op_header.oh_len]
            log_ops.append(XfsLogOperation(op_header, item_data))
            idx += xlog_op_header.sizeof() + op_header.oh_len
            # if op_header.oh_flags & xfs_structs.XLOG_COMMIT_TRANS:
            #     break
        return log_ops

    # def _parse_log_items(self, log_op: XfsLogOperation, record_format: int) -> None:
    #     print("Log Operation Header:")
    #     print(log_op.op_header)
    #     xfs_trans_header = xfs_log_item = None
    #     match record_format:
    #         case xfs_structs.XLOG_FMT_UNKNOWN:
    #             print("Unknown log record format does not supported.")
    #             return
    #         case xfs_structs.XLOG_FMT_LINUX_LE:
    #             xfs_trans_header = xfs_trans_header_le
    #             xfs_log_item = xfs_log_item_le
    #         case xfs_structs.XLOG_FMT_LINUX_BE | xfs_structs.XLOG_FMT_IRIX_BE:
    #             xfs_trans_header = xfs_trans_header_be
    #             xfs_log_item = xfs_log_item_be

    #     if xfs_trans_header and xfs_log_item:
    #         try:
    #             if log_op.item_data:
    #                 trans_header = xfs_trans_header.parse(log_op.item_data)
    #                 print("Transaction Header:")
    #                 print(trans_header)
    #         except ConstError:
    #             log_item = xfs_log_item.parse(log_op.item_data)
    #             print("Log Item:")
    #             print(log_item)

    # def _parse_directory_entries_shortform(self, log_op: XfsLogOperation, dsize: int) -> Generator[Container | None, None, None]:
    def _parse_directory_entries_shortform(self, log_op: XfsLogOperation, dsize: int) -> tuple[int, list[Container]]:
        data = log_op.item_data
        dir_entries: list[Container] = []
        idx = 0
        sf_hdr_x = xsf_dir2_sf_hdr_x.parse(data[idx : idx + 2])

        if sf_hdr_x.count > 0 and sf_hdr_x.i8count == 0:
            inumber_len = 4
            xfs_dir2_sf_hdr = xfs_dir2_sf_hdr_4
            xfs_dir2_sf_entry = xfs_dir2_sf_entry_4
        elif sf_hdr_x.count == 0 and sf_hdr_x.i8count > 0:
            inumber_len = 8
            xfs_dir2_sf_hdr = xfs_dir2_sf_hdr_8
            xfs_dir2_sf_entry = xfs_dir2_sf_entry_8
        else:
            msg = "Invalid directory entry count."
            raise ValueError(msg)

        dir2_sf_hdr = xfs_dir2_sf_hdr.parse(data[idx : idx + xfs_dir2_sf_hdr.sizeof()])
        idx = xfs_dir2_sf_hdr.sizeof()
        while idx < dsize:
            dir2_sf_entry = xfs_dir2_sf_entry.parse(data[idx:dsize])
            idx += 0x1 + 0x2 + dir2_sf_entry.namelen + 0x1 + inumber_len  # xfs_dir2_sf_entry.offset is not used in short form
            # yield dir2_sf_entry
            dir_entries.append(dir2_sf_entry)

        return dir2_sf_hdr.parent, dir_entries

    def _parse_eattrs_shortform(self, log_op: XfsLogOperation, asize: int) -> list[ExtendedAttribute]:
        namespace_flags = {
            0: "user.",
            1: "",  # XFS_ATTR_LOCAL
            2: "trusted.",  # XFS_ATTR_ROOT
            4: "security.",  # XFS_ATTR_SECURE
            8: "",  # XFS_ATTR_PARENT
            128: "",  # XFS_ATTR_INCOMPLETE
        }

        data = log_op.item_data
        idx = 0
        eattrs: list[ExtendedAttribute] = []

        attr_sf_hdr = xfs_attr_sf_hdr.parse(data[: xfs_attr_sf_hdr.sizeof()])
        idx = xfs_attr_sf_hdr.sizeof()
        while idx < attr_sf_hdr.totsize:
            ea_name = ""
            attr_sf_entry = xfs_attr_sf_entry.parse(data[idx:])
            if name_space := namespace_flags.get(attr_sf_entry.flags):
                ea_name = name_space
            ea_name += attr_sf_entry.nameval[: attr_sf_entry.namelen].decode("utf-8")
            ea_value = attr_sf_entry.nameval[attr_sf_entry.namelen :]
            eattrs.append(ExtendedAttribute(ea_name, ea_value))
            idx += 0x1 + 0x1 + 0x1 + attr_sf_entry.namelen + attr_sf_entry.valuelen
        return eattrs

    def _parse_inode_update(self, log_ops: list[XfsLogOperation]) -> tuple[Container | None, list[Container], list[ExtendedAttribute], int]:
        transaction = list(self.transactions.values())[-1]  # The latest transaction must be the current transaction
        inode_log_format_64 = self.xfs_inode_log_format_64.parse(log_ops[0].item_data)
        idx = 1  # Processing from the second log operation
        inode = None
        dir_entries: list[Container] = []
        eattrs: list[ExtendedAttribute] = []
        parent_inode = 0

        while idx < inode_log_format_64.ilf_size:
            if inode_log_format_64.ilf_fields & xfs_structs.XFS_ILOG_CORE:
                inode = self.xfs_dinode_core.parse(log_ops[idx].item_data)
                # print(f"inode: {inode.di_ino}, mode: {inode.di_mode:04o}")
                # print(
                #     f"atime: {inode.di_mtime.bigtime}, mtime: {inode.di_mtime.bigtime}, ctime: {inode.di_ctime.bigtime}, crtime: {inode.di_crtime.bigtime}",
                # )
                idx += 1
            if inode_log_format_64.ilf_fields & xfs_structs.XFS_ILOG_DDATA:
                if inode and inode.di_mode & xfs_structs.S_IFDIR:
                    # for entry in self._parse_directory_entries_shortform(log_ops[idx], inode_log_format_64.ilf_dsize):
                    #     print(entry)
                    parent_inode, dir_entries = self._parse_directory_entries_shortform(log_ops[idx], inode_log_format_64.ilf_dsize)
                    # dir_inode = 0
                    # for dir_entry in dir_entries:
                    #     if dir_entry.name == b".":
                    #         dir_inode = dir_entry.inumber
                    #         continue
                    #     if dir_entry.ftype == xfs_structs.XFS_DIR3_FT_DIR:
                    #         transaction.set_dir_inode(dir_entry.inumber, parent_inode)
                    #     else:
                    #         transaction.set_dir_inode(dir_entry.inumber, dir_inode)
                    #     transaction.set_parent_inode(dir_entry.inumber, parent_inode)
                    #     transaction.set_dir_entry_info(dir_entry.inumber, dir_entry)
                idx += 1
            if inode_log_format_64.ilf_fields & xfs_structs.XFS_ILOG_DEXT:
                idx += 1
            if inode_log_format_64.ilf_fields & xfs_structs.XFS_ILOG_DBROOT:
                idx += 1
            if inode_log_format_64.ilf_fields & xfs_structs.XFS_ILOG_ADATA:
                eattrs = self._parse_eattrs_shortform(log_ops[idx], inode_log_format_64.ilf_asize)
                # print(eattrs)
                idx += 1
            if inode_log_format_64.ilf_fields & xfs_structs.XFS_ILOG_AEXT:
                idx += 1
            if inode_log_format_64.ilf_fields & xfs_structs.XFS_ILOG_ABROOT:
                idx += 1

        return inode, dir_entries, eattrs, parent_inode

    def _parse_block_directoreis(self, data: bytes) -> Generator[Container | None, None, None]:
        idx = 0
        while idx < len(data):
            dir2_data_entry = xfs_dir2_data_entry.parse(data[idx:])
            if (dir2_data_entry.inumber >> 48) == 0xFFFF:
                break
            idx += 0x8 + 0x1 + dir2_data_entry.namelen + 0x1 + (4 - (dir2_data_entry.namelen % 4)) + 0x2
            yield dir2_data_entry

    def _parse_buffer_writes(self, log_ops: list[XfsLogOperation]) -> Generator[tuple[int, Container | None], None, None]:
        # dir_entries: list[Container] = []
        buf_log_format = self.xfs_buf_log_format.parse(log_ops[0].item_data)
        blf_flags = buf_log_format.blf_flags >> 11
        # print(f"xfs_buf_log_format.blf_flags: 0x{blf_flags:x}")
        idx = 1  # Processing from the second log operation
        while idx < buf_log_format.blf_size:
            data = log_ops[idx].item_data[0 : xfs_dir3_data_hdr.sizeof()]
            dir3_data_hdr = xfs_dir3_data_hdr.parse(data)
            if (
                dir3_data_hdr.hdr.magic in (0x58444233, 0x58444433) and blf_flags == XfsBlft.XFS_BLFT_DIR_BLOCK_BUF
            ):  # XDB3 = 0x58444233, XDD3 = 0x58444433
                # print(f"magic: {dir3_data_hdr.hdr.magic}")
                # print(f"blkno: {dir3_data_hdr.hdr.blkno}")
                # print(f"owner: {dir3_data_hdr.hdr.owner}")
                for dir_entry in self._parse_block_directoreis(log_ops[idx].item_data[xfs_dir3_data_hdr.sizeof() :]):
                    #     print(dir_entry)
                    #     dir_entries.append(dir_entry)
                    yield dir3_data_hdr.hdr.owner, dir_entry
                # yield from self._parse_block_directoreis(log_ops[idx].item_data[xfs_dir3_data_hdr.sizeof() :])
            idx += 1

    def parse_journal(self) -> None:
        self._parse_xfs_superblock()

        first_log_rec_addr = self._find_first_log_record()
        if first_log_rec_addr == -1:
            msg = "Failed to find the first log record."
            raise LogRecordNotFoundError(msg)
        journal_addr = first_log_rec_addr

        while journal_addr < first_log_rec_addr + self.xfs_superblock.sb_logblocks * self.block_size:
            data = self._read_journal_data(journal_addr, 0x200)
            record_header = xlog_rec_header.parse(data)
            if record_header.h_magicno == xfs_structs.XLOG_HEADER_MAGIC and record_header.h_cycle > 0:
                # print(f"===== 0x{journal_addr:0x}: Log record =====")
                # print("Record Header:")
                # print(f"h_lsn: 0x{record_header.h_lsn:0x}")
                # print(f"h_num_logops: {record_header.h_num_logops}")
                transaction_id = record_header.h_lsn
                self.add_transaction(transaction_id)
                transaction = self.transactions[transaction_id]
                transaction.record_len = record_header.h_len
                transaction.record_format = record_header.h_fmt
                journal_addr += 0x200
                data = self._read_journal_data(journal_addr, record_header.h_len)
                log_ops = self._parse_log_operations(data)
                if log_ops:
                    xfs_trans_header = xfs_log_item = None
                    match transaction.record_format:
                        case xfs_structs.XLOG_FMT_UNKNOWN:
                            print("Unknown log record format does not supported.")
                            return
                        case xfs_structs.XLOG_FMT_LINUX_LE:
                            xfs_log_item = xfs_log_item_le
                            xfs_trans_header = xfs_trans_header_le
                            self.xfs_dinode_core = xfs_dinode_core_le
                            self.xfs_inode_log_format_64 = xfs_inode_log_format_64_le
                            self.xfs_buf_log_format = xfs_buf_log_format_le
                        case xfs_structs.XLOG_FMT_LINUX_BE | xfs_structs.XLOG_FMT_IRIX_BE:
                            xfs_log_item = xfs_log_item_be
                            xfs_trans_header = xfs_trans_header_be
                            self.xfs_dinode_core = xfs_dinode_core_be
                            self.xfs_inode_log_format_64 = xfs_inode_log_format_64_be
                            self.xfs_buf_log_format = xfs_buf_log_format_be

                    idx = 0
                    if xfs_trans_header and xfs_log_item:
                        while idx < len(log_ops):
                            log_op = log_ops[idx]
                            op_size = 1
                            if log_op.op_header.oh_clientid == xfs_structs.XFS_TRANSACTION:
                                match log_op.op_header.oh_flags:
                                    case xfs_structs.XLOG_START_TRANS:
                                        transaction.trans_state = TransState.START_TRANS
                                    case 0x0:
                                        log_item = xfs_log_item.parse(log_op.item_data)
                                        match log_item.magic:
                                            case 0x414E | 0x5452:  # Little endian = "AN" | Big endian = "TR"
                                                trans_header = xfs_trans_header.parse(log_op.item_data)
                                                transaction.trans_state = TransState.TRANS_DESC
                                            case xfs_structs.XFS_LI_INODE:  # 0x123B
                                                op_size = log_item.size
                                                inode, dir_entries, eattrs, parent_inode = self._parse_inode_update(log_ops[idx : idx + op_size])
                                                if inode:
                                                    self.transactions[transaction_id].set_inode_info(inode.di_ino, inode, eattrs)
                                                    if dir_entries:
                                                        dir_inode = inode.di_ino
                                                        for dir_entry in dir_entries:
                                                            # self.transactions[transaction_id].set_dir_entry_info(dir_entry.inumber, dir_entry)
                                                            # if dir_entry.name == b".":
                                                            #     dir_inode = dir_entry.inumber
                                                            #     continue
                                                            # if dir_entry.ftype == xfs_structs.XFS_DIR3_FT_DIR:
                                                            #     transaction.set_dir_inode(dir_entry.inumber, parent_inode)
                                                            # else:
                                                            #     transaction.set_dir_inode(dir_entry.inumber, dir_inode)
                                                            transaction.set_dir_inode(dir_entry.inumber, dir_inode)
                                                            transaction.set_parent_inode(dir_entry.inumber, parent_inode)
                                                            transaction.set_dir_entry_info(dir_entry.inumber, dir_entry)
                                                            if not transaction.sf_dir_entries.get(dir_inode):
                                                                transaction.sf_dir_entries[dir_inode] = []
                                                            transaction.sf_dir_entries[dir_inode].append(
                                                                SfDirEntry(dir_entry.inumber, dir_entry.name.decode("utf-8"), dir_entry.ftype),
                                                            )
                                            case xfs_structs.XFS_LI_BUF:  # 0x123C
                                                op_size = log_item.size
                                                parent_inode = 0
                                                for dir_inode, dir_entry in self._parse_buffer_writes(log_ops[idx : idx + op_size]):
                                                    # if dir_entry.name == b".":
                                                    #     dir_inode = dir_entry.inumber
                                                    #     continue
                                                    if dir_entry.name == b".":
                                                        continue
                                                    if dir_entry.name == b"..":
                                                        parent_inode = dir_entry.inumber
                                                        continue
                                                    # if dir_entry.ftype == xfs_structs.XFS_DIR3_FT_DIR:
                                                    #     transaction.set_dir_inode(dir_entry.inumber, parent_inode)
                                                    # else:
                                                    #     transaction.set_dir_inode(dir_entry.inumber, dir_inode)
                                                    transaction.set_dir_inode(dir_entry.inumber, dir_inode)
                                                    transaction.set_parent_inode(dir_entry.inumber, parent_inode)
                                                    transaction.set_dir_entry_info(dir_entry.inumber, dir_entry)
                                                    # Deleted inode number is overwritten the high 16 bits with 0xFFFF
                                                    deleted_inode = dir_entry.inumber | 0xFFFF000000000000
                                                    if not transaction.block_directory_entries.get(deleted_inode):
                                                        transaction.block_directory_entries[deleted_inode] = []
                                                    transaction.block_directory_entries[deleted_inode].append(transaction.entries[dir_entry.inumber])
                                            case xfs_structs.XFS_LI_ICREATE:  # 0x123F
                                                # TODO: Implement parsing inode creation, but I have never seen this log item in the journal.
                                                transaction.trans_state = TransState.INODE_CREATION
                                            case _:
                                                print(f"Unsupported log item magic: 0x{log_item.magic:x}")
                            idx += op_size
                journal_addr += record_header.h_len
            else:
                # print(f"===== 0x{journal_addr:0x}: Empty log record =====")
                journal_addr += 0x200
                # If the first empty log record is found, the loop will be terminated.
                # This is temporarily implemented to prevent long loops. This will be removed later.
                break

    def _generate_timeline_event(self, tid: int, current_entry: EntryInfo, transaction_entry: EntryInfo) -> TimelineEventInfo | None:
        timeline_event = None
        if differences := self._compare_entry_fields(current_entry, transaction_entry):
            action = Actions.UNKNOWN
            info = ""
            name = eattrs = []
            symlink_target = ""
            dir_inode = parent_inode = mode = uid = gid = size = flags = -1
            atime = ctime = mtime = crtime = dtime = None
            for field, current_value, new_value in differences:
                match field:
                    case "name":
                        action |= Actions.RENAME
                        info = self._append_msg(info, f"Name: {current_value} -> {new_value}")
                        name = new_value
                    case "dir_inode":
                        action |= Actions.MOVE
                        info = self._append_msg(info, f"Dir Inode: {current_value} -> {new_value}")
                        dir_inode = new_value
                    case "parent_inode":
                        action |= Actions.MOVE
                        info = self._append_msg(info, f"Parent Inode: {current_value} -> {new_value}")
                        parent_inode = new_value
                    case "mode":
                        action |= Actions.CHANGE_MODE
                        info = self._append_msg(info, f"Mode: {current_value:04o} -> {new_value:04o}")
                        mode = new_value
                    case "uid":
                        action |= Actions.CHANGE_UID
                        info = self._append_msg(info, f"UID: {current_value} -> {new_value}")
                        if new_value & xfs_structs.S_ISUID:
                            action |= Actions.SETUID
                            info += " (SetUID)"
                        uid = new_value
                    case "gid":
                        action |= Actions.CHANGE_GID
                        info = self._append_msg(info, f"GID: {current_value} -> {new_value}")
                        if new_value & xfs_structs.S_ISGID:
                            action |= Actions.SETGID
                            info += " (SetGID)"
                        gid = new_value
                    case "size":
                        if current_value < new_value:
                            action |= Actions.SIZE_UP
                        else:
                            action |= Actions.SIZE_DOWN
                        info = self._append_msg(info, f"Size: {current_value} -> {new_value}")
                        size = new_value
                    case "atime":
                        action |= Actions.ACCESS
                        current_atime = current_value
                        current_atime_nanoseconds = current_entry.atime_nanoseconds
                        new_atime = new_value
                        if result := self._filter_differences(differences, "atime_nanoseconds"):
                            _, _, new_atime_nanoseconds = result
                        else:
                            new_atime_nanoseconds = current_atime_nanoseconds
                        info = self._append_msg(
                            info,
                            f"Atime: {datetime.fromtimestamp(current_atime, tz=UTC).strftime('%Y-%m-%d %H:%M:%S')}.{current_atime_nanoseconds:09d} UTC -> {datetime.fromtimestamp(new_atime, tz=UTC).strftime('%Y-%m-%d %H:%M:%S')}.{new_atime_nanoseconds:09d} UTC",
                        )

                        current_atime_f = float(f"{current_atime}.{current_atime_nanoseconds:09d}")
                        new_atime_f = float(f"{new_atime}.{new_atime_nanoseconds:09d}")
                        if new_atime_f < current_atime_f:
                            action |= Actions.TIMESTOMP
                            info += " (Timestomp)"
                        atime = new_atime_f
                    case "ctime":
                        action |= Actions.CHANGE
                        current_ctime = current_value
                        current_ctime_nanoseconds = current_entry.ctime_nanoseconds
                        new_ctime = new_value
                        if result := self._filter_differences(differences, "ctime_nanoseconds"):
                            _, _, new_ctime_nanoseconds = result
                        else:
                            new_ctime_nanoseconds = current_ctime_nanoseconds
                        info = self._append_msg(
                            info,
                            f"Ctime: {datetime.fromtimestamp(current_ctime, tz=UTC).strftime('%Y-%m-%d %H:%M:%S')}.{current_ctime_nanoseconds:09d} UTC -> {datetime.fromtimestamp(new_ctime, tz=UTC).strftime('%Y-%m-%d %H:%M:%S')}.{new_ctime_nanoseconds:09d} UTC",
                        )

                        current_ctime_f = float(f"{current_ctime}.{current_ctime_nanoseconds:09d}")
                        new_ctime_f = float(f"{new_ctime}.{new_ctime_nanoseconds:09d}")
                        if new_ctime_f < current_ctime_f:
                            action |= Actions.TIMESTOMP
                            info += " (Timestomp)"
                        ctime = new_ctime_f
                    case "mtime":
                        action |= Actions.MODIFY
                        current_mtime = current_value
                        current_mtime_nanoseconds = current_entry.mtime_nanoseconds
                        new_mtime = new_value
                        if result := self._filter_differences(differences, "mtime_nanoseconds"):
                            _, _, new_mtime_nanoseconds = result
                        else:
                            new_mtime_nanoseconds = current_mtime_nanoseconds
                        info = self._append_msg(
                            info,
                            f"Mtime: {datetime.fromtimestamp(current_mtime, tz=UTC).strftime('%Y-%m-%d %H:%M:%S')}.{current_mtime_nanoseconds:09d} UTC -> {datetime.fromtimestamp(new_mtime, tz=UTC).strftime('%Y-%m-%d %H:%M:%S')}.{new_mtime_nanoseconds:09d} UTC",
                        )

                        current_mtime_f = float(f"{current_mtime}.{current_mtime_nanoseconds:09d}")
                        new_mtime_f = float(f"{new_mtime}.{new_mtime_nanoseconds:09d}")
                        if new_mtime_f < current_mtime_f:
                            action |= Actions.TIMESTOMP
                            info += " (Timestomp)"
                        mtime = new_mtime_f
                    case "crtime":
                        action |= Actions.CREATE
                        current_crtime = current_value
                        current_crtime_nanoseconds = current_entry.crtime_nanoseconds
                        new_crtime = new_value
                        if result := self._filter_differences(differences, "crtime_nanoseconds"):
                            _, _, new_crtime_nanoseconds = result
                        else:
                            new_crtime_nanoseconds = current_crtime_nanoseconds
                        info = self._append_msg(
                            info,
                            f"Crtime: {datetime.fromtimestamp(current_crtime, tz=UTC).strftime('%Y-%m-%d %H:%M:%S')}.{current_crtime_nanoseconds:09d} UTC -> {datetime.fromtimestamp(new_crtime, tz=UTC).strftime('%Y-%m-%d %H:%M:%S')}.{new_crtime_nanoseconds:09d} UTC",
                        )

                        current_crtime_f = float(f"{current_crtime}.{current_crtime_nanoseconds:09d}")
                        new_crtime_f = float(f"{new_crtime}.{new_crtime_nanoseconds:09d}")
                        if new_crtime_f < current_crtime_f:
                            action |= Actions.TIMESTOMP
                            info += " (Timestomp)"
                        crtime = new_crtime_f
                    # case "dtime":
                    #     action |= Actions.DELETE
                    #     new_dtime = new_value
                    #     info = self._append_msg(info, f"Dtime: {datetime.fromtimestamp(new_dtime, tz=UTC).strftime('%Y-%m-%d %H:%M:%S')} UTC")
                    #     dtime = new_dtime
                    case "flags":
                        action |= Actions.CHANGE_FLAGS
                        if current_value & xfs_structs.XFS_DIFLAG_IMMUTABLE:
                            info = self._append_msg(info, "Flags: Mutable")
                        elif new_value & xfs_structs.XFS_DIFLAG_IMMUTABLE:
                            info = self._append_msg(info, "Flags: Immutable")
                        else:
                            info = self._append_msg(info, f"Flags: 0x{current_value:08x} -> 0x{new_value:08x}")
                        flags = new_value
                    case "symlink_target":
                        action |= Actions.CHANGE_SYMLINK_TARGET
                        info = self._append_msg(info, f"Symlink Target: {current_value} -> {new_value}")
                        symlink_target = new_value
                    case "extended_attributes":
                        action |= Actions.CHANGE_EA
                        eattrs = new_value
                        added_ea, removed_ea = self._compare_extended_attributes(current_value, new_value)
                        if added_ea:
                            added_ea_str = ", ".join(f"{ea}" for ea in added_ea)
                            info = self._append_msg(info, f"Added EA: {added_ea_str}")
                        if removed_ea:
                            removed_ea_str = ", ".join(f"{ea}" for ea in removed_ea)
                            info = self._append_msg(info, f"Removed EA: {removed_ea_str}")
                    case _:
                        pass

            if action != Actions.UNKNOWN:
                timeline_event = TimelineEventInfo(
                    transaction_id=tid,
                    inode=current_entry.inode,
                    file_type=current_entry.file_type,
                    name=name if name else current_entry.name,
                    action=action,
                    dir_inode=dir_inode if dir_inode != -1 else current_entry.dir_inode,
                    parent_inode=parent_inode if parent_inode != -1 else current_entry.parent_inode,
                    mode=mode if mode != -1 else current_entry.mode,
                    uid=uid if uid != -1 else current_entry.uid,
                    gid=gid if gid != -1 else current_entry.gid,
                    size=size if size != -1 else current_entry.size,
                    atime=atime if atime is not None else float(f"{current_entry.atime}.{current_entry.atime_nanoseconds:09d}"),
                    ctime=ctime if ctime is not None else float(f"{current_entry.ctime}.{current_entry.ctime_nanoseconds:09d}"),
                    mtime=mtime if mtime is not None else float(f"{current_entry.mtime}.{current_entry.mtime_nanoseconds:09d}"),
                    crtime=crtime if crtime is not None else float(f"{current_entry.crtime}.{current_entry.crtime_nanoseconds:09d}"),
                    # dtime=dtime if dtime is not None else current_entry.dtime,
                    dtime=0,
                    flags=flags if flags != -1 else current_entry.flags,
                    symlink_target=symlink_target if symlink_target else current_entry.symlink_target,
                    extended_attributes=eattrs if eattrs else current_entry.extended_attributes,
                    info=info,
                )

            # Apply new values to the current entry
            for field, _, new_value in differences:
                setattr(current_entry, field, new_value)

            return timeline_event

        return None

    def timeline(self) -> None:
        working_entries: dict[int, EntryInfo] = {}
        timeline_events: list[TimelineEventInfo] = []
        for tid in sorted(self.transactions.keys()):
            transaction = self.transactions[tid]
            for inode_num in transaction.entries:
                if not working_entries.get(inode_num):
                    msg = info = ""
                    action = Actions.UNKNOWN
                    working_entries[inode_num] = copy.deepcopy(transaction.entries[inode_num])
                    atime_f = float(f"{working_entries[inode_num].atime}.{working_entries[inode_num].atime_nanoseconds}")
                    ctime_f = float(f"{working_entries[inode_num].ctime}.{working_entries[inode_num].ctime_nanoseconds}")
                    mtime_f = float(f"{working_entries[inode_num].mtime}.{working_entries[inode_num].mtime_nanoseconds}")
                    crtime_f = float(f"{working_entries[inode_num].crtime}.{working_entries[inode_num].crtime_nanoseconds}")

                    # Creation of files in a directory updates the directory's ctime and mtime,
                    # so a directory created almost simultaneously with a large number of files may not be detected.
                    # Under the following conditions, differences of less than 1 second are ignored.
                    if (
                        working_entries[inode_num].crtime != 0
                        and working_entries[inode_num].atime
                        == working_entries[inode_num].ctime
                        == working_entries[inode_num].mtime
                        == working_entries[inode_num].crtime
                    ):
                        action |= Actions.CREATE
                        info = self._append_msg(
                            info,
                            f"Crtime: {datetime.fromtimestamp(working_entries[inode_num].crtime, tz=UTC).strftime('%Y-%m-%d %H:%M:%S')}.{working_entries[inode_num].crtime_nanoseconds:09d} UTC",
                        )

                    if atime_f < crtime_f:
                        action |= Actions.ACCESS | Actions.TIMESTOMP
                        msg = f"Atime: {datetime.fromtimestamp(working_entries[inode_num].atime, tz=UTC).strftime('%Y-%m-%d %H:%M:%S')}.{working_entries[inode_num].atime_nanoseconds:09d} UTC (Timestomp)"
                        info = self._append_msg(info, msg)

                    if ctime_f < crtime_f:
                        action |= Actions.CHANGE | Actions.TIMESTOMP
                        msg = f"Ctime: {datetime.fromtimestamp(working_entries[inode_num].ctime, tz=UTC).strftime('%Y-%m-%d %H:%M:%S')}.{working_entries[inode_num].ctime_nanoseconds:09d} UTC (Timestomp)"
                        info = self._append_msg(info, msg)

                    if mtime_f < crtime_f:
                        action |= Actions.MODIFY | Actions.TIMESTOMP
                        msg = f"Mtime: {datetime.fromtimestamp(working_entries[inode_num].mtime, tz=UTC).strftime('%Y-%m-%d %H:%M:%S')}.{working_entries[inode_num].mtime_nanoseconds:09d} UTC (Timestomp)"
                        info = self._append_msg(info, msg)

                    # if working_entries[inode_num].dtime != 0:
                    #     action |= Actions.DELETE
                    #     info = self._append_msg(
                    #         info,
                    #         f"Dtime: {datetime.fromtimestamp(working_entries[inode_num].dtime, tz=UTC).strftime('%Y-%m-%d %H:%M:%S')} UTC",
                    #     )
                    #     if working_entries[inode_num].dtime < crtime_f or working_entries[inode_num].dtime > commit_time_f:
                    #         action |= Actions.TIMESTOMP
                    #         info += " (Timestomp)"

                    if working_entries[inode_num].flags & xfs_structs.XFS_DIFLAG_IMMUTABLE:
                        action |= Actions.CHANGE_FLAGS
                        info = self._append_msg(info, "Flags: Immutable")

                    if action != Actions.UNKNOWN:
                        timeline_events.append(
                            TimelineEventInfo(
                                transaction_id=tid,
                                inode=inode_num,
                                file_type=working_entries[inode_num].file_type,
                                name=working_entries[inode_num].name,
                                action=action,
                                dir_inode=working_entries[inode_num].dir_inode,
                                parent_inode=working_entries[inode_num].parent_inode,
                                mode=working_entries[inode_num].mode,
                                uid=working_entries[inode_num].uid,
                                gid=working_entries[inode_num].gid,
                                size=working_entries[inode_num].size,
                                atime=atime_f,
                                ctime=ctime_f,
                                mtime=mtime_f,
                                crtime=crtime_f,
                                # dtime=working_entries[inode_num].dtime,
                                dtime=0,
                                flags=working_entries[inode_num].flags,
                                symlink_target=working_entries[inode_num].symlink_target,
                                extended_attributes=working_entries[inode_num].extended_attributes,
                                info=info,
                            ),
                        )
                # Generate timeline event for each inode
                if timeline_event := self._generate_timeline_event(tid, working_entries[inode_num], transaction.entries[inode_num]):
                    timeline_events.append(timeline_event)

        for event in timeline_events:
            print(json.dumps(event.to_dict()))


def parse_extent(ext: int) -> tuple[int, int, int, int]:
    # Refer for details: https://www.kernel.org/pub/linux/utils/fs/xfs/docs/xfs_filesystem_structure.pdf - Capter 19 Data Extents
    # ext: 128 bit
    # flag: 1 bit (bit 127)
    # logical_block_offset: 54 bit (bit 73-126)
    # abs_block_num: 52 bit (bit 21-72)
    # number_of_blocks: 21 bit (bit 0-20)
    flag = (ext >> 127) & 0x1
    logical_block_offset = (ext >> 73) & ((1 << 54) - 1)
    abs_block_num = (ext >> 21) & ((1 << 52) - 1)
    number_of_blocks = ext & ((1 << 21) - 1)
    return flag, logical_block_offset, abs_block_num, number_of_blocks
