#
# Copyright 2025 Minoru Kobayashi <unknownbit@gmail.com> (@unkn0wnbit)
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
# https://github.com/torvalds/linux/blob/master/fs/xfs/xfs_linux.h
# https://github.com/torvalds/linux/blob/master/include/linux/kdev_t.h

import copy
import io
import json
import sys
from argparse import Namespace
from collections.abc import Generator
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import IntEnum, auto

import pytsk3
from construct import Container, StreamError

from journalparser.common import (
    Actions,
    DentInfo,
    DeviceNumber,
    EntryInfo,
    EntryInfoSource,
    EntryInfoTypes,
    ExtendedAttribute,
    FileTypes,
    FsTypes,
    JournalParserCommon,
    JournalTransaction,
    TimelineEventInfo,
)
from journalparser.structs import xfs_structs
from journalparser.structs.xfs_structs import (
    XfsBlft,
    xfs_attr_sf_entry,
    xfs_attr_sf_hdr,
    xfs_buf_log_format_be,
    xfs_buf_log_format_le,
    xfs_dinode_core_be,
    xfs_dinode_core_le,
    xfs_dir2_data_entry,
    xfs_dir2_data_unused,
    xfs_dir2_sf_entry_4,
    xfs_dir2_sf_entry_8,
    xfs_dir2_sf_hdr_4,
    xfs_dir2_sf_hdr_8,
    xfs_dir2_sf_hdr_x,
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
)


# @dataclass(frozen=True)
@dataclass
class XfsLogOperation:
    op_header: Container
    item_data: bytes


# Not needed for now
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
class EntryInfoXfs(EntryInfo):
    generation: int = 0  # Inode generation number (this value is same to xfs_dinode_core.di_gen)


@dataclass
class JournalTransactionXfs(JournalTransaction):
    record_len: int = 0
    record_format: int = 0
    trans_state = TransState.UNKNOWN
    tid_real: int = 0

    @staticmethod
    def _convert_to_epoch(seconds: int) -> int:
        base_datetime = datetime(1901, 12, 13, 20, 45, 52, tzinfo=UTC)  # XFS datetime starts from 1901-12-13 20:45:52
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

    def set_inode_info(self, block_num: int, inode_num: int, inode: Container, eattrs: list[ExtendedAttribute]) -> None:
        special_inodes = {
            128: "Root directory",
        }

        if not self.entries.get(inode_num):
            self.entries[inode_num] = EntryInfoXfs()
        entry = self.entries[inode_num]
        entry.inode = inode_num
        if special_inodes.get(inode_num):
            entry.names[128] = [special_inodes[inode_num]]
            if not self.dents.get(128):
                self.dents[128] = DentInfo(dir_inode=128, parent_inode=128)
            if not self.dents[128].block_entries.get(block_num):
                self.dents[128].block_entries[block_num] = {}
            self.dents[128].block_entries[block_num].update({inode_num: [special_inodes[inode_num]]})

        entry.file_type = xfs_structs.FILETYPE_MAP.get(inode.di_mode & xfs_structs.S_IFMT, FileTypes.UNKNOWN)
        # This is a special case where the inode is a symbolic link but has no file type bits set.
        # if inode.di_magic == 0x0000 and inode.di_mode == 0x100:
        #     entry.file_type = FileTypes.SYMBOLIC_LINK
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
        entry.link_count = inode.di_nlink
        entry.extended_attributes = eattrs
        entry.entryinfo_source |= EntryInfoSource.INODE
        entry.generation = inode.di_gen

    def set_dent_info(self, block_num: int, dir_inode_num: int, parent_inode_num: int, inode_num: int, dir_entry: Container | list | None) -> None:
        # Set DentInfo
        if dir_entry is not None:
            if not self.dents.get(dir_inode_num):
                self.dents[dir_inode_num] = DentInfo(dir_inode=dir_inode_num, parent_inode=parent_inode_num)
            if not self.dents[dir_inode_num].block_entries.get(block_num):
                self.dents[dir_inode_num].block_entries[block_num] = {}
            dent = self.dents[dir_inode_num].block_entries[block_num]
            # Add EntryInfoSource.DIR_ENTRY to entries[dir_inode_num]
            # This setting is required to mark directory entries recognized in the current transaction
            # so they can be merged with entries from previous transactions.
            if not self.entries.get(dir_inode_num):
                self.entries[dir_inode_num] = EntryInfoXfs(inode=dir_inode_num)
            self.entries[dir_inode_num].entryinfo_source |= EntryInfoSource.DIR_ENTRY

        if dir_entry:
            try:
                name = dir_entry.name.decode("utf-8")
                if not dent.get(inode_num):
                    dent[inode_num] = []
                if name not in dent[inode_num]:
                    dent[inode_num].append(name)
            except UnicodeDecodeError:
                print(f"set_dent_info UnicodeDecodeError: {dir_entry}", file=sys.stderr)

        # Set EntryInfo
        if dir_entry:
            if not self.entries.get(inode_num):
                self.entries[inode_num] = EntryInfoXfs(inode=inode_num)
            entry = self.entries[inode_num]

            # Set file type from directory entry
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

            entry.entryinfo_source |= EntryInfoSource.DIR_ENTRY


class LogRecordNotFoundError(Exception):
    pass


class JournalParserXfs(JournalParserCommon[JournalTransactionXfs, EntryInfoXfs]):
    def __init__(self, img_info: pytsk3.Img_Info | io.BufferedReader, fs_info: pytsk3.FS_Info | None, args: Namespace) -> None:
        super().__init__(img_info, fs_info, args)
        self.fstype = FsTypes.XFS
        self.incomplete_log_ops: list[XfsLogOperation] = []

    def _convert_block_to_absaddr(self, block_num: int, log2val: int) -> int:
        if self.sb_agblocks:
            agno = block_num >> log2val
            rel_offset = block_num & ((1 << log2val) - 1)
            return (agno * self.sb_agblocks + rel_offset) * self.block_size
        return 0

    def _create_transaction(self, tid: int) -> JournalTransactionXfs:
        return JournalTransactionXfs(tid=tid)

    def _parse_xfs_superblock(self) -> None:
        self.xfs_superblock = xfs_dsb.parse(self.read_data(self.offset + 0x0, 0x200))
        self.dbg_print(f"XFS superblock: {self.xfs_superblock}")
        # https://github.com/torvalds/linux/blob/master/fs/xfs/libxfs/xfs_format.h#L299 - XFS_SB_VERSION_NUM()
        masked_ver = self.xfs_superblock.sb_versionnum & 0xF
        if masked_ver != 5:
            msg = f"XFS version: {masked_ver}. Only XFS version 5 is supported."
            raise ValueError(msg)
        self.block_size = self.xfs_superblock.sb_blocksize
        self.sb_agblocks = self.xfs_superblock.sb_agblocks
        self.sb_logstart_addr = self._convert_block_to_absaddr(self.xfs_superblock.sb_logstart, self.xfs_superblock.sb_agblklog)
        self.sb_rootino = self.xfs_superblock.sb_rootino
        self.sb_inodesize = self.xfs_superblock.sb_inodesize

    def _find_first_log_record(self) -> int:
        end = self.sb_logstart_addr + self.xfs_superblock.sb_logblocks * self.block_size
        addr = self.sb_logstart_addr
        while addr < end:
            data = self.read_data(self.offset + addr, xfs_structs.xlog_rec_header.sizeof())
            hdr = xlog_rec_header.parse(data)
            if hdr.h_magicno == xfs_structs.XLOG_HEADER_MAGIC and hdr.h_cycle > 0x0:
                self.dbg_print(f"First log record: {addr}")
                return addr
            # addr += 4
            addr += 0x200  # Aligned to 0x200 ?
        return -1

    def _read_journal_data(self, journal_addr: int, read_len: int = 4096) -> bytes:
        self.dbg_print(f"_read_journal_data journal_addr: 0x{journal_addr:0x}, read_len: {read_len}")
        xfs_sb = self.xfs_superblock
        if journal_addr < self.sb_logstart_addr:
            self.dbg_print(
                f"_read_journal_data journal_addr is smaller than self.sb_logstart_addr. something is wrong.: {journal_addr} < {self.sb_logstart_addr}",
            )
            return b""
        journal_data_len = xfs_sb.sb_logblocks * self.block_size
        self.dbg_print(f"_read_journal_data sb_logblocks: {xfs_sb.sb_logblocks}")
        self.dbg_print(f"_read_journal_data block_size: {self.block_size}")
        self.dbg_print(f"_read_journal_data journal_data_len: {journal_data_len}")
        read_pos = (journal_addr - self.sb_logstart_addr) % journal_data_len
        self.dbg_print(f"_read_journal_data sb_logstart_addr: {self.sb_logstart_addr}")
        self.dbg_print(f"_read_journal_data read_pos: {read_pos}")
        if read_pos + read_len >= journal_data_len:
            read_len_1 = journal_data_len - read_pos
            read_len_2 = read_len - read_len_1
            self.dbg_print(f"_read_journal_data read_len_1: {read_len_1}")
            data_1 = self.read_data(self.offset + self.sb_logstart_addr + read_pos, read_len_1)
            self.dbg_print(f"_read_journal_data data_1[:0x100]: {data_1[:0x100]}")
            self.dbg_print(f"_read_journal_data read_len_2: {read_len_2}")
            data_2 = self.read_data(self.offset + self.sb_logstart_addr, read_len_2)
            self.dbg_print(f"_read_journal_data data_2[:0x100]: {data_2[:0x100]}")
            return data_1 + data_2
        data = self.read_data(self.offset + self.sb_logstart_addr + read_pos, read_len)
        self.dbg_print(f"_read_journal_data data: {data}")
        return data

    def _find_next_xlog_op_header(self, tid: int, data: bytes) -> int:
        idx = 0
        while idx < len(data):
            self.dbg_print(f"_find_next_xlog_op_header data[{idx}:{idx + xlog_op_header.sizeof()}]: {data[idx : idx + xlog_op_header.sizeof()]}")
            op_header = xlog_op_header.parse(data[idx : idx + xlog_op_header.sizeof()])
            if (
                op_header.oh_tid == tid
                and op_header.oh_len <= len(data) - idx - xlog_op_header.sizeof()
                and (op_header.oh_clientid in (xfs_structs.XFS_TRANSACTION, xfs_structs.XFS_VOLUME, xfs_structs.XFS_LOG))
                and (op_header.oh_flags == 0 or op_header.oh_flags & xfs_structs.XLOG_OPERATION_FLAGS_ALL)
            ):
                self.dbg_print(f"_find_next_xlog_op_header found xlog_op_header: {op_header}")
                return idx
            idx += 1
        return 0

    def _restore_cycle_data(self, data: bytes, cycle_data: list[int]) -> bytes:
        # Replace the beginning of each log sector with cycle_data
        cycle_idx = 0
        tmp_data = b""
        while cycle_idx * 0x200 < len(data):
            self.dbg_print(
                f"_restore_cycle_data replace data[{cycle_idx * 0x200}:{cycle_idx * 0x200 + 4}]: {data[cycle_idx * 0x200 : cycle_idx * 0x200 + 4]} -> cycle_data[{cycle_idx}]: {cycle_data[cycle_idx].to_bytes(4, 'big')}",
            )
            tmp_data += cycle_data[cycle_idx].to_bytes(4, "big") + data[cycle_idx * 0x200 + 4 : cycle_idx * 0x200 + 0x200]
            cycle_idx += 1
        self.dbg_print(f"_restore_cycle_data replaced data: {data}")
        return tmp_data

    def _parse_log_operations(self, data: bytes, cycle_data: list[int]) -> tuple[int, list[XfsLogOperation]]:
        idx = 0
        tid = 0
        log_ops: list[XfsLogOperation] = []
        self.dbg_print(f"_parse_log_operations data: {data}")
        self.dbg_print(f"_parse_log_operations cycle_data: {cycle_data}")

        data = self._restore_cycle_data(data, cycle_data)

        # Parse log operations and log items
        while idx < len(data):
            try:
                self.dbg_print(f"_parse_log_operations data[{idx}:{idx + xlog_op_header.sizeof()}]: {data[idx : idx + xlog_op_header.sizeof()]}")
                op_header = xlog_op_header.parse(data[idx : idx + xlog_op_header.sizeof()])
                self.dbg_print(f"_parse_log_operations idx: {idx}")
                self.dbg_print(f"_parse_log_operations op_header: {op_header}")

                # Unmount transaction is a special case.
                if (
                    op_header.oh_tid > 0
                    # and op_header.oh_len == 0  # Not needed?
                    and op_header.oh_clientid == xfs_structs.XFS_LOG
                    and op_header.oh_flags == xfs_structs.XLOG_UNMOUNT_TRANS
                ):
                    log_ops.append(XfsLogOperation(op_header, b""))
                    return op_header.oh_tid, log_ops

                # The transaction ID does not change within a log record.
                # So, if a different transaction ID appears, we need to guess the correct length of the log item.
                # This is caused by incorrect value sometimes being recorded in oh_len. The reason why I don't know.
                if tid == 0:
                    tid = op_header.oh_tid
                    self.dbg_print(f"_parse_log_operations op_header.oh_tid: {tid}")

                if (
                    op_header.oh_tid != tid
                    or op_header.oh_clientid not in (xfs_structs.XFS_TRANSACTION, xfs_structs.XFS_VOLUME, xfs_structs.XFS_LOG)
                    or not (op_header.oh_flags == 0 or op_header.oh_flags & xfs_structs.XLOG_OPERATION_FLAGS_ALL)
                ) and (next_op_header := self._find_next_xlog_op_header(tid, data[idx:])):
                    self.dbg_print(f"Found next xlog_op_header (next_op_header): {next_op_header}")
                    log_ops[-1].op_header.oh_len += next_op_header
                    log_ops[-1].item_data += data[idx : idx + next_op_header]
                    self.dbg_print(f"_parse_log_operations updated log_ops[-1].op_header: {log_ops[-1].op_header}")
                    self.dbg_print(f"_parse_log_operations updated log_ops[-1].item_data: {log_ops[-1].item_data}")
                    idx += next_op_header
                    op_header = xlog_op_header.parse(data[idx : idx + xlog_op_header.sizeof()])
                    self.dbg_print(f"_parse_log_operations updated op_header: {op_header}")

                item_data = data[idx + xlog_op_header.sizeof() : idx + xlog_op_header.sizeof() + op_header.oh_len]
                self.dbg_print(f"_parse_log_operations item_data: {item_data}")
                idx += xlog_op_header.sizeof() + op_header.oh_len
                log_ops.append(XfsLogOperation(op_header, item_data))
                if op_header.oh_flags & (xfs_structs.XLOG_COMMIT_TRANS | xfs_structs.XLOG_CONTINUE_TRANS):
                    break
            except StreamError as err:
                self.dbg_print(err)
                self.dbg_print(
                    f"Failed to parse xlog_op_header: data[{idx}:{idx + xlog_op_header.sizeof()}]: {data[idx : idx + xlog_op_header.sizeof()]}",
                )
                break
        return tid, log_ops

    def _brute_force_xfs_dir2_sf_entry(self, data: bytes) -> Container | None:
        namelen = 1
        while namelen < len(data):
            try:
                tmp_data = namelen.to_bytes(1, "big") + data[1:]
                self.dbg_print(f"_brute_force_xfs_dir2_sf_entry tmp_data: {tmp_data}")
                dir2_sf_entry = self.xfs_dir2_sf_entry.parse(tmp_data)
                self.dbg_print(f"_brute_force_xfs_dir2_sf_entry dir2_sf_entry: {dir2_sf_entry}")
                if xfs_structs.XFS_DIR3_FT_UNKNOWN <= dir2_sf_entry.ftype <= xfs_structs.XFS_DIR3_FT_WHT and not self._contains_control_chars_bytes(
                    dir2_sf_entry.name,
                ):
                    return dir2_sf_entry
                namelen += 1
                if namelen > 255:
                    break
            except StreamError as err:
                self.dbg_print(f"_brute_force_xfs_dir2_sf_entry exception: {err}")
                self.dbg_print(f"_brute_force_xfs_dir2_sf_entry exception: {data}")
                return None
        return None

    def _parse_directory_entries_shortform(self, log_op: XfsLogOperation, dsize: int) -> tuple[int, list[Container]]:
        data = log_op.item_data
        self.dbg_print(f"_parse_directory_entries_shortform data: {data}")
        dir_entries: list[Container] = []
        idx = 0
        sf_hdr_x = xfs_dir2_sf_hdr_x.parse(data[idx : idx + 2])
        self.dbg_print(f"_parse_directory_entries_shortform sf_hdr_x: {sf_hdr_x}")

        if (sf_hdr_x.count > 0 and sf_hdr_x.i8count == 0) or (sf_hdr_x.count == 0 and sf_hdr_x.i8count == 0):
            inumber_len = 4
            xfs_dir2_sf_hdr = xfs_dir2_sf_hdr_4
            self.xfs_dir2_sf_entry = xfs_dir2_sf_entry_4
        elif sf_hdr_x.count == 0 and sf_hdr_x.i8count > 0:
            inumber_len = 8
            xfs_dir2_sf_hdr = xfs_dir2_sf_hdr_8
            self.xfs_dir2_sf_entry = xfs_dir2_sf_entry_8
        else:
            msg = "Invalid directory entry count."
            raise ValueError(msg)

        dir2_sf_hdr = xfs_dir2_sf_hdr.parse(data[idx : idx + xfs_dir2_sf_hdr.sizeof()])
        self.dbg_print(f"_parse_directory_entries_shortform dir2_sf_hdr: {dir2_sf_hdr}")
        idx = xfs_dir2_sf_hdr.sizeof()
        while idx < dsize:
            try:
                self.dbg_print(f"_parse_directory_entries_shortform idx: {idx}")
                dir2_sf_entry = self.xfs_dir2_sf_entry.parse(data[idx:dsize])
                self.dbg_print(f"_parse_directory_entries_shortform dir2_sf_entry: {dir2_sf_entry}")
                if (
                    dir2_sf_entry.namelen == 0
                    or dir2_sf_entry.ftype < xfs_structs.XFS_DIR3_FT_UNKNOWN
                    or dir2_sf_entry.ftype > xfs_structs.XFS_DIR3_FT_WHT
                    or self._contains_control_chars_bytes(dir2_sf_entry.name)
                ):
                    self.dbg_print(f"Invalid directory entry: {dir2_sf_entry}")
                    dir2_sf_entry = self._brute_force_xfs_dir2_sf_entry(data[idx:dsize])
                    if dir2_sf_entry is None:
                        self.dbg_print(f"Failed to brute force xfs_dir2_sf_entry: {data[idx:]}")
                        idx += 1
                        continue
                idx += 0x1 + 0x2 + dir2_sf_entry.namelen + 0x1 + inumber_len  # xfs_dir2_sf_entry.offset is not used in short form
                # If control code is included in dir2_sf_entry.name, it may not be appended.
                dir_entries.append(dir2_sf_entry)
            except StreamError as err:
                self.dbg_print(f"_parse_directory_entries_shortform exception: {err}")
                self.dbg_print(f"_parse_directory_entries_shortform exception: {data[idx:]}")
                idx += 1

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

        self.dbg_print(f"_parse_eattrs_shortform data: {data}")
        attr_sf_hdr = xfs_attr_sf_hdr.parse(data[: xfs_attr_sf_hdr.sizeof()])
        self.dbg_print(f"_parse_eattrs_shortform attr_sf_hdr: {attr_sf_hdr}")
        idx = xfs_attr_sf_hdr.sizeof()
        while idx < attr_sf_hdr.totsize:
            ea_name = ""
            self.dbg_print(f"_parse_eattrs_shortform idx: {idx}")
            attr_sf_entry = xfs_attr_sf_entry.parse(data[idx:])
            self.dbg_print(f"_parse_eattrs_shortform attr_sf_entry: {attr_sf_entry}")
            if attr_sf_entry.flags & ~xfs_structs.XFS_ATTR_ALL or self._contains_control_chars_bytes(attr_sf_entry.nameval[: attr_sf_entry.namelen]):
                break

            if name_space := namespace_flags.get(attr_sf_entry.flags):
                ea_name = name_space
            ea_name += attr_sf_entry.nameval[: attr_sf_entry.namelen].decode("utf-8")
            ea_value = attr_sf_entry.nameval[attr_sf_entry.namelen :]
            eattrs.append(ExtendedAttribute(ea_name, ea_value))
            idx += 0x1 + 0x1 + 0x1 + attr_sf_entry.namelen + attr_sf_entry.valuelen
        return eattrs

    def _parse_inode_update(
        self,
        log_ops: list[XfsLogOperation],
    ) -> tuple[int, Container | None, list[Container] | None, list[ExtendedAttribute], str, DeviceNumber, int]:
        idx = 1  # Processing from the second log operation
        inode = None
        dir_entries: list[Container] | None = None
        eattrs: list[ExtendedAttribute] = []
        symlink_target = ""
        device_number = DeviceNumber()
        parent_inode = 0

        try:
            self.dbg_print(f"_parse_inode_update log_ops: {log_ops}")
            inode_log_format_64 = self.xfs_inode_log_format_64.parse(log_ops[0].item_data)
            self.dbg_print(f"_parse_inode_update inode_log_format_64: {inode_log_format_64}")
        except StreamError:
            self.dbg_print("_parse_inode_update Exception StreamError")
            return 0, inode, dir_entries, eattrs, symlink_target, device_number, parent_inode

        old_idx = 0
        while len(log_ops) >= inode_log_format_64.ilf_size and idx < inode_log_format_64.ilf_size:
            if idx == old_idx:
                print(f"inode_log_format_64.ilf_fields contains unprocessable values: 0x{inode_log_format_64.ilf_fields:x}", file=sys.stderr)
                self.dbg_print(f"_parse_inode_update inode_log_format_64.ilf_fields: {inode_log_format_64.ilf_fields}")
                sys.exit(1)
            old_idx = idx
            self.dbg_print(f"_parse_inode_update idx: {idx}")
            if (
                inode_log_format_64.ilf_fields & xfs_structs.XFS_ILOG_CORE
                # or inode_log_format_64.ilf_fields & 0x03000000  # Probably not needed
                # or inode_log_format_64.ilf_fields & 0x21000000  # Probably not needed
            ):
                try:
                    self.dbg_print(f"_parse_inode_update xfs_dinode_core: {log_ops[idx].item_data}")
                    inode = self.xfs_dinode_core.parse(log_ops[idx].item_data)
                    self.dbg_print(f"_parse_inode_update inode: {inode}")
                    # In some cases, the magic number (di_magic) is 0x0000, and mode (di_mode) is weird (symlink inode only?)
                    # XFS Algorighms and Data Structures, capter 14.3.16 Inode Data Log Item says like below:
                    #     This region contains the new contents of a part of an inode, as described in the previous section. There are no magic numbers.
                    #     If XFS_ILOG_CORE is set in ilf_fields, the corresponding data buffer must be in the format struct xfs_icdinode,
                    #     which has the same format as the first 96 bytes of an inode, but is recorded in host byte order.
                    # if inode.di_magic not in (xfs_structs.XFS_DINODE_MAGIC, 0x0000):
                    if inode.di_magic != xfs_structs.XFS_DINODE_MAGIC:
                        msg = f"Invalid inode magic number: 0x{inode.di_magic:04x}"
                        self.dbg_print(msg)
                        raise ValueError(msg)
                except (StreamError, ValueError) as err:
                    self.dbg_print(f"_parse_inode_update exception (XFS_ILOG_CORE): {err}")
                    break
                else:
                    idx += 1
            if inode_log_format_64.ilf_fields & xfs_structs.XFS_ILOG_DDATA:
                if inode and inode.di_format == xfs_structs.XFS_DINODE_FMT_LOCAL:
                    try:
                        if inode.di_mode & xfs_structs.S_IFDIR:
                            parent_inode, dir_entries = self._parse_directory_entries_shortform(log_ops[idx], inode_log_format_64.ilf_dsize)
                            self.dbg_print(f"_parse_inode_update Parent inode: {parent_inode}")
                            self.dbg_print(f"_parse_inode_update Directory entries (short form): {dir_entries}")
                        # elif inode.di_mode & xfs_structs.S_IFLNK or (
                        #     inode.di_magic == 0x0000 and inode.di_mode == 0x100  # Seems a symlink. Is this condition correct?
                        # ):
                        elif inode.di_mode & xfs_structs.S_IFLNK:
                            self.dbg_print(f"_parse_inode_update Symlink target data: {log_ops[idx].item_data}")
                            if not self._contains_control_chars_bytes(log_ops[idx].item_data):
                                symlink_target = log_ops[idx].item_data[: inode.di_size].decode("utf-8").rstrip("\x00")
                                self.dbg_print(f"_parse_inode_update Symlink target: {symlink_target}")
                    except StreamError:
                        self.dbg_print("_parse_inode_update Exception StreamError (XFS_ILOG_DDATA)")
                idx += 1
            if inode_log_format_64.ilf_fields & xfs_structs.XFS_ILOG_DEXT:
                idx += 1
            if inode_log_format_64.ilf_fields & xfs_structs.XFS_ILOG_DBROOT:
                idx += 1
            if inode_log_format_64.ilf_fields & xfs_structs.XFS_ILOG_DEV:
                # Device number is stored in xfs_inode_log_format_64.ilf_u.ilfu_rdev field.
                # https://github.com/torvalds/linux/blob/master/fs/xfs/xfs_linux.h#L163 - xfs_to_linux_dev_t()
                # https://github.com/torvalds/linux/blob/master/fs/xfs/xfs_linux.h#L168 - linux_to_xfs_dev_t()
                # https://github.com/torvalds/linux/blob/master/include/linux/kdev_t.h#L73 - sysv_major()
                # https://github.com/torvalds/linux/blob/master/include/linux/kdev_t.h#L78 - sysv_minor()
                ilfu_rdev = inode_log_format_64.ilf_u.ilfu_rdev
                device_number.major = (ilfu_rdev >> 18) & 0x3FFF
                device_number.minor = ilfu_rdev & 0x3FFFF
                idx += 1
            if inode_log_format_64.ilf_fields & xfs_structs.XFS_ILOG_UUID:
                idx += 1
            if (
                inode_log_format_64.ilf_fields & xfs_structs.XFS_ILOG_ADATA
                # or inode_log_format_64.ilf_fields & 0x1E000000
            ):  # 0x1E000000 is probably not needed.
                try:
                    eattrs = self._parse_eattrs_shortform(log_ops[idx], inode_log_format_64.ilf_asize)
                    self.dbg_print(f"_parse_inode_update Extended attributes (short form): {eattrs}")
                except (StreamError, IndexError) as err:
                    self.dbg_print(f"_parse_inode_update exception (XFS_ILOG_ADATA): {err}")
                idx += 1
            if inode_log_format_64.ilf_fields & xfs_structs.XFS_ILOG_AEXT:
                idx += 1
            if inode_log_format_64.ilf_fields & xfs_structs.XFS_ILOG_ABROOT:
                idx += 1

        return inode_log_format_64.ilf_blkno, inode, dir_entries, eattrs, symlink_target, device_number, parent_inode

    def _brute_force_xfs_dir2_data_entry(self, data: bytes) -> Container | None:
        namelen = 1
        while namelen < len(data) and namelen < 256:
            tmp_data = data[0:8]
            tmp_data += namelen.to_bytes(1, "big")
            tmp_data += data[9:]
            self.dbg_print(f"_brute_force_xfs_dir2_data_entry tmp_data: {tmp_data}")
            dir2_data_entry = xfs_dir2_data_entry.parse(tmp_data)
            self.dbg_print(f"_brute_force_xfs_dir2_data_entry dir2_data_entry: {dir2_data_entry}")
            if (
                xfs_structs.XFS_DIR3_FT_UNKNOWN <= dir2_data_entry.ftype <= xfs_structs.XFS_DIR3_FT_WHT
                and dir2_data_entry.tag >= 64
                and not self._contains_control_chars_bytes(dir2_data_entry.name)
            ):
                return dir2_data_entry
            namelen += 1
        return None

    def _parse_block_directoreis(self, data: bytes) -> Generator[Container | None, None, None]:
        try:
            idx = 0
            while idx < len(data) and len(data) - idx >= 0x8 + 0x1 + 0x0 + 0x1 + 0x4 + 0x2:
                self.dbg_print(f"_parse_block_directoreis data[{idx}:]: {data[idx:]}")
                dir2_data_entry = xfs_dir2_data_entry.parse(data[idx:])
                self.dbg_print(f"_parse_block_directoreis dir2_data_entry: {dir2_data_entry}")
                if (dir2_data_entry.inumber >> 48) == 0xFFFF:  # Deleted directory entry's inode number starts with 0xFFFF
                    dir2_data_unused = xfs_dir2_data_unused.parse(data[idx:])
                    self.dbg_print(f"dir2_data_unused: {dir2_data_unused}")
                    idx += dir2_data_unused.length
                    continue
                elif (
                    dir2_data_entry.ftype < xfs_structs.XFS_DIR3_FT_UNKNOWN
                    or dir2_data_entry.ftype > xfs_structs.XFS_DIR3_FT_WHT
                    or dir2_data_entry.tag < 64
                    or self._contains_control_chars_bytes(dir2_data_entry.name)
                ):
                    dir2_data_entry = self._brute_force_xfs_dir2_data_entry(data[idx:])
                    if dir2_data_entry is None:
                        self.dbg_print(f"Failed to brute force xfs_dir2_data_entry: {data[idx:]}")
                        break
                padding_len = (8 - (0x8 + 0x1 + dir2_data_entry.namelen + 0x1 + 0x2) % 8) % 8
                idx += 0x8 + 0x1 + dir2_data_entry.namelen + 0x1 + padding_len + 0x2
                # If control code is included in dir2_data_entry.name, it may not be appended.
                yield dir2_data_entry
        except StreamError:
            self.dbg_print("_parse_block_directoreis Exception StreamError")

    def _parse_buffer_writes(self, log_ops: list[XfsLogOperation]) -> Generator[tuple[int, int, Container | None], None, None]:
        try:
            # The first log operation is like a header for subsequent log operations.
            self.dbg_print(f"_parse_buffer_writes log_ops: {log_ops}")
            buf_log_format = self.xfs_buf_log_format.parse(log_ops[0].item_data)
            self.dbg_print(f"_parse_buffer_writes buf_log_format: {buf_log_format}")
            # https://github.com/torvalds/linux/blob/master/fs/xfs/libxfs/xfs_log_format.h#L588 - xfs_blft_to_flags()
            # https://github.com/torvalds/linux/blob/master/fs/xfs/libxfs/xfs_log_format.h#L596 - xfs_blft_from_flags()
            blf_flags = buf_log_format.blf_flags >> xfs_structs.XFS_BLFT_SHIFT
            if len(log_ops) != buf_log_format.blf_size:
                self.dbg_print(f"_parse_buffer_writes buf_log_format.blf_size: {buf_log_format.blf_size}")
                self.dbg_print(f"_parse_buffer_writes actual log_ops size: {len(log_ops)}")

            # Processing from the second log operation
            # Merge item_data
            idx = 1
            tmp_data = b""
            while idx < len(log_ops):
                self.dbg_print(f"_parse_buffer_writes log_ops[{idx}].item_data: {log_ops[idx].item_data}")
                tmp_data += log_ops[idx].item_data
                idx += 1
            self.dbg_print(f"_parse_buffer_writes tmp_data: {tmp_data}")

            # Parse as directory entries
            dir3_data_hdr = xfs_dir3_data_hdr.parse(tmp_data[0 : xfs_dir3_data_hdr.sizeof()])
            self.dbg_print(f"_parse_buffer_writes dir3_data_hdr: {dir3_data_hdr}")
            magic = dir3_data_hdr.hdr.magic.to_bytes(4, "big")
            if (
                # dir3_data_hdr.hdr.magic in (0x58444233, 0x58444433) and blf_flags & XfsBlft.XFS_BLFT_DIR_BLOCK_BUF
                magic in (b"XDB3", b"XDD3") and blf_flags & XfsBlft.XFS_BLFT_DIR_BLOCK_BUF
            ):  # XDB3 = 0x58444233, XDD3 = 0x58444433
                for dir_entry in self._parse_block_directoreis(tmp_data[xfs_dir3_data_hdr.sizeof() :]):
                    yield buf_log_format.blf_blkno, dir3_data_hdr.hdr.owner, dir_entry
            # elif dir3_data_hdr.hdr.magic == 0x58534C4D:  # XSLM = 0x58534c4d
            elif magic == b"XSLM":  # XSLM = 0x58534c4d
                # XFS Algorithms & Data Structures, chapter 22.2 Extent Symbolic Links
                print("Found a log operation which has the XSLM magic number. Need to implement a parser for extent symbolic links.", file=sys.stderr)

        except StreamError:
            self.dbg_print("_parse_buffer_writes Exception StreamError")

    def _retrieve_log_ops(self, log_item: Container, log_ops: list[XfsLogOperation]) -> tuple[bool, list[XfsLogOperation]]:
        idx = 0
        tmp_log_ops: list[XfsLogOperation] = []
        try:
            self.dbg_print(f"_retrieve_log_ops log_ops: {log_ops}")
            if not self.incomplete_log_ops and log_item.magic in (xfs_structs.XFS_LI_INODE, xfs_structs.XFS_LI_BUF):  # 0x123B or 0x123C
                for i in range(log_item.size):
                    log_op = log_ops[idx + i]
                    tmp_log_ops.append(log_op)
                    if log_op.op_header.oh_flags & xfs_structs.XLOG_CONTINUE_TRANS:
                        self.incomplete_log_ops = tmp_log_ops
                        self.dbg_print(f"_retrieve_log_ops incomplete_log_ops: {self.incomplete_log_ops}")
                        break

            self.dbg_print(f"_retrieve_log_ops log_item.size: {log_item.size}")
            self.dbg_print(f"_retrieve_log_ops tmp_log_ops size: {len(tmp_log_ops)}")
            if len(tmp_log_ops) == log_item.size:
                self.incomplete_log_ops = []
                return True, tmp_log_ops
        except IndexError as err:
            self.dbg_print(f"_retrieve_log_ops IndexError: {err}")
            self.incomplete_log_ops = tmp_log_ops
            return False, tmp_log_ops
        else:
            return False, tmp_log_ops

    def _concatenate_log_ops(self, log_ops: list[XfsLogOperation]) -> list[XfsLogOperation]:
        if self.incomplete_log_ops:
            self.dbg_print(f"_concatenate_log_ops incomplete_log_ops: {self.incomplete_log_ops}")
            self.dbg_print(f"_concatenate_log_ops first log_op[0]: {log_ops[0]}")
            idx = 0
            tmp_data = b""
            tmp_log_ops = copy.deepcopy(self.incomplete_log_ops)
            if (
                tmp_log_ops[-1].op_header.oh_flags & xfs_structs.XLOG_CONTINUE_TRANS
                and log_ops[0].op_header.oh_flags & xfs_structs.XLOG_WAS_CONT_TRANS
            ):
                tmp_data = tmp_log_ops[-1].item_data
                while idx < len(log_ops):
                    tmp_data += log_ops[idx].item_data
                    if log_ops[idx].op_header.oh_flags & xfs_structs.XLOG_END_TRANS:
                        break
                    idx += 1

                tmp_log_ops[-1] = XfsLogOperation(tmp_log_ops[-1].op_header, tmp_data)
                tmp_log_ops[-1].op_header.oh_len = len(tmp_log_ops[-1].item_data)
                tmp_log_ops[-1].op_header.oh_flags |= log_ops[0].op_header.oh_flags
                # Clear oh_flags
                op_flags = tmp_log_ops[-1].op_header.oh_flags
                for f in (xfs_structs.XLOG_CONTINUE_TRANS, xfs_structs.XLOG_WAS_CONT_TRANS, xfs_structs.XLOG_END_TRANS):
                    if op_flags & f:
                        op_flags &= ~f
                tmp_log_ops[-1].op_header.oh_flags = op_flags
                tmp_log_ops.extend(log_ops[idx + 1 :])
                self.incomplete_log_ops = []
                self.dbg_print(f"_concatenate_log_ops concatenated log_ops: {tmp_log_ops}")
                return tmp_log_ops

            if tmp_log_ops[-1].op_header.oh_flags == 0:
                tmp_log_ops.extend(log_ops)
                self.incomplete_log_ops = []
                return tmp_log_ops

        return log_ops

    def parse_journal(self) -> None:
        log_records: dict[int, int] = {}  # dict[h_lsn, journal_addr]

        self._parse_xfs_superblock()

        first_log_rec_addr = self._find_first_log_record()  # This variable reflects the offset.
        if first_log_rec_addr == -1:
            msg = "Failed to find the first log record."
            raise LogRecordNotFoundError(msg)
        journal_addr = first_log_rec_addr

        # Find all log records and sort by h_lsn.
        while journal_addr < first_log_rec_addr + self.xfs_superblock.sb_logblocks * self.block_size:
            data = self._read_journal_data(journal_addr, 0x200)  # record header size is 0x200
            record_header = xlog_rec_header.parse(data)
            self.dbg_print(f"record_header: {record_header}")
            if record_header.h_magicno == xfs_structs.XLOG_HEADER_MAGIC and record_header.h_cycle > 0x0:
                if record_header.h_len >= xfs_structs.XLOG_HEADER_CYCLE_SIZE:
                    print(f"parse_journal xlog_rec_header.h_len is large: {record_header.h_len}", file=sys.stderr)
                    print("A parser for xlog_rec_ext_header structure might be needed.", file=sys.stderr)
                    print(f"journal_addr: {journal_addr}", file=sys.stderr)
                    print(f"record_header: {record_header}", file=sys.stderr)
                log_records[record_header.h_lsn] = journal_addr
            journal_addr += 0x200 + record_header.h_len  # record header size is 0x200

        sorted_log_records = dict(sorted(log_records.items()))  # Sort log records by h_lsn

        for journal_addr in sorted_log_records.values():
            data = self._read_journal_data(journal_addr, 0x200)  # record header size is 0x200
            record_header = xlog_rec_header.parse(data)
            self.dbg_print(f"record_header: {record_header}")
            if record_header.h_magicno == xfs_structs.XLOG_HEADER_MAGIC:
                transaction_id = record_header.h_lsn
                self.add_transaction(transaction_id)
                transaction = self.transactions[transaction_id]
                transaction.record_len = record_header.h_len
                transaction.record_format = record_header.h_fmt
                data = self._read_journal_data(journal_addr + 0x200, record_header.h_len)  # record header size is 0x200
                tid_real, log_ops = self._parse_log_operations(data, record_header.h_cycle_data)
                transaction.tid_real = tid_real
                self.dbg_print(f"Number of log operations: record_header.h_num_logops = {record_header.h_num_logops}, log_ops = {len(log_ops)}")
                if len(log_ops) == record_header.h_num_logops:
                    self.dbg_print("All log operations are found.")
                else:
                    self.dbg_print("Not all log operations are found.")

                if log_ops:
                    xfs_trans_header = xfs_log_item = None
                    match transaction.record_format:
                        case xfs_structs.XLOG_FMT_UNKNOWN:
                            print("Unknown log record format does not supported.", file=sys.stderr)
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
                        case _:
                            print(f"Unsupported log record format: {transaction.record_format}", file=sys.stderr)

                    # Concatenate log operations if there are incomplete log operations.
                    log_ops = self._concatenate_log_ops(log_ops)

                    idx = 0
                    if xfs_trans_header and xfs_log_item:
                        self.dbg_print(f"parse_journal log_ops: {log_ops}")
                        while idx < len(log_ops):
                            self.dbg_print(f"parse_journal log_ops[{idx}]: {log_ops[idx]}")
                            log_op = log_ops[idx]
                            op_size = 1
                            if log_op.op_header.oh_clientid == xfs_structs.XFS_TRANSACTION:  # TODO: consider to remove this line
                                if log_op.op_header.oh_flags == 0x0 or log_op.op_header.oh_flags & (
                                    xfs_structs.XLOG_COMMIT_TRANS
                                    | xfs_structs.XLOG_CONTINUE_TRANS
                                    | xfs_structs.XLOG_WAS_CONT_TRANS
                                    | xfs_structs.XLOG_END_TRANS
                                ):
                                    try:
                                        self.dbg_print(f"parse_journal log_op.item_data: {log_op.item_data}")
                                        log_item = xfs_log_item.parse(log_op.item_data)
                                        self.dbg_print(f"parse_journal log_item: {log_item}")
                                    except StreamError:
                                        self.dbg_print("parse_journal Exception StreamError")
                                        idx += 1
                                        continue
                                    match log_item.magic:
                                        case 0x414E | 0x5452:  # Little endian = "AN" | Big endian = "TR"
                                            trans_header = xfs_trans_header.parse(log_op.item_data)
                                            transaction.trans_state = TransState.TRANS_DESC
                                        case xfs_structs.XFS_LI_INODE:  # 0x123B
                                            op_size = log_item.size
                                            result, processing_log_ops = self._retrieve_log_ops(log_item, log_ops[idx : idx + op_size])
                                            if result:
                                                block_num, inode, dir_entries, eattrs, symlink_target, device_number, parent_inode = (
                                                    self._parse_inode_update(
                                                        processing_log_ops,
                                                    )
                                                )
                                                if inode:
                                                    self.transactions[transaction_id].set_inode_info(block_num, inode.di_ino, inode, eattrs)
                                                    self.transactions[transaction_id].entries[inode.di_ino].symlink_target = symlink_target
                                                    self.transactions[transaction_id].entries[inode.di_ino].device_number = device_number
                                                    dir_inode = inode.di_ino
                                                    if dir_entries:
                                                        for dir_entry in dir_entries:
                                                            transaction.set_dent_info(
                                                                block_num,
                                                                dir_inode,
                                                                parent_inode,
                                                                dir_entry.inumber,
                                                                dir_entry,
                                                            )
                                                    # If dir_entries is "[]", it means the last directory entry was deleted. Only "." and ".." are left.
                                                    # If dir_entries is "None", it means the log operations don't contain directory entries (inode_log_format_64.ilf_fields does not have xfs_structs.XFS_ILOG_DDATA flag).
                                                    elif self.transactions[transaction_id].entries[inode.di_ino].file_type == FileTypes.DIRECTORY:
                                                        if dir_entries == []:
                                                            transaction.set_dent_info(block_num, dir_inode, parent_inode, 0, [])
                                                        elif dir_entries is None:
                                                            transaction.set_dent_info(block_num, dir_inode, parent_inode, 0, None)
                                        case xfs_structs.XFS_LI_BUF:  # 0x123C
                                            op_size = log_item.size
                                            result, processing_log_ops = self._retrieve_log_ops(log_item, log_ops[idx : idx + op_size])
                                            if result:
                                                parent_inode = 0
                                                self.dbg_print("Directory entry:")
                                                for block_num, dir_inode, dir_entry in self._parse_buffer_writes(processing_log_ops):
                                                    if dir_entry.name == b".":
                                                        continue
                                                    if dir_entry.name == b"..":
                                                        parent_inode = dir_entry.inumber
                                                        continue
                                                    transaction.set_dent_info(block_num, dir_inode, parent_inode, dir_entry.inumber, dir_entry)
                                        case xfs_structs.XFS_LI_ICREATE:  # 0x123F
                                            # Implement parsing inode creation, but I have never seen this log item in journals.
                                            transaction.trans_state = TransState.INODE_CREATION
                                        case 0x4946:  # "IF" of "FIB3"
                                            if log_item.size == 0x3342:  # "3B" of "FIB3"
                                                pass
                                            else:  # Execute pass even if log_item.size is not 0x3342 now.
                                                pass
                                        case _:
                                            self.dbg_print(f"Unsupported log item magic: 0x{log_item.magic:x}")
                                            self.dbg_print(f"log_op.item_data[:0x100]: {log_op.item_data[:0x100]}")

                            idx += op_size

    def _reuse_predicate(self, differences: dict[str, tuple[EntryInfoTypes, EntryInfoTypes]]) -> bool:
        return ("file_type" in differences) or ("generation" in differences)

    def _detect_delete(self, transaction_entry: EntryInfoXfs, reuse_inode: bool) -> tuple[bool, int, int]:
        if (
            transaction_entry.file_type == FileTypes.UNKNOWN
            and transaction_entry.mode == 0
            # and transaction_entry.size == 0  # In many cases, size is 0 for deleted inodes. But not always.
            and transaction_entry.link_count == 0
            and reuse_inode
        ):
            return True, transaction_entry.ctime, transaction_entry.ctime_nanoseconds
        return False, 0, 0

    def _apply_flag_changes(self, new_flags: int) -> str:
        msg = ""
        if new_flags & xfs_structs.XFS_DIFLAG_IMMUTABLE:
            msg = self._append_msg(msg, "Immutable", " ")
        if new_flags & xfs_structs.XFS_DIFLAG_NOATIME:
            msg = self._append_msg(msg, "NoAtime", " ")
        if new_flags & xfs_structs.XFS_DIFLAG_PREALLOC:
            msg = self._append_msg(msg, "Preallocated", " ")
        return msg

    def _generate_timeline_event(self, transaction: JournalTransactionXfs, inode_num: int, working_entry: EntryInfoXfs) -> TimelineEventInfo | None:
        return self._generate_timeline_event_common(transaction, inode_num, working_entry, commit_ts=None)

    def timeline(self) -> None:
        working_entries: dict[int, EntryInfoXfs] = {}
        timeline_events: list[TimelineEventInfo] = []
        for tid in sorted(self.transactions):
            transaction = self.transactions[tid]
            self.update_directory_entries(transaction)

            for inode_num in transaction.entries:
                # Skip special inodes except the root inode
                # The root inode number is 128 and it is hanled as a normal inode here.
                if not self.special_inodes and inode_num < 128:
                    continue
                transaction_entry = transaction.entries[inode_num]
                # Generate working_entriy and first timeline event for each inode
                if not working_entries.get(inode_num):
                    msg = info = ""
                    action = Actions.UNKNOWN
                    working_entries[inode_num] = copy.deepcopy(transaction.entries[inode_num])
                    atime_f = self._to_float_ts(transaction_entry.atime, transaction_entry.atime_nanoseconds)
                    ctime_f = self._to_float_ts(transaction_entry.ctime, transaction_entry.ctime_nanoseconds)
                    mtime_f = self._to_float_ts(transaction_entry.mtime, transaction_entry.mtime_nanoseconds)
                    crtime_f = self._to_float_ts(transaction_entry.crtime, transaction_entry.crtime_nanoseconds)
                    dtime_f = 0.0

                    transaction_entry.names = self.retrieve_names_by_inodenum(inode_num)

                    is_delete, d_sec, d_nsec = self._detect_delete(transaction_entry, False)
                    if is_delete:
                        action |= Actions.DELETE_INODE
                        info = self._append_msg(info, self.format_timestamp(d_sec, d_nsec, label="Dtime", follow=False))
                        dtime_f = self._to_float_ts(d_sec, d_nsec)
                        self._refresh_directory_entries(inode_num, transaction)

                    if not (action & Actions.DELETE_INODE):
                        # Create inode
                        # - Creation of files in a directory updates the directory's ctime and mtime,
                        #   so a directory created almost simultaneously with a large number of files may not be detected.
                        #   Under the following conditions, differences of less than 1 second are ignored.
                        # - In some cases, such as creating symlinks, only atime is updated. So, it is removed from the condition.
                        if transaction_entry.crtime != 0 and transaction_entry.ctime == transaction_entry.mtime == transaction_entry.crtime:
                            action |= Actions.CREATE_INODE
                            msg = self.format_timestamp(
                                transaction_entry.crtime,
                                transaction_entry.crtime_nanoseconds,
                                label="Crtime",
                                follow=False,
                            )
                            info = self._append_msg(info, msg)

                        # Create hard link
                        if action & Actions.CREATE_INODE:
                            action |= Actions.CREATE_HARDLINK
                            if transaction_entry.link_count > 0:
                                info = self._append_msg(info, f"Link Count: {transaction_entry.link_count}")

                        for mac_type, mac_ts, act, label in (
                            ("atime", (transaction_entry.atime, transaction_entry.atime_nanoseconds), Actions.ACCESS, "Atime"),
                            ("ctime", (transaction_entry.ctime, transaction_entry.ctime_nanoseconds), Actions.CHANGE, "Ctime"),
                            ("mtime", (transaction_entry.mtime, transaction_entry.mtime_nanoseconds), Actions.MODIFY, "Mtime"),
                        ):
                            if self._timestomp((transaction_entry.crtime, transaction_entry.crtime_nanoseconds), mac_ts):
                                action |= act | Actions.TIMESTOMP
                                msg = self.format_timestamp(
                                    mac_ts[0],
                                    mac_ts[1],
                                    label=label,
                                    follow=False,
                                )
                                msg += f" (Timestomp: {mac_type} < crtime)"
                                info = self._append_msg(info, msg)

                        # Set flags
                        if transaction_entry.flags & (
                            xfs_structs.XFS_DIFLAG_IMMUTABLE | xfs_structs.XFS_DIFLAG_NOATIME | xfs_structs.XFS_DIFLAG_PREALLOC
                        ):
                            action |= Actions.CHANGE_FLAGS
                            info = self._append_msg(info, f"Flags: 0x{transaction_entry.flags:x}")
                            if add_info := self._apply_flag_changes(transaction_entry.flags):
                                info = self._append_msg(info, add_info, " ")

                    # Update working_entry with transaction_entry
                    working_entries[inode_num].names = copy.deepcopy(transaction_entry.names)

                    if action != Actions.UNKNOWN:
                        timeline_events.append(
                            TimelineEventInfo(
                                # transaction_id=tid,
                                transaction_id=transaction.tid_real,
                                inode=inode_num,
                                file_type=transaction_entry.file_type,
                                names=transaction_entry.names,
                                action=action,
                                mode=transaction_entry.mode,
                                uid=transaction_entry.uid,
                                gid=transaction_entry.gid,
                                size=transaction_entry.size,
                                atime=atime_f,
                                ctime=ctime_f,
                                mtime=mtime_f,
                                crtime=crtime_f,
                                dtime=dtime_f,
                                flags=transaction_entry.flags,
                                link_count=transaction_entry.link_count,
                                symlink_target=transaction_entry.symlink_target,
                                extended_attributes=transaction_entry.extended_attributes,
                                device_number=transaction_entry.device_number,
                                info=info,
                            ),
                        )

                # Sometimes transaction.entries[inode_num] has information only from only directory entries and does not have information from an inode.
                # In such cases, transaction.entries[inode_num] is updated with working_entries[inode_num] excepted name field.
                if transaction.entries[inode_num].entryinfo_source == EntryInfoSource.DIR_ENTRY:
                    tmp_entryinfo_source = copy.deepcopy(transaction.entries[inode_num].entryinfo_source)
                    transaction.entries[inode_num] = copy.deepcopy(working_entries[inode_num])
                    transaction.entries[inode_num].entryinfo_source = tmp_entryinfo_source | EntryInfoSource.WORKING_ENTRY

                # Generate timeline event for each inode
                if timeline_event := self._generate_timeline_event(transaction, inode_num, working_entries[inode_num]):
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
