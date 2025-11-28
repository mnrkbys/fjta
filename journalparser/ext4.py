#
# Copyright 2025 Minoru Kobayashi <unknownbit@gmail.com> (@unkn0wnbit)
#
#    This file is part of Forensic Journal Timeline Analyzer (FJTA).
#    Usage or distribution of this code is subject to the terms of the Apache License, Version 2.0.
#

# References:
# https://www.kernel.org/doc/html/latest/filesystems/ext4/journal.html
# https://www.kernel.org/doc/html/latest/filesystems/ext4/dynamic.html
# https://www.kernel.org/doc/html/latest/filesystems/ext4/overview.html#special-inodes
# https://www.kernel.org/doc/html/latest/filesystems/ext4/ifork.html
# https://github.com/torvalds/linux/blob/master/include/linux/jbd2.h
# https://github.com/torvalds/linux/blob/master/fs/ext4/namei.c
# https://github.com/torvalds/linux/blob/master/fs/ext4/ext4.h
# https://righteousit.com/wp-content/uploads/2024/04/understanding-ext4-part-1-extents.pdf
# https://righteousit.com/wp-content/uploads/2024/04/understanding-ext4-part-2-timestamps.pdf
# https://righteousit.com/wp-content/uploads/2024/04/understanding-ext4-part-3-extent-trees.pdf
# https://righteousit.com/wp-content/uploads/2024/04/understanding-ext4-part-4-demolition-derby.pdf
# https://righteousit.com/wp-content/uploads/2024/04/understanding-ext4-part-5-large-extents.pdf
# https://righteousit.com/wp-content/uploads/2024/04/understanding-ext4-part-6-directories.pdf
# https://righteousit.com/2024/09/04/more-on-ext4-timestamps-and-timestomping/

import copy
import json
import math
import re
import sys
from argparse import Namespace
from collections.abc import Generator
from dataclasses import dataclass, field
from pathlib import Path

import pytsk3
from construct import ConstError, Container, RangeError, StreamError

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
    ImageLike,
    JournalParserCommon,
    JournalTransaction,
    TimelineEventInfo,
)
from journalparser.structs import ext4_structs
from journalparser.structs.ext4_structs import (
    commit_header,
    dx_root,
    ext4_dir_entry_2,
    ext4_dir_entry_tail,
    ext4_extent,
    ext4_extent_header,
    ext4_group_desc,
    ext4_inode,
    ext4_superblock_s,
    ext4_xattr_entry,
    ext4_xattr_header,
    ext4_xattr_ibody_header,
    journal_block_tag3_s,
    journal_block_tag_s,
    journal_header_s,
    journal_superblock_s,
)


@dataclass(frozen=True)
class BgInodeTable:
    head: int
    len: int


@dataclass
class EntryInfoExt4(EntryInfo):
    dtime: int = 0
    dtime_nanoseconds: int = 0  # Not needed?
    external_ea_block_num: int = 0
    symlink_block_num: int = 0


@dataclass
class JournalTransactionExt4(JournalTransaction[EntryInfoExt4]):
    commit_time: int = 0
    commit_time_nanoseconds: int = 0
    external_ea_blocks: dict[int, list[ExtendedAttribute]] = field(default_factory=dict)  # dict[block_num, list[ExtendedAttribute]]
    symlink_extents: dict[int, str] = field(default_factory=dict)  # dict[block_num, symlink_target]

    def set_commit_time(self, commit: Container | None) -> None:
        if commit:
            self.commit_time = commit.h_commit_sec
            self.commit_time_nanoseconds = commit.h_commit_nsec

    def _retrieve_symlink_target(self, i_block: bytes) -> int | str:
        try:
            extent_header = ext4_extent_header.parse(i_block[0 : ext4_extent_header.sizeof()])
            if extent_header.eh_entries != 1:
                return "Not supporting multi extents in i_block"
            extent = ext4_extent.parse(i_block[ext4_extent_header.sizeof() : ext4_extent_header.sizeof() + ext4_extent.sizeof()])
            return extent.ee_start_hi << 32 | extent.ee_start_lo
        except ConstError:
            try:
                return i_block.decode("utf-8").rstrip("\x00")
            except UnicodeDecodeError:
                return i_block.hex()

    @staticmethod
    def _calc_extra_time(time: int, extra_time: int) -> tuple[int, int]:
        extra_bits = extra_time & 0x3
        time = extra_bits * 2**32 + time
        nano_seconds = extra_time >> 2
        return time, nano_seconds

    @classmethod
    def _adjust_time(cls, entry: EntryInfoExt4, inode: Container) -> None:
        entry.atime, entry.atime_nanoseconds = cls._calc_extra_time(inode.i_atime, inode.i_atime_extra)
        entry.ctime, entry.ctime_nanoseconds = cls._calc_extra_time(inode.i_ctime, inode.i_ctime_extra)
        entry.mtime, entry.mtime_nanoseconds = cls._calc_extra_time(inode.i_mtime, inode.i_mtime_extra)
        entry.crtime, entry.crtime_nanoseconds = cls._calc_extra_time(inode.i_crtime, inode.i_crtime_extra)

    def set_inode_info(self, block_num: int, inode_num: int, inode: Container, eattrs: list[ExtendedAttribute]) -> None:
        special_inodes = {
            0: "Doesn't exist",
            1: "List of defective blocks",
            2: "Root directory",
            3: "User quota",
            4: "Group quota",
            5: "Boot loader",
            6: "Undelete directory",
            7: "Reserved group descriptors inode",
            8: "Journal inode",
            9: "The exclude inode",
            10: "Replica inode",
            11: "lost+found",
        }

        if not self.entries.get(inode_num):
            self.entries[inode_num] = EntryInfoExt4()
        entry = self.entries[inode_num]
        entry.inode = inode_num
        if special_inodes.get(inode_num):
            entry.names[2] = [special_inodes[inode_num]]
            if not self.dents.get(2):
                self.dents[2] = DentInfo(dir_inode=2, parent_inode=2)
            if not self.dents[2].block_entries.get(block_num):
                self.dents[2].block_entries[block_num] = {}
            self.dents[2].block_entries[block_num].update({inode_num: [special_inodes[inode_num]]})

        entry.file_type = ext4_structs.FILETYPE_MAP.get(inode.i_mode & 0xF000, FileTypes.UNKNOWN)
        if entry.file_type == FileTypes.SYMBOLIC_LINK:
            result = self._retrieve_symlink_target(inode.i_block)
            if isinstance(result, str):
                entry.symlink_target = result
            elif isinstance(result, int):
                entry.symlink_block_num = result
        entry.mode = inode.i_mode & 0o7777  # Remove file type bits
        entry.uid = inode.i_osd2.l_i_uid_high << 16 | inode.i_uid
        entry.gid = inode.i_osd2.l_i_gid_high << 16 | inode.i_gid
        entry.size = inode.i_size_high << 32 | inode.i_size_lo
        self._adjust_time(entry, inode)  # Calculate MACB time
        entry.dtime = inode.i_dtime
        entry.dtime_nanoseconds = 0
        entry.flags = inode.i_flags
        entry.link_count = inode.i_links_count
        entry.external_ea_block_num = inode.i_osd2.l_i_file_acl_high << 32 | inode.i_file_acl_lo
        entry.extended_attributes = eattrs
        if inode.i_mode & 0xF000 in (ext4_structs.S_IFCHR, ext4_structs.S_IFBLK):
            device_num = int.from_bytes(inode.i_block[:2], byteorder="little")
            major = device_num >> 8
            minor = device_num & 0xFF
            entry.device_number = DeviceNumber(major, minor)
        entry.entryinfo_source |= EntryInfoSource.INODE

    def set_dent_info(self, block_num: int, dir_inode_num: int, parent_inode_num: int, inode_num: int, dir_entry: Container | list | None) -> None:
        # Set DentInfo (directory entry information)
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
                self.entries[dir_inode_num] = EntryInfoExt4(inode=dir_inode_num)
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

        # Set EntryInfo (file entry information)
        if dir_entry:
            if not self.entries.get(inode_num):
                self.entries[inode_num] = EntryInfoExt4(inode=inode_num)
            entry = self.entries[inode_num]

            # Set file type from directory entry
            match dir_entry.file_type:
                case ext4_structs.EXT4_FT_UNKNOWN:
                    entry.file_type = FileTypes.UNKNOWN
                case ext4_structs.EXT4_FT_REG_FILE:
                    entry.file_type = FileTypes.REGULAR_FILE
                case ext4_structs.EXT4_FT_DIR:
                    entry.file_type = FileTypes.DIRECTORY
                case ext4_structs.EXT4_FT_CHRDEV:
                    entry.file_type = FileTypes.CHARACTER_DEVICE
                case ext4_structs.EXT4_FT_BLKDEV:
                    entry.file_type = FileTypes.BLOCK_DEVICE
                case ext4_structs.EXT4_FT_FIFO:
                    entry.file_type = FileTypes.FIFO
                case ext4_structs.EXT4_FT_SOCK:
                    entry.file_type = FileTypes.SOCKET
                case ext4_structs.EXT4_FT_SYMLINK:
                    entry.file_type = FileTypes.SYMBOLIC_LINK

            entry.entryinfo_source |= EntryInfoSource.DIR_ENTRY


class JournalDescriptorNotFoundError(Exception):
    pass


class JournalParserExt4(JournalParserCommon[JournalTransactionExt4, EntryInfoExt4]):
    # def __init__(self, img_info: pytsk3.Img_Info | io.BufferedReader, fs_info: pytsk3.FS_Info | None, args: Namespace) -> None:
    def __init__(self, img_info: ImageLike, fs_info: pytsk3.FS_Info | None, args: Namespace, fstype: FsTypes = FsTypes.EXT4) -> None:
        super().__init__(img_info, fs_info, args)
        self.fstype = fstype
        self.dumpe2fs_path: Path | None = None

    def _create_transaction(self, tid: int) -> JournalTransactionExt4:
        return JournalTransactionExt4(tid=tid)

    def _parse_ext4_superblock(self) -> None:
        if self.fstype == FsTypes.EXT4:
            self.ext4_superblock = ext4_superblock_s.parse(self.img_info.read(self.offset + 0x400, ext4_superblock_s.sizeof()))
            if self.ext4_superblock.s_magic == 0xEF53:  # EXT4 superblock magic number is 0xEF53
                self.dbg_print(f"EXT4 superblock: {self.ext4_superblock}")
                self.s_inodes_per_group = self.ext4_superblock.s_inodes_per_group
                self.block_size = 2 ** (10 + self.ext4_superblock.s_log_block_size)
                self.s_inode_size = self.ext4_superblock.s_inode_size
            else:
                msg = f"Bad magic number in EXT4 superblock: 0x{self.ext4_superblock.s_magic:x}"
                raise ValueError(msg)

        elif self.fstype == FsTypes.EXPORTED_EXT4_JOURNAL:
            self.ext4_superblock = None

    def _parse_block_group_descriptors(self) -> None:
        if self.fstype != FsTypes.EXT4:
            return

        self.bg_descriptors: list[Container] = []
        block_idx = 1  # Skip first block (Group 0 padding + EXT4 superblock)
        found_empty_bg_desc = False
        while not found_empty_bg_desc:
            bg_desc_block_data = self.img_info.read(self.offset + block_idx * self.block_size, self.block_size)
            bg_desc_entry_idx = 0
            while bg_desc_entry_idx < self.block_size:
                bg_desc_entry_data = bg_desc_block_data[bg_desc_entry_idx : bg_desc_entry_idx + ext4_group_desc.sizeof()]
                # Empty block group descriptor must indicate the end of the block group descriptors.
                if bg_desc_entry_data == b"\x00" * ext4_group_desc.sizeof():
                    found_empty_bg_desc = True
                    break
                bg_desc = ext4_group_desc.parse(bg_desc_entry_data)
                self.dbg_print(f"Block group descriptor: {bg_desc}")
                self.bg_descriptors.append(bg_desc)
                bg_desc_entry_idx += ext4_group_desc.sizeof()

            block_idx += 1

    def _load_dumpe2fs(self, path: Path) -> bool:
        self.block_size = 0
        self.s_inodes_per_group = 0
        self.s_inode_size = 0
        inode_tables: list[BgInodeTable] = []

        pattern_block_size = re.compile(r"Block size:\s+(\d+)")
        pattern_inode_per_group = re.compile(r"Inodes per group:\s+(\d+)")
        pattern_inode_size = re.compile(r"Inode size:\s+(\d+)")
        pattern_inode_table = re.compile(r"Inode table at (\d+)-(\d+)")

        if not path.exists() or not path.is_file():
            return False

        with path.open("r", encoding="utf-8") as fp:
            for line in fp:
                if not self.block_size and (m_block_size := pattern_block_size.match(line)):
                    self.block_size = int(m_block_size.group(1))
                    continue
                if not self.s_inodes_per_group and (m_inode_per_group := pattern_inode_per_group.match(line)):
                    self.s_inodes_per_group = int(m_inode_per_group.group(1))
                    continue
                if not self.s_inode_size and (m_inode_size := pattern_inode_size.match(line)):
                    self.s_inode_size = int(m_inode_size.group(1))
                    continue

                if not inode_tables and (m_inode_table := pattern_inode_table.search(line)):
                    head = int(m_inode_table.group(1))
                    end = int(m_inode_table.group(2))
                    len = end - head + 1
                    inode_tables.append(BgInodeTable(head, len))

        self.inode_tables = inode_tables
        return all((self.block_size, self.s_inodes_per_group, self.s_inode_size, inode_tables))

    def _retrieve_inode_tables(self) -> None:
        if self.fstype != FsTypes.EXT4:
            return

        ext4_sb = self.ext4_superblock
        inode_tables: list[BgInodeTable] = []
        enable_64bit_size_block = self.ext4_superblock.s_feature_incompat & ext4_structs.EXT4_FEATURE_INCOMPAT_64BIT
        inode_table_len = math.ceil(ext4_sb.s_inodes_per_group * ext4_sb.s_inode_size / 2 ** (10 + ext4_sb.s_log_block_size))
        for bg_desc in self.bg_descriptors:
            if enable_64bit_size_block:
                inode_table_head = bg_desc.bg_inode_table_hi << 32 | bg_desc.bg_inode_table_lo
            else:
                inode_table_head = bg_desc.bg_inode_table_lo
            self.dbg_print(f"Block group inode table: {inode_table_head}, {inode_table_len}")
            inode_tables.append(BgInodeTable(inode_table_head, inode_table_len))
        self.inode_tables = inode_tables

    def _check_inode_table_range(self, t_blocknr: int) -> tuple[int, BgInodeTable | None]:
        inode_table_num = 0
        for inode_table in self.inode_tables:
            if inode_table.head <= t_blocknr < inode_table.head + inode_table.len:
                return inode_table_num, inode_table
            inode_table_num += 1
        return inode_table_num, None

    def _read_journal_block(self, block_num: int) -> bytes:
        journal_sb = self.journal_superblock
        if block_num < journal_sb.s_first:
            # return b""
            msg = "block_num is less than s_first"
            raise IndexError(msg)
        journal_data_len = journal_sb.s_maxlen - journal_sb.s_first
        read_pos = block_num % journal_data_len
        if read_pos == 0:
            read_pos = journal_data_len

        if self.fstype == FsTypes.EXT4:
            return self.journal_file.read_random(read_pos * journal_sb.s_blocksize, journal_sb.s_blocksize)
        # FsTypes.EXPORTED_EXT4_JOURNAL
        return self.img_info.read(read_pos * journal_sb.s_blocksize, journal_sb.s_blocksize)

    def _parse_journal_superblock(self) -> None:
        data = self.journal_file.read_random(0, self.block_size) if self.fstype == FsTypes.EXT4 else self.img_info.read(0, self.block_size)
        self.journal_superblock = journal_superblock_s.parse(data)
        self.dbg_print(f"Journal superblock: {self.journal_superblock}")
        self.jbd2_feature_incompat_revoke = bool(self.journal_superblock.s_feature_incompat & ext4_structs.JBD2_FEATURE_INCOMPAT_REVOKE)
        self.jbd2_feature_incompat_64bit = bool(self.journal_superblock.s_feature_incompat & ext4_structs.JBD2_FEATURE_INCOMPAT_64BIT)
        self.jbd2_feature_incompat_csum_v2 = bool(self.journal_superblock.s_feature_incompat & ext4_structs.JBD2_FEATURE_INCOMPAT_CSUM_V2)
        self.jbd2_feature_incompat_csum_v3 = bool(self.journal_superblock.s_feature_incompat & ext4_structs.JBD2_FEATURE_INCOMPAT_CSUM_V3)

    def _find_first_descriptor_block(self) -> int:
        journal_sb = self.journal_superblock
        self.dbg_print(f"Finding first descriptor block: {journal_sb.s_first}, {journal_sb.s_maxlen}")
        for block_num in range(journal_sb.s_first, journal_sb.s_maxlen):
            self.dbg_print(f"Block number: {block_num}")
            if self.fstype == FsTypes.EXT4:
                data = self.journal_file.read_random(block_num * journal_sb.s_blocksize, journal_sb.s_blocksize)
            else:  # FsTypes.EXPORTED_EXT4_JOURNAL
                data = self.img_info.read(block_num * journal_sb.s_blocksize, journal_sb.s_blocksize)
            self.dbg_print(f"Data: {data[:0x20]}")
            try:
                block_header = journal_header_s.parse(data)
                if block_header.h_blocktype == ext4_structs.JBD2_DESCRIPTOR_BLOCK:
                    self.dbg_print(f"First descriptor block: {block_num}")
                    return block_num
            except ConstError:
                self.dbg_print("Not descriptor block")
        return -1

    def _parse_descriptor_block_tags(self, data: bytes) -> list[Container]:
        idx = journal_header_s.sizeof()  # Skip journal header
        tags: list[Container] = []
        found_last_tag = False

        if self.jbd2_feature_incompat_csum_v3:
            tag_size = journal_block_tag3_s.sizeof()
            journal_block_tag = journal_block_tag3_s
        else:
            tag_size = journal_block_tag_s.sizeof()
            journal_block_tag = journal_block_tag_s

        while idx <= len(data) - tag_size:
            tag_data = data[idx : idx + tag_size]
            idx += tag_size
            # if tag_data == b"\x00" * tag_size:  # Skip empty tag
            #     continue

            tag = journal_block_tag.parse(tag_data)
            tags.append(tag)
            if not (tag.t_flags & ext4_structs.JBD2_FLAG_SAME_UUID):
                idx += 16  # Skip uuid (16 bytes)
            if tag.t_flags & ext4_structs.JBD2_FLAG_LAST_TAG:
                found_last_tag = True
                break

        if idx > len(data) - tag_size and not found_last_tag:
            print("_parse_descriptor_block_tags JBD2_FLAG_LAST_TAG not found.", file=sys.stderr)

        return tags

    def _parse_ea_entries(self, data: bytes, offset: int = 0) -> list[ExtendedAttribute]:
        attribute_name_indices = {
            0: "",
            ext4_structs.EXT4_XATTR_INDEX_USER: "user.",
            ext4_structs.EXT4_XATTR_INDEX_POSIX_ACL_ACCESS: "system.posix_acl_access",
            ext4_structs.EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT: "system.posix_acl_default",
            ext4_structs.EXT4_XATTR_INDEX_TRUSTED: "trusted.",
            ext4_structs.EXT4_XATTR_INDEX_SECURITY: "security.",
            ext4_structs.EXT4_XATTR_INDEX_SYSTEM: "system.",
            ext4_structs.EXT4_XATTR_INDEX_RICHACL: "system.richacl",
        }

        idx = offset
        eattrs: list[ExtendedAttribute] = []
        while idx < len(data):
            ea_name: str = ""
            ea_entry = ext4_xattr_entry.parse(data[idx:])
            entry_size = 0x10 + ea_entry.e_name_len + ((4 - (ea_entry.e_name_len % 4)) % 4)
            if ea_entry.e_name_len == 0 and ea_entry.e_name_index == 0 and ea_entry.e_value_offs == 0 and ea_entry.e_value_inum == 0:
                break
            if name_space := attribute_name_indices.get(ea_entry.e_name_index):
                ea_name = name_space
            ea_name += ea_entry.e_name.decode("utf-8")
            # Need to support INCOMPAT_EA_INODE (ea_entry.e_value_inum != 0)? It's not enabled by default.
            ea_value = data[ea_entry.e_value_offs : ea_entry.e_value_offs + ea_entry.e_value_size]
            eattrs.append(ExtendedAttribute(ea_name, ea_value))
            idx += entry_size
        return eattrs

    def _parse_ea_in_inode(self, data: bytes) -> list[ExtendedAttribute]:
        idx: int = 0
        eattrs: list[ExtendedAttribute] = []
        try:
            _ = ext4_xattr_ibody_header.parse(data[idx : idx + ext4_xattr_ibody_header.sizeof()])
            idx += ext4_xattr_ibody_header.sizeof()
            eattrs = self._parse_ea_entries(data[idx:])
        except (ConstError, StreamError):
            return eattrs
        else:
            return eattrs

    def _parse_inode_table(
        self,
        t_blocknr: int,
        inode_table_num: int,
        inode_table: BgInodeTable,
        data: bytes,
    ) -> Generator[tuple[int, Container, list[ExtendedAttribute]], None, None]:
        eattrs = []
        if inode_table.head <= t_blocknr < inode_table.head + inode_table.len:
            idx = 0
            first_inode_num_in_table_block = (
                (inode_table_num * self.s_inodes_per_group) + ((t_blocknr % inode_table.head) * (len(data) // self.s_inode_size)) + 1
            )
            while idx < len(data):
                inode_data = data[idx : idx + self.s_inode_size]
                # Empty inode (b"\00" * s_inode_size) is not a valid inode. So, it can be ignored probably.
                if inode_data != b"\x00" * self.s_inode_size and inode_data != b"\xff" * self.s_inode_size:
                    inode = ext4_inode.parse(inode_data)
                    if inode.i_mode & 0xF000 < ext4_structs.S_IFIFO or inode.i_mode & 0xF000 > ext4_structs.S_IFSOCK:
                        idx += self.s_inode_size
                        continue
                    inode_num = first_inode_num_in_table_block + (idx // self.s_inode_size)
                    eattrs = self._parse_ea_in_inode(data[idx + 128 + inode.i_extra_isize : idx + self.s_inode_size])
                    yield inode_num, inode, eattrs
                idx += self.s_inode_size

    def _parse_linear_directory(self, data: bytes) -> list[Container] | None:
        idx = 0
        dir_entries: list[Container] | None = []

        while idx < len(data) - ext4_dir_entry_tail.sizeof():
            dir_entry = ext4_dir_entry_2.parse(data[idx : idx + self.s_inode_size])
            if dir_entry.rec_len == 0:  # rec_len must not be zero
                break
            idx += dir_entry.rec_len
            if dir_entry.inode == 0 or dir_entry.name_len == 0 or dir_entry.file_type == ext4_structs.EXT4_FT_UNKNOWN:  # Skip an invalid entry
                continue
            dir_entries.append(dir_entry)

        return dir_entries

    def _parse_directory_entries(self, data: bytes) -> list[Container] | None:
        try:
            as_dx_root = dx_root.parse(data)
            if (
                as_dx_root.dot.rec_len == 12
                and as_dx_root.dot.name_len == 1
                and as_dx_root.dot.file_type == ext4_structs.EXT4_FT_DIR
                and as_dx_root.dot.name == b".\x00\x00\x00"
                and as_dx_root.dotdot.rec_len == 4084
                and as_dx_root.dotdot.name_len == 2
                and as_dx_root.dotdot.file_type == ext4_structs.EXT4_FT_DIR
                and as_dx_root.dotdot.name == b"..\x00\x00"
                and as_dx_root.dx_root_info.reserved_zero == 0
                and as_dx_root.dx_root_info.hash_version in range(7)
                and as_dx_root.dx_root_info.info_length == 8
                and as_dx_root.dx_root_info.indirect_levels in range(4)
            ):
                return [as_dx_root.dot, as_dx_root.dotdot]
            if (
                as_dx_root.dot.inode == 0 and as_dx_root.dot.rec_len == 0 and as_dx_root.dot.name_len == 0 and as_dx_root.dot.file_type == 0
            ):  # This data block must be a dx_node.
                pass
            else:
                return self._parse_linear_directory(data)
        except (StreamError, RangeError):
            try:
                return self._parse_linear_directory(data)
            except StreamError:
                self.dbg_print("_parse_directory_entries Exception StreamError")
                # yield None
                return None

    def parse_journal(self) -> None:
        journal_blocks: dict[int, int] = {}  # dict[h_sequence, block_num]
        tmp_journal_blocks: dict[int, int] = {}  # dict[h_sequence, block_num]

        self._parse_ext4_superblock()
        self._parse_block_group_descriptors()
        self._retrieve_inode_tables()
        if self.fstype == FsTypes.EXPORTED_EXT4_JOURNAL and self.dumpe2fs_path and not self._load_dumpe2fs(self.dumpe2fs_path):
            msg = f"Required ext4 superblock parameters are not found: {self.dumpe2fs_path}"
            raise ValueError(msg)

        self._parse_journal_superblock()
        journal_sb = self.journal_superblock
        first_desc_block = self._find_first_descriptor_block()
        if first_desc_block == -1:
            msg = "Failed to find the first descriptor block."
            raise JournalDescriptorNotFoundError(msg)
        # block_num indicates the block number in journal data, not the block number of the file system
        block_num = first_desc_block

        # Find all transactions in the journal and sort by h_sequence.
        pbar = self.tqdm(total=journal_sb.s_maxlen - journal_sb.s_first, desc="Finding transactions", unit="block", leave=False)
        found_descriptor_block = False
        while block_num < first_desc_block + journal_sb.s_maxlen - journal_sb.s_first:
            try:
                data = self._read_journal_block(block_num)
                block_header = journal_header_s.parse(data)
                self.dbg_print(f"Block header: {block_header}")
                if block_header.h_blocktype == ext4_structs.JBD2_DESCRIPTOR_BLOCK:
                    found_descriptor_block = True
                    tmp_journal_blocks[block_header.h_sequence] = block_num
                elif block_header.h_blocktype == ext4_structs.JBD2_COMMIT_BLOCK and found_descriptor_block:
                    journal_blocks.update(tmp_journal_blocks)
                    found_descriptor_block = False
            except ConstError:
                pass
            finally:
                block_num += 1
                pbar.update(1)
        pbar.close()

        sorted_journal_blocks = dict(sorted(journal_blocks.items()))

        for block_num in self.tqdm(sorted_journal_blocks.values(), desc="Parsing transactions", unit="transaction", leave=False):
            while True:
                try:
                    data = self._read_journal_block(block_num)
                    block_header = journal_header_s.parse(data)
                    self.dbg_print(f"Block header: {block_header}")
                    transaction_id = block_header.h_sequence

                    match block_header.h_blocktype:
                        case ext4_structs.JBD2_DESCRIPTOR_BLOCK:
                            self.dbg_print("JBD2_DESCRIPTOR_BLOCK")
                            self.add_transaction(transaction_id)
                            self.dbg_print(f"Transaction ID: {transaction_id}")
                            transaction = self.transactions[transaction_id]
                            tags = self._parse_descriptor_block_tags(data)
                            if tags:
                                for tag in self.tqdm(tags, desc="Parsing block tags", unit="tag", leave=False):
                                    self.dbg_print(f"Block tag: {tag}")
                                    if self.jbd2_feature_incompat_64bit:
                                        t_blocknr = tag.t_blocknr_high << 32 | tag.t_blocknr
                                    else:
                                        t_blocknr = tag.t_blocknr
                                    block_num += 1
                                    data_block = self._read_journal_block(block_num)
                                    # If block_num is a part of inode table, parse it as inode list.
                                    # If not, parse it as external extended attributes or ext4_dir_entry_2 entries.
                                    inode_table_num, inode_table = self._check_inode_table_range(t_blocknr)
                                    if inode_table:
                                        for inode_num, inode, eattrs in self._parse_inode_table(t_blocknr, inode_table_num, inode_table, data_block):
                                            self.dbg_print(f"Inode number: {inode_num}")
                                            self.dbg_print(f"Inode: {inode}")
                                            self.dbg_print(f"Extended attributes: {eattrs}")
                                            self.transactions[transaction_id].set_inode_info(t_blocknr, inode_num, inode, eattrs)
                                    else:
                                        try:
                                            symlink_target = data_block.decode("utf-8").rstrip("\x00")
                                            self.dbg_print(f"Symlink target: {symlink_target}")
                                            self.transactions[transaction_id].symlink_extents[t_blocknr] = symlink_target
                                        except UnicodeDecodeError:
                                            # Parse as external extended attributes
                                            try:
                                                _ = ext4_xattr_header.parse(data_block)
                                                self.transactions[transaction_id].external_ea_blocks[t_blocknr] = self._parse_ea_entries(
                                                    data_block,
                                                    ext4_xattr_header.sizeof(),
                                                )
                                                self.dbg_print(
                                                    f"External extended attributes {t_blocknr}: {self.transactions[transaction_id].external_ea_blocks[t_blocknr]}",
                                                )
                                            # Parse as directory entries
                                            except ConstError:
                                                try:
                                                    dir_inode = 0
                                                    parent_inode = 0
                                                    self.dbg_print("Directory entry:")
                                                    dir_entries = self._parse_directory_entries(data_block)
                                                    if dir_entries:
                                                        for dir_entry in dir_entries:
                                                            if dir_entry:
                                                                self.dbg_print(dir_entry)
                                                                if dir_entry.name.decode("utf-8").rstrip("\x00") == ".":
                                                                    dir_inode = dir_entry.inode
                                                                    continue
                                                                if dir_entry.name.decode("utf-8").rstrip("\x00") == "..":
                                                                    parent_inode = dir_entry.inode
                                                                    continue
                                                            transaction.set_dent_info(t_blocknr, dir_inode, parent_inode, dir_entry.inode, dir_entry)
                                                    elif dir_entries == []:
                                                        transaction.set_dent_info(t_blocknr, dir_inode, parent_inode, 0, [])
                                                    elif dir_entries == None:  # StreamError exception happened in _parse_directory_entries()?
                                                        transaction.set_dent_info(t_blocknr, dir_inode, parent_inode, 0, None)
                                                except UnicodeDecodeError:
                                                    pass

                        case ext4_structs.JBD2_COMMIT_BLOCK:
                            self.dbg_print("JBD2_COMMIT_BLOCK")
                            commit = commit_header.parse(data)
                            if self.transactions.get(transaction_id):
                                self.transactions[transaction_id].set_commit_time(commit)
                                break

                        case ext4_structs.JBD2_REVOKE_BLOCK:
                            self.dbg_print("JBD2_REVOKE_BLOCK")

                        case ext4_structs.JBD2_SUPERBLOCK_V1:
                            self.dbg_print("JBD2_SUPERBLOCK_V1 is not supported.")

                        case ext4_structs.JBD2_SUPERBLOCK_V2:
                            self.dbg_print("JBD2_SUPERBLOCK_V2")

                        case _:
                            msg = f"Invalid block type: {block_header.h_blocktype}"
                            raise TypeError(msg)

                except ConstError:
                    pass

                finally:
                    block_num += 1

    # ext4 inode does not have a field for managing file generations like XFS's di_gen field.
    # ext4's l_i_version field is not equivalent to XFS's di_gen field.
    # If the last timeline event of the inode can be checked and its action is DELETE_INODE, the inode in this transaction is considered a reuse.
    def _reuse_predicate(self, differences: dict[str, tuple[EntryInfoTypes, EntryInfoTypes]]) -> bool:
        # If crtime is changed from non-zero to another value and dtime is not changed, it is considered inode reuse without DELETE_INODE.
        if "crtime" in differences and "dtime" not in differences:
            old_crtime, new_crtime = differences["crtime"]
            return old_crtime != 0 and old_crtime < new_crtime if isinstance(old_crtime, int) and isinstance(new_crtime, int) else False

        # This condition was implemented just in case.
        # If file_type is changed, it is considered inode reuse.
        if "file_type" in differences:
            if "dtime" in differences:
                old_dtime, new_dtime = differences["dtime"]
                if isinstance(old_dtime, int) and isinstance(new_dtime, int) and old_dtime != 0 and new_dtime == 0:
                    return False
            return True

        return False

    def _detect_delete(self, transaction_entry: EntryInfoExt4, reuse_inode: bool) -> tuple[bool, int, int]:
        if transaction_entry.dtime != 0:
            if transaction_entry.dtime == transaction_entry.ctime:
                return True, transaction_entry.ctime, transaction_entry.ctime_nanoseconds
            return True, transaction_entry.dtime, transaction_entry.dtime_nanoseconds
        return False, 0, 0

    def _apply_flag_changes(self, new_flags: int) -> str:
        msg = ""
        if new_flags & ext4_structs.EXT4_IMMUTABLE_FL:
            msg = self._append_msg(msg, "Immutable", " ")
        if new_flags & ext4_structs.EXT4_NOATIME_FL:
            msg = self._append_msg(msg, "NoAtime", " ")
        return msg

    def _generate_timeline_event(self, transaction: JournalTransactionExt4, inode_num: int, working_entry: EntryInfoExt4) -> TimelineEventInfo | None:
        commit_ts = (transaction.commit_time, transaction.commit_time_nanoseconds)
        return self._generate_timeline_event_common(transaction, inode_num, working_entry, commit_ts)

    def timeline(self) -> None:
        working_entries: dict[int, EntryInfoExt4] = {}
        timeline_events: list[TimelineEventInfo] = []
        for tid in self.tqdm(sorted(self.transactions), desc="Generating timeline", unit="transaction", leave=False):
            transaction = self.transactions[tid]
            commit_ts = (transaction.commit_time, transaction.commit_time_nanoseconds)
            self.update_directory_entries(transaction)

            for inode_num in self.tqdm(transaction.entries, desc=f"Inffering file activity (Transaction {tid})", unit="entry", leave=False):
                # Skip special inodes except the root inode
                # The root inode number is 2 and it is hanled as a normal inode here.
                if not self.special_inodes and inode_num <= 11 and inode_num != 2:
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
                    dtime_f = self._to_float_ts(transaction_entry.dtime, transaction_entry.dtime_nanoseconds)

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
                            elif self._timestomp(mac_ts, commit_ts):
                                action |= act | Actions.TIMESTOMP
                                msg = self.format_timestamp(
                                    mac_ts[0],
                                    mac_ts[1],
                                    label=label,
                                    follow=False,
                                )
                                msg += f" (Timestomp: commit_time < {mac_type})"
                                info = self._append_msg(info, msg)

                        # Set flags
                        if transaction_entry.flags & (ext4_structs.EXT4_IMMUTABLE_FL | ext4_structs.EXT4_NOATIME_FL):
                            action |= Actions.CHANGE_FLAGS
                            info = self._append_msg(info, f"Flags: 0x{transaction_entry.flags:x}")
                            if add_info := self._apply_flag_changes(transaction_entry.flags):
                                info = self._append_msg(info, add_info, " ")

                    # Copy symlink target to working entry
                    if symlink_target := transaction.symlink_extents.get(working_entries[inode_num].symlink_block_num):
                        working_entries[inode_num].symlink_target = symlink_target
                    if symlink_target := transaction.symlink_extents.get(transaction_entry.symlink_block_num):
                        transaction_entry.symlink_target = symlink_target

                    # Update working_entry with transaction_entry
                    working_entries[inode_num].names = copy.deepcopy(transaction_entry.names)

                    if action != Actions.UNKNOWN:
                        timeline_events.append(
                            TimelineEventInfo(
                                transaction_id=tid,
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

                # Copy symlink target to current entry
                if symlink_target := transaction.symlink_extents.get(working_entries[inode_num].symlink_block_num):
                    if not transaction.entries.get(inode_num):
                        transaction.entries[inode_num] = copy.deepcopy(working_entries[inode_num])
                    transaction.entries[inode_num].symlink_target = symlink_target

                # Copy external extended attributes to current entry
                if eattrs := transaction.external_ea_blocks.get(working_entries[inode_num].external_ea_block_num):
                    if not transaction.entries.get(inode_num):
                        transaction.entries[inode_num] = copy.deepcopy(working_entries[inode_num])
                    transaction.entries[inode_num].extended_attributes.extend(eattrs)

                # Generate timeline event for each inode
                if timeline_event := self._generate_timeline_event(transaction, inode_num, working_entries[inode_num]):
                    timeline_events.append(timeline_event)

        for event in timeline_events:
            print(json.dumps(event.to_dict()))
