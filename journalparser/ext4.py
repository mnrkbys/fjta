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
from collections.abc import Generator
from dataclasses import dataclass, field

import pytsk3
from construct import ConstError, Container, RangeError, StreamError

from journalparser.common import (
    Actions,
    DentInfo,
    DeviceNumber,
    EntryInfo,
    EntryInfoSource,
    ExtendedAttribute,
    FileTypes,
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

    def set_inode_info(self, inode_num: int, inode: Container, eattrs: list[ExtendedAttribute]) -> None:
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
            if 2 not in entry.associated_dirs:
                entry.associated_dirs.append(2)
            entry.names.update({2: [special_inodes[inode_num]]})
            if not self.dents.get(2):
                self.dents[2] = DentInfo(dir_inode=2, parent_inode=2)
            self.dents[2].entries[inode_num] = [special_inodes[inode_num]]

        match inode.i_mode & 0xF000:
            case ext4_structs.EXT4_FT_UNKNOWN:
                entry.file_type = FileTypes.UNKNOWN
            case ext4_structs.S_IFREG:
                entry.file_type = FileTypes.REGULAR_FILE
            case ext4_structs.S_IFDIR:
                entry.file_type = FileTypes.DIRECTORY
            case ext4_structs.S_IFCHR:
                entry.file_type = FileTypes.CHARACTER_DEVICE
            case ext4_structs.S_IFBLK:
                entry.file_type = FileTypes.BLOCK_DEVICE
            case ext4_structs.S_IFIFO:
                entry.file_type = FileTypes.FIFO
            case ext4_structs.S_IFSOCK:
                entry.file_type = FileTypes.SOCKET
            case ext4_structs.S_IFLNK:
                entry.file_type = FileTypes.SYMBOLIC_LINK
                result = self._retrieve_symlink_target(inode.i_block)
                if isinstance(result, str):
                    entry.symlink_target = result
                elif isinstance(result, int):
                    entry.symlink_block_num = result
        entry.mode = inode.i_mode & 0o7777  # Remove file type bits
        entry.uid = inode.i_osd2.l_i_uid_high << 16 | inode.i_uid
        entry.gid = inode.i_osd2.l_i_gid_high << 16 | inode.i_gid
        entry.size = inode.i_size_high << 32 | inode.i_size_lo
        self._adjust_time(entry, inode)  # MACB time
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

    def set_dent_info(self, dir_inode_num: int, parent_inode_num: int, inode_num: int, dir_entry: Container | None) -> None:
        # Set DentInfo (directory entry information)
        if not self.dents.get(dir_inode_num):
            self.dents[dir_inode_num] = DentInfo(dir_inode=dir_inode_num, parent_inode=parent_inode_num)
        dent = self.dents[dir_inode_num]
        if dir_entry:
            try:
                name = dir_entry.name.decode("utf-8")
                if name not in dent.entries.get(inode_num, []):
                    if not dent.entries.get(inode_num):
                        dent.entries[inode_num] = []
                    dent.entries[inode_num].append(name)
            except UnicodeDecodeError:
                pass

        # Set EntryInfo (file entry information)
        if dir_entry:
            if not self.entries.get(inode_num):
                self.entries[inode_num] = EntryInfoExt4(inode=inode_num)
            entry = self.entries[inode_num]

            if dir_inode_num not in entry.associated_dirs:
                entry.associated_dirs.append(dir_inode_num)

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
    def __init__(self, img_info: pytsk3.Img_Info, fs_info: pytsk3.FS_Info, offset: int = 0, debug: bool = False) -> None:
        super().__init__(img_info, fs_info, offset, debug)

    def _create_transaction(self, tid: int) -> JournalTransactionExt4:
        return JournalTransactionExt4(tid)

    def _parse_ext4_superblock(self) -> None:
        self.ext4_superblock = ext4_superblock_s.parse(self.img_info.read(self.offset + 0x400, ext4_superblock_s.sizeof()))
        if self.ext4_superblock.s_magic == 0xEF53:  # EXT4 superblock magic number is 0xEF53
            self.dbg_print(f"EXT4 superblock: {self.ext4_superblock}")
            self.s_inode_size = self.ext4_superblock.s_inode_size
        else:
            msg = f"Bad magic number in EXT4 superblock: 0x{self.ext4_superblock.s_magic:x}"
            raise ValueError(msg)

    def _parse_block_group_descriptors(self) -> None:
        img_info = self.img_info
        self.bg_descriptors: list[Container] = []
        block_idx = 1  # Skip first block (Group 0 padding + EXT4 superblock)
        found_empty_bg_desc = False
        while not found_empty_bg_desc:
            bg_desc_block_data = img_info.read(self.offset + block_idx * self.block_size, self.block_size)
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

    def _retrieve_inode_tables(self) -> None:
        ext4_sb = self.ext4_superblock
        inode_tables: list[BgInodeTable] = []
        enable_64bit_size_block = self.ext4_superblock.s_feature_incompat & ext4_structs.EXT4_FEATURE_INCOMPAT_64BIT
        for bg_desc in self.bg_descriptors:
            if enable_64bit_size_block:
                inode_table_head = bg_desc.bg_inode_table_hi << 32 | bg_desc.bg_inode_table_lo
            else:
                inode_table_head = bg_desc.bg_inode_table_lo
            inode_table_len = math.ceil(ext4_sb.s_inodes_per_group * ext4_sb.s_inode_size / 2 ** (10 + ext4_sb.s_log_block_size))
            self.dbg_print(f"Block group inode table: {inode_table_head}, {inode_table_len}")
            inode_tables.append(BgInodeTable(inode_table_head, inode_table_len))
        self.inode_tables = inode_tables

    def _check_inode_table_range(self, t_blocknr: int) -> BgInodeTable | None:
        for inode_table in self.inode_tables:
            if inode_table.head <= t_blocknr < inode_table.head + inode_table.len:
                return inode_table
        return None

    def _read_journal_block(self, block_num: int) -> bytes:
        journal_sb = self.journal_superblock
        if block_num < journal_sb.s_first:
            return b""
        journal_data_len = journal_sb.s_maxlen - journal_sb.s_first
        read_pos = block_num % journal_data_len
        if read_pos == 0:
            read_pos = journal_data_len
        return self.journal_file.read_random(read_pos * journal_sb.s_blocksize, journal_sb.s_blocksize)

    def _parse_journal_superblock(self) -> None:
        data = self.journal_file.read_random(0, self.block_size)
        self.journal_superblock = journal_superblock_s.parse(data)
        self.dbg_print(f"Journal superblock: {self.journal_superblock}")
        self.jbd2_feature_incompat_revoke = bool(self.journal_superblock.s_feature_incompat & ext4_structs.JBD2_FEATURE_INCOMPAT_REVOKE)
        self.jbd2_feature_incompat_64bit = bool(self.journal_superblock.s_feature_incompat & ext4_structs.JBD2_FEATURE_INCOMPAT_64BIT)
        self.jbd2_feature_incompat_csum_v2 = bool(self.journal_superblock.s_feature_incompat & ext4_structs.JBD2_FEATURE_INCOMPAT_CSUM_V2)
        self.jbd2_feature_incompat_csum_v3 = bool(self.journal_superblock.s_feature_incompat & ext4_structs.JBD2_FEATURE_INCOMPAT_CSUM_V3)
        # if not (self.jbd2_feature_incompat_csum_v2 or self.jbd2_feature_incompat_csum_v3):
        #     msg = f"Unknown feature incompat value: {self.journal_superblock.s_feature_incompat}"
        #     raise ValueError(msg)

    def _find_first_descriptor_block(self) -> int:
        journal_sb = self.journal_superblock
        self.dbg_print(f"Finding first descriptor block: {journal_sb.s_first}, {journal_sb.s_maxlen}")
        for block_num in range(journal_sb.s_first, journal_sb.s_maxlen):
            self.dbg_print(f"Block number: {block_num}")
            data = self.journal_file.read_random(block_num * journal_sb.s_blocksize, journal_sb.s_blocksize)
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
        tags = []
        # while idx < len(data):
        #     if self.jbd2_feature_incompat_csum_v3:
        #         tag_size = journal_block_tag3_s.sizeof()
        #         tag_data = data[idx : idx + tag_size]
        #     else:
        #         tag_size = journal_block_tag_s.sizeof()
        #         tag_data = data[idx : idx + tag_size]

        #     idx += tag_size
        #     if tag_data == b"\x00" * tag_size:  # Skip empty tag
        #         continue

        #     tag = journal_block_tag3_s.parse(tag_data) if self.jbd2_feature_incompat_csum_v3 else journal_block_tag_s.parse(tag_data)
        #     tags.append(tag)
        #     if tag.t_flags & ext4_structs.JBD2_FLAG_LAST_TAG:
        #         break

        # tag_size = journal_block_tag3_s.sizeof() if self.jbd2_feature_incompat_csum_v3 else journal_block_tag_s.sizeof()
        if self.jbd2_feature_incompat_csum_v3:
            tag_size = journal_block_tag3_s.sizeof()
            journal_block_tag = journal_block_tag3_s
        else:
            tag_size = journal_block_tag_s.sizeof()
            journal_block_tag = journal_block_tag_s

        while idx <= len(data) - tag_size:
            # tag_data = data[idx : idx + tag_size] if self.jbd2_feature_incompat_csum_v3 else data[idx : idx + tag_size]
            tag_data = data[idx : idx + tag_size]

            idx += tag_size
            if tag_data == b"\x00" * tag_size:  # Skip empty tag
                continue

            # tag = journal_block_tag3_s.parse(tag_data) if self.jbd2_feature_incompat_csum_v3 else journal_block_tag_s.parse(tag_data)
            tag = journal_block_tag.parse(tag_data)
            tags.append(tag)
            if tag.t_flags & ext4_structs.JBD2_FLAG_LAST_TAG:
                break

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
            ea_name = ""
            ea_entry = ext4_xattr_entry.parse(data[idx:])
            # if ea_entry.e_name_len % 4 != 0:
            #     entry_size = 0x10 + ea_entry.e_name_len + (4 - (ea_entry.e_name_len % 4))
            # else:
            #     entry_size = 0x10 + ea_entry.e_name_len + (ea_entry.e_name_len % 4)
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
        idx = 0
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
        inode_table: BgInodeTable,
        data: bytes,
    ) -> Generator[tuple[int, Container, list[ExtendedAttribute]], None, None]:
        itable_head = inode_table.head
        itable_len = inode_table.len
        eattrs = []
        if itable_head <= t_blocknr < itable_head + itable_len:
            idx = 0
            first_inode_in_table = (t_blocknr % itable_head) * (len(data) // self.s_inode_size) + 1
            while idx < len(data):
                inode_data = data[idx : idx + self.s_inode_size]
                # Empty inode (b"\00" * s_inode_size) is not a valid inode. So, it can be ignored probably.
                if inode_data != b"\x00" * self.s_inode_size and inode_data != b"\xff" * self.s_inode_size:
                    inode = ext4_inode.parse(inode_data)
                    if inode.i_mode & 0xF000 < ext4_structs.S_IFIFO or inode.i_mode & 0xF000 > ext4_structs.S_IFSOCK:
                        idx += self.s_inode_size
                        continue
                    inode_num = first_inode_in_table + (idx // self.s_inode_size)
                    eattrs = self._parse_ea_in_inode(data[idx + 128 + inode.i_extra_isize : idx + self.s_inode_size])
                    yield inode_num, inode, eattrs
                idx += self.s_inode_size

    def _parse_linear_directory(self, data: bytes) -> Generator[Container, None, None]:
        idx = 0
        while idx < len(data) - ext4_dir_entry_tail.sizeof():
            dir_entry = ext4_dir_entry_2.parse(data[idx : idx + self.s_inode_size])
            if dir_entry.rec_len == 0:  # rec_len must not be zero
                break
            idx += dir_entry.rec_len
            if dir_entry.inode == 0 or dir_entry.name_len == 0 or dir_entry.file_type == ext4_structs.EXT4_FT_UNKNOWN:  # Skip an invalid entry
                continue
            yield dir_entry

    def _parse_directory_entries(self, data: bytes) -> Generator[Container | None, None, None]:
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
                yield as_dx_root.dot
                yield as_dx_root.dotdot
            elif (
                as_dx_root.dot.inode == 0 and as_dx_root.dot.rec_len == 0 and as_dx_root.dot.name_len == 0 and as_dx_root.dot.file_type == 0
            ):  # This data block must be a dx_node.
                pass
            else:
                yield from self._parse_linear_directory(data)
        except (StreamError, RangeError):
            try:
                yield from self._parse_linear_directory(data)
            except StreamError:
                yield None

    def parse_journal(self) -> None:
        self._parse_ext4_superblock()
        self._parse_block_group_descriptors()
        self._retrieve_inode_tables()
        self._parse_journal_superblock()
        journal_sb = self.journal_superblock
        first_desc_block = self._find_first_descriptor_block()
        if first_desc_block == -1:
            msg = "Failed to find the first descriptor block."
            raise JournalDescriptorNotFoundError(msg)
        # block_num indicates the block number in journal data, not the block number of the file system
        block_num = first_desc_block
        while block_num < first_desc_block + journal_sb.s_maxlen - journal_sb.s_first:
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
                            for tag in tags:
                                self.dbg_print(f"Block tag: {tag}")
                                if self.jbd2_feature_incompat_64bit:
                                    t_blocknr = tag.t_blocknr_high << 32 | tag.t_blocknr
                                else:
                                    t_blocknr = tag.t_blocknr
                                block_num += 1
                                data_block = self._read_journal_block(block_num)
                                # If block_num is a part of inode table, parse it as inode list.
                                # If not, parse it as external extended attributes or ext4_dir_entry_2 entries.
                                if inode_table := self._check_inode_table_range(t_blocknr):
                                    for inode_num, inode, eattrs in self._parse_inode_table(t_blocknr, inode_table, data_block):
                                        self.dbg_print(f"Inode number: {inode_num}")
                                        self.dbg_print(f"Inode: {inode}")
                                        self.dbg_print(f"Extended attributes: {eattrs}")
                                        self.transactions[transaction_id].set_inode_info(inode_num, inode, eattrs)
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
                                                # self.dbg_print(data_block[:0x30])
                                                for dir_entry in self._parse_directory_entries(data_block):
                                                    if dir_entry:
                                                        self.dbg_print(dir_entry)
                                                        if dir_entry.name.decode("utf-8") == ".":
                                                            dir_inode = dir_entry.inode
                                                            continue
                                                        if dir_entry.name.decode("utf-8") == "..":
                                                            parent_inode = dir_entry.inode
                                                            continue
                                                        transaction.set_dent_info(dir_inode, parent_inode, dir_entry.inode, dir_entry)
                                            except UnicodeDecodeError:
                                                pass

                    case ext4_structs.JBD2_COMMIT_BLOCK:
                        self.dbg_print("JBD2_COMMIT_BLOCK")
                        commit = commit_header.parse(data)
                        if self.transactions.get(transaction_id):
                            self.transactions[transaction_id].set_commit_time(commit)

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

            block_num += 1

    def _generate_timeline_event(
        self,
        transaction: JournalTransactionExt4,
        inode_num: int,
        working_entry: EntryInfoExt4,
    ) -> TimelineEventInfo | None:
        # print("=" * 50)
        # print(f"_generate_timeline_event2: tid={transaction.tid}")
        # print(f"_generate_timeline_event2: inode_num={inode_num}")
        # print(f"_generate_timeline_event2: working_entry={working_entry}")
        # print(f"_generate_timeline_event2: transaction.entries[{inode_num}]={transaction.entries[inode_num]}")
        # print(f"_generate_timeline_event2: transaction.dents={transaction.dents}")

        tid = transaction.tid
        transaction_entry = transaction.entries[inode_num]

        timeline_event = None
        action = Actions.UNKNOWN
        msg = info = ""

        atime_f = float(f"{transaction_entry.atime}.{transaction_entry.atime_nanoseconds:09d}")
        ctime_f = float(f"{transaction_entry.ctime}.{transaction_entry.ctime_nanoseconds:09d}")
        mtime_f = float(f"{transaction_entry.mtime}.{transaction_entry.mtime_nanoseconds:09d}")
        crtime_f = float(f"{transaction_entry.crtime}.{transaction_entry.crtime_nanoseconds:09d}")
        dtime_f = float(f"{transaction_entry.dtime}.{transaction_entry.dtime_nanoseconds:09d}")

        commit_time = self.transactions[tid].commit_time
        commit_time_nanoseconds = self.transactions[tid].commit_time_nanoseconds
        commit_time_f = float(f"{commit_time}.{commit_time_nanoseconds:09d}")

        self._build_names_from_entries(working_entry, transaction_entry, transaction.dents)

        # Delete inode
        # The ext4 inodes have a dtime field but ctime (and mtime) is more reliable for deletion detection.
        if transaction_entry.dtime != 0:
            action |= Actions.DELETE_INODE
            msg = self.format_timestamp(
                # transaction_entry.dtime,
                # transaction_entry.dtime_nanoseconds,
                transaction_entry.ctime,
                transaction_entry.ctime_nanoseconds,
                label="Dtime",
                follow=False,
            )
            info = self._append_msg(info, msg)
            dtime_f = ctime_f

        # Delete hard link
        if working_entry.link_count > transaction_entry.link_count:
            action |= Actions.DELETE_HARDLINK
            info = self._append_msg(info, f"Link Count: {working_entry.link_count} -> {transaction_entry.link_count}")
            info = self._append_msg(info, f"Filenames: {working_entry.names} -> {transaction_entry.names}")

        if not (action & Actions.DELETE_INODE) and (differences := self._compare_entry_fields(working_entry, transaction_entry)):
            for field, current_value, new_value in differences:
                match field:
                    case "crtime":  # Reuse inode or timestomping
                        current_crtime = current_value
                        current_crtime_nanoseconds = working_entry.crtime_nanoseconds
                        new_crtime = new_value
                        if result := self._filter_differences(differences, "crtime_nanoseconds"):
                            _, _, new_crtime_nanoseconds = result
                        else:
                            new_crtime_nanoseconds = current_crtime_nanoseconds

                        if transaction_entry.ctime == transaction_entry.mtime == transaction_entry.crtime:
                            action |= Actions.CREATE_INODE
                            msg = self.format_timestamp(current_crtime, current_crtime_nanoseconds, label="Crtime", follow=False)
                        else:
                            msg = self.format_timestamp(
                                current_crtime,
                                current_crtime_nanoseconds,
                                new_crtime,
                                new_crtime_nanoseconds,
                                "Crtime",
                            )

                        current_crtime_f = float(f"{current_crtime}.{current_crtime_nanoseconds:09d}")
                        new_crtime_f = float(f"{new_crtime}.{new_crtime_nanoseconds:09d}")
                        if new_crtime_f < current_crtime_f:
                            action |= Actions.TIMESTOMP
                            msg = self.format_timestamp(
                                current_crtime,
                                current_crtime_nanoseconds,
                                new_crtime,
                                new_crtime_nanoseconds,
                                "Crtime",
                            )
                            msg += " (Timestomp)"
                        elif commit_time_f < new_crtime_f:
                            action |= Actions.TIMESTOMP
                            msg = self.format_timestamp(
                                current_crtime,
                                current_crtime_nanoseconds,
                                new_crtime,
                                new_crtime_nanoseconds,
                                "Crtime",
                            )
                            msg += " (Timestomp: commit_time < crtime)"
                        info = self._append_msg(info, msg)
                    # case "dtime":
                    #     action |= Actions.DELETE_INODE
                    #     new_dtime = new_value
                    #     msg = self.format_timestamp(
                    #         new_dtime,
                    #         transaction_entry.dtime_nanoseconds,
                    #         label="Dtime",
                    #         follow=False,
                    #     )
                    #     info = self._append_msg(info, msg)
                    case "atime":
                        action |= Actions.ACCESS
                        current_atime = current_value
                        current_atime_nanoseconds = working_entry.atime_nanoseconds
                        new_atime = new_value
                        if result := self._filter_differences(differences, "atime_nanoseconds"):
                            _, _, new_atime_nanoseconds = result
                        else:
                            new_atime_nanoseconds = current_atime_nanoseconds
                        msg = self.format_timestamp(current_atime, current_atime_nanoseconds, new_atime, new_atime_nanoseconds, "Atime")

                        current_atime_f = float(f"{current_atime}.{current_atime_nanoseconds:09d}")
                        new_atime_f = float(f"{new_atime}.{new_atime_nanoseconds:09d}")
                        if new_atime_f < current_atime_f:
                            action |= Actions.TIMESTOMP
                            msg += " (Timestomp)"
                        elif commit_time_f < new_atime_f:
                            action |= Actions.TIMESTOMP
                            msg += " (Timestomp: commit_time < atime)"
                        info = self._append_msg(info, msg)
                    case "ctime":
                        action |= Actions.CHANGE
                        current_ctime = current_value
                        current_ctime_nanoseconds = working_entry.ctime_nanoseconds
                        new_ctime = new_value
                        if result := self._filter_differences(differences, "ctime_nanoseconds"):
                            _, _, new_ctime_nanoseconds = result
                        else:
                            new_ctime_nanoseconds = current_ctime_nanoseconds
                        msg = self.format_timestamp(current_ctime, current_ctime_nanoseconds, new_ctime, new_ctime_nanoseconds, "Ctime")

                        current_ctime_f = float(f"{current_ctime}.{current_ctime_nanoseconds:09d}")
                        new_ctime_f = float(f"{new_ctime}.{new_ctime_nanoseconds:09d}")
                        if new_ctime_f < current_ctime_f:
                            action |= Actions.TIMESTOMP
                            msg += " (Timestomp)"
                        elif commit_time_f < new_ctime_f:
                            action |= Actions.TIMESTOMP
                            msg += " (Timestomp: commit_time < ctime)"
                        info = self._append_msg(info, msg)
                    case "mtime":
                        action |= Actions.MODIFY
                        current_mtime = current_value
                        current_mtime_nanoseconds = working_entry.mtime_nanoseconds
                        new_mtime = new_value
                        if result := self._filter_differences(differences, "mtime_nanoseconds"):
                            _, _, new_mtime_nanoseconds = result
                        else:
                            new_mtime_nanoseconds = current_mtime_nanoseconds
                        msg = self.format_timestamp(current_mtime, current_mtime_nanoseconds, new_mtime, new_mtime_nanoseconds, "Mtime")

                        current_mtime_f = float(f"{current_mtime}.{current_mtime_nanoseconds:09d}")
                        new_mtime_f = float(f"{new_mtime}.{new_mtime_nanoseconds:09d}")
                        if new_mtime_f < current_mtime_f:
                            action |= Actions.TIMESTOMP
                            msg += " (Timestomp)"
                        elif commit_time_f < new_mtime_f:
                            action |= Actions.TIMESTOMP
                            msg += " (Timestomp: commit_time < mtime)"
                        info = self._append_msg(info, msg)
                    case "mode":
                        action |= Actions.CHANGE_MODE
                        info = self._append_msg(info, f"Mode: {current_value:04o} -> {new_value:04o}")
                    case "uid":
                        action |= Actions.CHANGE_UID
                        info = self._append_msg(info, f"UID: {current_value} -> {new_value}")
                        if new_value & ext4_structs.S_ISUID:
                            action |= Actions.SETUID
                            info += " (SetUID)"
                    case "gid":
                        action |= Actions.CHANGE_GID
                        info = self._append_msg(info, f"GID: {current_value} -> {new_value}")
                        if new_value & ext4_structs.S_ISGID:
                            action |= Actions.SETGID
                            info += " (SetGID)"
                    case "size":
                        if current_value < new_value:
                            action |= Actions.SIZE_UP
                        else:
                            action |= Actions.SIZE_DOWN
                        info = self._append_msg(info, f"Size: {current_value} -> {new_value}")
                    case "link_count":
                        if working_entry.link_count < transaction_entry.link_count:
                            action |= Actions.CREATE_HARDLINK
                            info = self._append_msg(
                                info,
                                f"Link Count: {working_entry.link_count} -> {transaction_entry.link_count}",
                            )
                        elif working_entry.link_count > transaction_entry.link_count:
                            action |= Actions.DELETE_HARDLINK
                            info = self._append_msg(
                                info,
                                f"Link Count: {working_entry.link_count} -> {transaction_entry.link_count}",
                            )
                    case "flags":
                        action |= Actions.CHANGE_FLAGS
                        info = self._append_msg(info, f"Flags: 0x{current_value:x} -> 0x{new_value:x}")
                        if new_value & ext4_structs.EXT4_IMMUTABLE_FL:
                            info = self._append_msg(info, "Immutable", " ")
                        elif new_value & ext4_structs.EXT4_NOATIME_FL:
                            info = self._append_msg(info, "NoAtime", "")
                    case "symlink_target":
                        action |= Actions.CHANGE_SYMLINK_TARGET
                        info = self._append_msg(info, f"Symlink Target: {current_value} -> {new_value}")
                    case "extended_attributes":
                        action |= Actions.CHANGE_EA
                        added_ea, removed_ea = self._compare_extended_attributes(current_value, new_value)
                        if added_ea:
                            added_ea_str = ", ".join(f"{ea}" for ea in added_ea)
                            info = self._append_msg(info, f"Added EA: {added_ea_str}")
                        if removed_ea:
                            removed_ea_str = ", ".join(f"{ea}" for ea in removed_ea)
                            info = self._append_msg(info, f"Removed EA: {removed_ea_str}")
                    case "names":
                        if working_entry.link_count == transaction_entry.link_count and working_entry.names != transaction_entry.names:
                            action |= Actions.MOVE
                            info = self._append_msg(info, f"Filenames: {working_entry.names} -> {transaction_entry.names}")
                    case _:
                        pass

            # Update working_entry with transaction_entry
            for field, _, new_value in differences:
                if field not in ("associated_dirs", "names"):
                    setattr(working_entry, field, new_value)
            working_entry.associated_dirs = copy.deepcopy(transaction_entry.associated_dirs)
            working_entry.names = copy.deepcopy(transaction_entry.names)

        if action != Actions.UNKNOWN:
            timeline_event = TimelineEventInfo(
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
            )

        return timeline_event

    def timeline(self) -> None:
        working_entries: dict[int, EntryInfoExt4] = {}
        timeline_events: list[TimelineEventInfo] = []
        for tid in sorted(self.transactions):
            transaction = self.transactions[tid]
            commit_time_f = float(f"{transaction.commit_time}.{transaction.commit_time_nanoseconds:09d}")
            for inode_num in transaction.entries:
                if inode_num <= 11 and inode_num != 2:
                    continue  # Skip special inodes
                transaction_entry = transaction.entries[inode_num]
                # Generate working_entriy and first timeline event for each inode
                if not working_entries.get(inode_num):
                    msg = info = ""
                    action = Actions.UNKNOWN
                    working_entries[inode_num] = copy.deepcopy(transaction.entries[inode_num])
                    atime_f = float(f"{transaction_entry.atime}.{transaction_entry.atime_nanoseconds:09d}")
                    ctime_f = float(f"{transaction_entry.ctime}.{transaction_entry.ctime_nanoseconds:09d}")
                    mtime_f = float(f"{transaction_entry.mtime}.{transaction_entry.mtime_nanoseconds:09d}")
                    crtime_f = float(f"{transaction_entry.crtime}.{transaction_entry.crtime_nanoseconds:09d}")
                    dtime_f = float(f"{transaction_entry.dtime}.{transaction_entry.dtime_nanoseconds:09d}")

                    self._build_names_from_entries(working_entries[inode_num], transaction_entry, transaction.dents)

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
                        info = self._append_msg(
                            info,
                            msg,
                        )

                    # Create hard link
                    if action & Actions.CREATE_INODE:
                        action |= Actions.CREATE_HARDLINK
                        if transaction_entry.link_count > 0:
                            info = self._append_msg(
                                info,
                                f"Link Count: {transaction_entry.link_count}",
                            )

                    # Delete inode
                    # The deletion time of XFS inodes is the same as ctime.
                    if transaction_entry.dtime != 0:
                        action |= Actions.DELETE_INODE
                        msg = self.format_timestamp(
                            transaction_entry.dtime,
                            transaction_entry.dtime_nanoseconds,
                            label="Dtime",
                            follow=False,
                        )
                        info = self._append_msg(
                            info,
                            msg,
                        )

                    # Timestomp atime
                    if atime_f < crtime_f:
                        action |= Actions.ACCESS | Actions.TIMESTOMP
                        msg = self.format_timestamp(
                            transaction_entry.atime,
                            transaction_entry.atime_nanoseconds,
                            label="Atime",
                            follow=False,
                        )
                        msg += " (Timestomp: atime < crtime)"
                        info = self._append_msg(info, msg)
                    elif commit_time_f < atime_f:
                        action |= Actions.ACCESS | Actions.TIMESTOMP
                        msg = self.format_timestamp(
                            transaction_entry.atime,
                            transaction_entry.atime_nanoseconds,
                            label="Atime",
                            follow=False,
                        )
                        msg += " (Timestomp: commit_time < atime)"
                        info = self._append_msg(info, msg)

                    # Timestomp ctime
                    if ctime_f < crtime_f:
                        action |= Actions.CHANGE | Actions.TIMESTOMP
                        msg = self.format_timestamp(
                            transaction_entry.ctime,
                            transaction_entry.ctime_nanoseconds,
                            label="Ctime",
                            follow=False,
                        )
                        msg += " (Timestomp: ctime < crtime)"
                        info = self._append_msg(info, msg)
                    elif commit_time_f < ctime_f:
                        action |= Actions.CHANGE | Actions.TIMESTOMP
                        msg = self.format_timestamp(
                            transaction_entry.ctime,
                            transaction_entry.ctime_nanoseconds,
                            label="Ctime",
                            follow=False,
                        )
                        msg += " (Timestomp: commit_time < ctime)"
                        info = self._append_msg(info, msg)

                    # Timestomp mtime
                    if mtime_f < crtime_f:
                        action |= Actions.MODIFY | Actions.TIMESTOMP
                        msg = self.format_timestamp(
                            transaction_entry.mtime,
                            transaction_entry.mtime_nanoseconds,
                            label="Mtime",
                            follow=False,
                        )
                        msg += " (Timestomp: mtime < crtime)"
                        info = self._append_msg(info, msg)
                    elif commit_time_f < mtime_f:
                        action |= Actions.MODIFY | Actions.TIMESTOMP
                        msg = self.format_timestamp(
                            transaction_entry.mtime,
                            transaction_entry.mtime_nanoseconds,
                            label="Mtime",
                            follow=False,
                        )
                        msg += " (Timestomp: commit_time < mtime)"
                        info = self._append_msg(info, msg)

                    # Set flags
                    if transaction_entry.flags & (ext4_structs.EXT4_IMMUTABLE_FL | ext4_structs.EXT4_NOATIME_FL):
                        action |= Actions.CHANGE_FLAGS
                        info = self._append_msg(info, f"Flags: 0x{transaction_entry.flags:x}")
                        if transaction_entry.flags & ext4_structs.EXT4_IMMUTABLE_FL:
                            info = self._append_msg(info, " Immutable", " ")
                        elif transaction_entry.flags & ext4_structs.EXT4_NOATIME_FL:
                            info = self._append_msg(info, " NoAtime", " ")

                    # Copy symlink target to working entry
                    if symlink_target := transaction.symlink_extents.get(working_entries[inode_num].symlink_block_num):
                        working_entries[inode_num].symlink_target = symlink_target
                    if symlink_target := transaction.symlink_extents.get(transaction_entry.symlink_block_num):
                        transaction_entry.symlink_target = symlink_target

                    # Update working_entry with transaction_entry
                    working_entries[inode_num].associated_dirs = copy.deepcopy(transaction_entry.associated_dirs)
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
                    transaction.entries[inode_num] = copy.deepcopy(working_entries[inode_num])
                    transaction.entries[inode_num].entryinfo_source |= EntryInfoSource.WORKING_ENTRY

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
