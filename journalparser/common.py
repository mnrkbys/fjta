#
# Copyright 2025 Minoru Kobayashi <unknownbit@gmail.com> (@unkn0wnbit)
#
#    This file is part of Forensic Journal Timeline Analyzer (FJTA).
#    Usage or distribution of this code is subject to the terms of the Apache License, Version 2.0.
#

import copy
import io
import os
from argparse import Namespace
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Flag, IntEnum, auto
from pathlib import Path
from typing import Protocol, cast, runtime_checkable

import pyewf
import pytsk3
import pyvhdi
import pyvmdk
from construct import Container, StreamError
from tqdm import tqdm as _tqdm
from tqdm.std import tqdm as TqdmType


class FsTypes(IntEnum):
    UNKNOWN = 0
    EXT4 = auto()
    XFS = auto()
    EXT4_EXPORTED_JOURNAL = auto()
    XFS_EXPORTED_JOURNAL = auto()


class DiskImgTypes(IntEnum):
    UNKNOWN = 0
    RAW = auto()
    EWF = auto()
    VMDK = auto()
    VHDI = auto()


@runtime_checkable
class ImageLike(Protocol):
    def read(self, offset: int, size: int) -> bytes: ...
    def get_size(self) -> int: ...
    def close(self) -> None: ...


class EWFImgInfo(pytsk3.Img_Info):
    def __init__(self, ewf_handle: pyewf.handle) -> None:
        self._ewf_handle: pyewf.handle = ewf_handle
        super().__init__(url="")

    def read(self, offset: int, size: int) -> bytes:
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)

    def get_size(self) -> int:
        return self._ewf_handle.get_media_size()

    def close(self) -> None:
        self._ewf_handle.close()
        super().close()


class VMDKImgInfo(pytsk3.Img_Info):
    def __init__(self, vmdk_handle: pyvmdk.handle) -> None:
        self._vmdk_handle: pyvmdk.handle = vmdk_handle
        super().__init__(url="")

    def read(self, offset: int, size: int) -> bytes:
        self._vmdk_handle.seek(offset)
        return self._vmdk_handle.read(size)

    def get_size(self) -> int:
        return self._vmdk_handle.get_media_size()

    def close(self) -> None:
        self._vmdk_handle.close()
        super().close()


class VHDIImgInfo(pytsk3.Img_Info):
    def __init__(self, vhdi_handle: pyvhdi.file) -> None:
        self._vhdi_handle: pyvhdi.file = vhdi_handle
        super().__init__(url="")

    def read(self, offset: int, size: int) -> bytes:
        self._vhdi_handle.seek(offset)
        return self._vhdi_handle.read(size)

    def get_size(self) -> int:
        return self._vhdi_handle.get_media_size()

    def close(self) -> None:
        self._vhdi_handle.close()
        super().close()


class RAWImgInfo:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._file = path.open("rb")

    def read(self, offset: int, size: int) -> bytes:
        self._file.seek(offset)
        return self._file.read(size)

    def get_size(self) -> int:
        return self._path.stat().st_size

    def close(self) -> None:
        self._file.close()


class FileTypes(IntEnum):
    UNKNOWN = 0
    REGULAR_FILE = auto()
    DIRECTORY = auto()
    CHARACTER_DEVICE = auto()
    BLOCK_DEVICE = auto()
    FIFO = auto()
    SOCKET = auto()
    SYMBOLIC_LINK = auto()


class Actions(Flag):
    UNKNOWN = 0
    CREATE_INODE = auto()
    CREATE_HARDLINK = auto()
    DELETE_INODE = auto()
    DELETE_HARDLINK = auto()
    REUSE_INODE = auto()
    RENAME = auto()
    MOVE = auto()
    ACCESS = auto()
    CHANGE = auto()
    MODIFY = auto()
    TIMESTOMP = auto()
    SETUID = auto()
    SETGID = auto()
    CHANGE_UID = auto()
    CHANGE_GID = auto()
    CHANGE_MODE = auto()
    SIZE_UP = auto()
    SIZE_DOWN = auto()
    CHANGE_FLAGS = auto()
    CHANGE_SYMLINK_TARGET = auto()
    CHANGE_EA = auto()


class EntryInfoSource(Flag):
    UNKNOWN = 0
    INODE = auto()
    DIR_ENTRY = auto()
    WORKING_ENTRY = auto()


@dataclass
class DeviceNumber:
    major: int = 0
    minor: int = 0

    def to_dict(self) -> dict:
        return {"major": self.major, "minor": self.minor}


@dataclass
class ExtendedAttribute:
    name: str = ""
    value: bytes = b""

    def __hash__(self) -> int:
        return hash((self.name, self.value))

    def __str__(self) -> str:
        try:
            value_str = self.value.decode("utf-8")
        except UnicodeDecodeError:
            value_str = self.value.hex()
        return f"{self.name}: {value_str}"

    def to_dict(self) -> dict:
        try:
            value_str = self.value.decode("utf-8")
        except UnicodeDecodeError:
            value_str = self.value.hex()
        return {"name": self.name, "value": value_str}


@dataclass
class DentInfo:
    dir_inode: int = 0  # Inode number of the directory containing this entry
    parent_inode: int = 0  # Actually not needed?
    block_entries: dict[int, dict[int, list[str]]] = field(default_factory=dict)  # dict[block_num, dict[inode_num, list[name]]]

    def find_names_by_inodenum(self, inode_num: int) -> list[str]:
        """
        Find names associated with a specific inode number.
        Returns an empty list if the inode number is not found.
        """
        names: list[str] = []
        for block_entry in self.block_entries.values():
            if block_entry.get(inode_num) and block_entry[inode_num] not in names:
                names.extend(block_entry[inode_num])
        return list(set(names))


@dataclass
class EntryInfo:
    inode: int = 0
    file_type: FileTypes = FileTypes.UNKNOWN
    names: dict[int, list[str]] = field(default_factory=dict)  # dict[dir_inode, list[name]]
    mode: int = 0
    uid: int = 0
    gid: int = 0
    size: int = 0
    atime: int = 0  # Is it better change int to float?
    atime_nanoseconds: int = 0
    ctime: int = 0
    ctime_nanoseconds: int = 0
    mtime: int = 0
    mtime_nanoseconds: int = 0
    crtime: int = 0
    crtime_nanoseconds: int = 0
    flags: int = 0
    link_count: int = 0
    symlink_target: str = ""
    extended_attributes: list[ExtendedAttribute] = field(default_factory=list)
    device_number: DeviceNumber = field(default_factory=DeviceNumber)
    entryinfo_source: EntryInfoSource = EntryInfoSource.UNKNOWN


EntryInfoTypes = int | str | FileTypes | list[ExtendedAttribute] | DeviceNumber | EntryInfoSource


@dataclass
class JournalTransaction[T: EntryInfo]:
    tid: int  # transaction id
    entries: dict[int, T] = field(default_factory=dict)  # dict[inode_num, EntryInfo]
    dents: dict[int, DentInfo] = field(default_factory=dict)  # dict[dir_inode, DentInfo]

    def set_inode_info(self, block_num: int, inode_num: int, inode: Container, eattrs: list[ExtendedAttribute]) -> None:
        msg = "Subclasses must implement set_inode_info."
        raise NotImplementedError(msg)

    def set_dir_entry_info(self, inode_num: int, dir_entry: Container) -> None:
        msg = "Subclasses must implement set_dir_entry_info."
        raise NotImplementedError(msg)

    def set_dent_info(self, block_num: int, dir_inode_num: int, parent_inode_num: int, inode_num: int, dir_entry: Container) -> None:
        msg = "Subclasses must implement set_dent_info."
        raise NotImplementedError(msg)

    # def retrieve_names_by_inodenum(self, inode_num: int) -> dict[int, list[str]]:
    #     names: dict[int, list[str]] = {}
    #     for dir_inode, dir_entries in self.dents.items():
    #         if tmp_names := dir_entries.find_names_by_inodenum(inode_num):
    #             # names.update({dir_inode: tmp_names})
    #             names[dir_inode] = tmp_names
    #     return names


@dataclass
class TimelineEventInfo:
    transaction_id: int = 0
    action: Actions = Actions.UNKNOWN
    inode: int = 0
    file_type: FileTypes = FileTypes.UNKNOWN
    names: dict[int, list[str]] = field(default_factory=dict)  # dict[dir_inode, list[name]]
    mode: int = 0
    uid: int = 0
    gid: int = 0
    size: int = 0
    atime: float = 0
    ctime: float = 0
    mtime: float = 0
    crtime: float = 0
    dtime: float = 0
    flags: int = 0
    link_count: int = 0
    symlink_target: str = ""
    extended_attributes: list[ExtendedAttribute] = field(default_factory=list)
    device_number: DeviceNumber = field(default_factory=DeviceNumber)
    info: str = ""

    def to_dict(self) -> dict:
        result = {}
        for tl_field in self.__dataclass_fields__:
            value = getattr(self, tl_field)
            if isinstance(value, Flag | FileTypes | Actions):
                result[tl_field] = value.name
            elif isinstance(value, list) and all(isinstance(item, ExtendedAttribute) for item in value):
                result[tl_field] = [item.to_dict() for item in value]
            # elif isinstance(value, dict) and all(isinstance(entry, DentInfo) for entry in value.values()):
            #     result[tl_field] = {dir_inode: entry.to_dict() for dir_inode, entry in value.items()}
            elif isinstance(value, DeviceNumber):
                result[tl_field] = value.to_dict()
            else:
                result[tl_field] = value
        return result


class JournalParserCommon[T: JournalTransaction, U: EntryInfo]:
    # io.BufferedReader might not be needed
    def __init__(self, img_info: ImageLike | io.BufferedReader, fs_info: pytsk3.FS_Info | None, args: Namespace) -> None:
        self.fstype = FsTypes.UNKNOWN
        self.img_info = img_info
        self.fs_info = fs_info
        self.offset = args.offset
        self.debug = args.debug
        self.special_inodes = args.special_inodes
        self.no_progress = args.no_progress
        # self.endian = self.fs_info.info.endian  # 1 = pytsk3.TSK_LIT_ENDIAN, 2 = pytsk3.TSK_BIG_ENDIAN
        self.block_size = 0
        self.journal_file = None  # Used in ext4
        if self.fs_info and self.fs_info.info.journ_inum != 0:
            # self.block_size = self.fs_info.info.block_size
            self.journal_file = self.fs_info.open_meta(self.fs_info.info.journ_inum)
        self.transactions: dict[int, T] = {}  # dict[transaction_id, JournalTransaction]
        self.working_dents: dict[int, DentInfo] = {}  # dict[dir_inode, DentInfo]

    def dbg_print(self, msg: str | Container | StreamError) -> None:
        if self.debug:
            print(msg)

    def tqdm(self, *args, **kwargs) -> TqdmType:
        if "disable" not in kwargs:
            kwargs["disable"] = self.no_progress
        return _tqdm(*args, **kwargs)

    def read_data(self, address: int, size: int) -> bytes:
        if isinstance(self.img_info, ImageLike):
            return self.img_info.read(address, size)
        if isinstance(self.img_info, io.BufferedReader):  # io.BufferedReader might not be needed
            self.img_info.seek(address, os.SEEK_SET)
            return self.img_info.read(size)
        raise TypeError("img_info must be either pytsk3.Img_Info or io.BufferedReader.")

    def _create_transaction(self, tid: int) -> T:
        msg = "Subclasses must implement _create_transaction."
        raise NotImplementedError(msg)

    def add_transaction(self, tid: int, transaction: T | None = None) -> None:
        if transaction is None or not self.transactions.get(tid):
            transaction = self._create_transaction(tid)
        self.transactions[tid] = transaction

    def parse_journal(self) -> None:
        msg = "Subclasses must implement parse_journal."
        raise NotImplementedError(msg)

    @staticmethod
    def _compare_entry_fields(current_entry: U, new_entry: U) -> dict[str, tuple[EntryInfoTypes, EntryInfoTypes]]:
        differences: dict[str, tuple[EntryInfoTypes, EntryInfoTypes]] = {}
        for entry_field in current_entry.__dataclass_fields__:
            if entry_field in ("entryinfo_source",):
                continue
            current_value = getattr(current_entry, entry_field)
            new_value = getattr(new_entry, entry_field)
            if current_value != new_value:
                differences[entry_field] = (current_value, new_value)
        return differences

    # @staticmethod
    # def _filter_differences(differences: list[tuple[str, any, any]], field: str) -> tuple[str, any, any] | tuple:
    #     filterd_diffs = list(filter(lambda x: x[0] == field, differences))
    #     if filterd_diffs:
    #         return filterd_diffs[0]
    #     return ()

    @staticmethod
    def _append_msg(orig_msg: str, msg: str, delimiter: str = "|") -> str:
        if orig_msg:
            return f"{orig_msg}{delimiter}{msg}"
        return msg

    @staticmethod
    def _compare_extended_attributes(
        current_eattrs: list[ExtendedAttribute],
        new_eattrs: list[ExtendedAttribute],
    ) -> tuple[set[ExtendedAttribute], set[ExtendedAttribute]]:
        current_set = set(current_eattrs)
        new_set = set(new_eattrs)
        added = new_set - current_set
        removed = current_set - new_set
        return added, removed

    @staticmethod
    def _contains_control_chars(s: str, th_min: int = 0x01, th_max: int = 0x1F) -> bool:
        return any(th_min <= ord(c) <= th_max for c in s)

    @classmethod
    def _contains_control_chars_bytes(cls, data: bytes, th_min: int = 0x01, th_max: int = 0x1F) -> bool:
        try:
            s = data.decode("utf-8")
        except UnicodeDecodeError:
            return True
        return cls._contains_control_chars(s, th_min, th_max)

    @staticmethod
    def format_timestamp(
        timestamp: int,
        nanoseconds: int,
        new_timestamp: int = 0,
        new_nanoseconds: int = 0,
        label: str = "Time",
        follow: bool = True,
    ) -> str:
        msg = f"{label}: {datetime.fromtimestamp(timestamp, tz=UTC).strftime('%Y-%m-%d %H:%M:%S')}.{nanoseconds:09d} UTC"
        if follow:
            msg += f" -> {datetime.fromtimestamp(new_timestamp, tz=UTC).strftime('%Y-%m-%d %H:%M:%S')}.{new_nanoseconds:09d} UTC"
        return msg

    @staticmethod
    def _to_float_ts(sec: int, nsec: int) -> float:
        return float(f"{sec}.{nsec:09d}")

    def update_directory_entries(self, transaction: T) -> None:
        for dir_inode, dir_entries in transaction.dents.items():
            if not self.working_dents.get(dir_inode):
                self.working_dents[dir_inode] = copy.deepcopy(dir_entries)
            elif transaction.entries.get(dir_inode) and transaction.entries[dir_inode].entryinfo_source & EntryInfoSource.DIR_ENTRY:
                for block_num in dir_entries.block_entries:
                    if not self.working_dents[dir_inode].block_entries.get(block_num):
                        self.working_dents[dir_inode].block_entries[block_num] = {}
                    self.working_dents[dir_inode].block_entries[block_num] = copy.deepcopy(dir_entries.block_entries[block_num])

    def remove_directory_entries(self, inode_num: int) -> None:
        for dir_inode, dir_entries in self.working_dents.items():
            for block_num in list(dir_entries.block_entries):
                if inode_num in dir_entries.block_entries.get(block_num, {}):
                    self.working_dents[dir_inode].block_entries[block_num].pop(inode_num)
                    if not self.working_dents[dir_inode].block_entries[block_num]:
                        del self.working_dents[dir_inode].block_entries[block_num]

    def _refresh_directory_entries(self, inode_num: int, transaction: T) -> None:
        self.remove_directory_entries(inode_num)
        self.update_directory_entries(transaction)

    def retrieve_names_by_inodenum(self, inode_num: int) -> dict[int, list[str]]:
        names: dict[int, list[str]] = {}
        for dir_inode, dir_entries in self.working_dents.items():
            if tmp_names := dir_entries.find_names_by_inodenum(inode_num):
                names[dir_inode] = tmp_names
        return names

    def _reuse_predicate(self, differences: dict[str, tuple[EntryInfoTypes, EntryInfoTypes]]) -> bool:
        raise NotImplementedError

    def _detect_delete(self, transaction_entry: U, reuse_inode: bool) -> tuple[bool, int, int]:
        raise NotImplementedError

    def _timestomp(self, cur_ts: tuple[int, int], new_ts: tuple[int, int]) -> bool:
        return self._to_float_ts(*new_ts) < self._to_float_ts(*cur_ts)

    def _apply_flag_changes(self, new_flags: int) -> str:
        # ext4: EXT4_* / XFS: XFS_DIFLAG_*
        raise NotImplementedError

    @staticmethod
    def _update_working_entry_fields(
        working_entry: U,
        transaction_entry: U,
        differences: dict[str, tuple[EntryInfoTypes, EntryInfoTypes]],
    ) -> None:
        for field_name in differences:
            if field_name != "names":
                setattr(working_entry, field_name, differences[field_name][1])
        working_entry.names = copy.deepcopy(transaction_entry.names)

    def _generate_timeline_event_common(
        self,
        transaction: T,
        inode_num: int,
        working_entry: U,
        commit_ts: tuple[int, int] | None,
    ) -> TimelineEventInfo | None:
        tid = transaction.tid
        transaction_entry = transaction.entries[inode_num]

        timeline_event = None
        action = Actions.UNKNOWN
        msg = info = ""
        reuse_inode = False

        atime_f = self._to_float_ts(transaction_entry.atime, transaction_entry.atime_nanoseconds)
        ctime_f = self._to_float_ts(transaction_entry.ctime, transaction_entry.ctime_nanoseconds)
        mtime_f = self._to_float_ts(transaction_entry.mtime, transaction_entry.mtime_nanoseconds)
        crtime_f = self._to_float_ts(transaction_entry.crtime, transaction_entry.crtime_nanoseconds)
        dtime_f = 0.0

        diffs = self._compare_entry_fields(working_entry, transaction_entry)

        reuse_inode = self._reuse_predicate(diffs)
        if reuse_inode:
            self._refresh_directory_entries(inode_num, transaction)

        if "atime" in diffs or "ctime" in diffs or "mtime" in diffs:
            is_delete, d_sec, d_nsec = self._detect_delete(transaction_entry, reuse_inode)
            if is_delete:
                action |= Actions.DELETE_INODE
                info = self._append_msg(info, self.format_timestamp(d_sec, d_nsec, label="Dtime", follow=False))
                dtime_f = self._to_float_ts(d_sec, d_nsec)
                self._refresh_directory_entries(inode_num, transaction)

        # refresh names from current working dents
        transaction_entry.names = self.retrieve_names_by_inodenum(inode_num)

        if not (action & Actions.DELETE_INODE) and reuse_inode:
            action |= Actions.REUSE_INODE

        # per-field updates
        if not (action & Actions.DELETE_INODE) and diffs:
            # crtime
            if "crtime" in diffs:
                cur_sec, new_sec = cast("tuple[int, int]", diffs["crtime"])
                cur_nsec = working_entry.crtime_nanoseconds
                new_nsec: int = cast("int", diffs.get("crtime_nanoseconds", (cur_nsec, cur_nsec))[1])
                if reuse_inode or (transaction_entry.ctime == transaction_entry.mtime == transaction_entry.crtime):
                    action |= Actions.CREATE_INODE
                    info = self._append_msg(info, self.format_timestamp(new_sec, new_nsec, label="Crtime", follow=False))
                else:
                    msg = self.format_timestamp(cur_sec, cur_nsec, new_sec, new_nsec, "Crtime")
                    if self._timestomp((cur_sec, cur_nsec), (new_sec, new_nsec)):
                        action |= Actions.TIMESTOMP
                        msg += " (Timestomp)"
                    elif commit_ts and self._timestomp((new_sec, new_nsec), commit_ts):
                        action |= Actions.TIMESTOMP
                        msg += " (Timestomp: commit_time < crtime)"
                    info = self._append_msg(info, msg)

            # atime / ctime / mtime
            for field_name, act, label in (
                ("atime", Actions.ACCESS, "Atime"),
                ("ctime", Actions.CHANGE, "Ctime"),
                ("mtime", Actions.MODIFY, "Mtime"),
            ):
                if reuse_inode or field_name not in diffs:
                    continue
                action |= act
                cur_sec, new_sec = cast("tuple[int, int]", diffs[field_name])
                cur_nsec = getattr(working_entry, f"{field_name}_nanoseconds")
                new_nsec: int = cast("int", diffs.get(f"{field_name}_nanoseconds", (cur_nsec, cur_nsec))[1])
                msg = self.format_timestamp(cur_sec, cur_nsec, new_sec, new_nsec, label)
                if self._timestomp((cur_sec, cur_nsec), (new_sec, new_nsec)):
                    action |= Actions.TIMESTOMP
                    msg += " (Timestomp)"
                elif commit_ts and self._timestomp((new_sec, new_nsec), commit_ts):
                    action |= Actions.TIMESTOMP
                    msg += f" (Timestomp: commit_time < {field_name})"
                info = self._append_msg(info, msg)

            # mode
            if not reuse_inode and "mode" in diffs:
                cur, new = diffs["mode"]
                action |= Actions.CHANGE_MODE
                info = self._append_msg(info, f"Mode: {cur:04o} -> {new:04o}")

            # uid/gid
            if not reuse_inode and "uid" in diffs:
                cur, new = diffs["uid"]
                action |= Actions.CHANGE_UID
                info = self._append_msg(info, f"UID: {cur} -> {new}")
            if not reuse_inode and "gid" in diffs:
                cur, new = diffs["gid"]
                action |= Actions.CHANGE_GID
                info = self._append_msg(info, f"GID: {cur} -> {new}")

            # size
            if not reuse_inode and "size" in diffs:
                cur, new = cast("tuple[int, int]", diffs["size"])
                action |= Actions.SIZE_UP if cur < new else Actions.SIZE_DOWN
                info = self._append_msg(info, f"Size: {cur} -> {new}")

            # link_count
            if "link_count" in diffs:
                if working_entry.link_count < transaction_entry.link_count:
                    if working_entry.link_count == 0:
                        action |= Actions.CREATE_INODE
                    action |= Actions.CREATE_HARDLINK
                elif working_entry.link_count > transaction_entry.link_count:
                    if transaction_entry.link_count == 0:
                        self._refresh_directory_entries(inode_num, transaction)
                    action |= Actions.DELETE_HARDLINK
                info = self._append_msg(info, f"Link Count: {working_entry.link_count} -> {transaction_entry.link_count}")

            # flags
            if not reuse_inode and "flags" in diffs:
                cur, new = cast("tuple[int, int]", diffs["flags"])
                action |= Actions.CHANGE_FLAGS
                info = self._append_msg(info, f"Flags: 0x{cur:x} -> 0x{new:x}")
                add_info = self._apply_flag_changes(new)
                if add_info := self._apply_flag_changes(new):
                    info = self._append_msg(info, add_info, " ")

            # symlink_target
            if not reuse_inode and "symlink_target" in diffs:
                cur, new = diffs["symlink_target"]
                action |= Actions.CHANGE_SYMLINK_TARGET
                info = self._append_msg(info, f"Symlink Target: {cur} -> {new}")

            # extended_attributes
            if not reuse_inode and "extended_attributes" in diffs:
                cur, new = cast("tuple[list[ExtendedAttribute], list[ExtendedAttribute]]", diffs["extended_attributes"])
                action |= Actions.CHANGE_EA
                added, removed = self._compare_extended_attributes(cur, new)
                if added:
                    info = self._append_msg(info, f"Added EA: {', '.join(map(str, added))}")
                if removed:
                    info = self._append_msg(info, f"Removed EA: {', '.join(map(str, removed))}")

            # names
            if (
                not reuse_inode
                and "names" in diffs
                and working_entry.link_count == transaction_entry.link_count
                and working_entry.names != transaction_entry.names
            ):
                action |= Actions.MOVE
                info = self._append_msg(info, f"Filenames: {working_entry.names} -> {transaction_entry.names}")

        # delete hard link
        if not reuse_inode and working_entry.link_count > transaction_entry.link_count:
            action |= Actions.DELETE_HARDLINK
            info = self._append_msg(info, f"Filenames: {working_entry.names} -> {transaction_entry.names}")

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

        # Update working_entry with transaction_entry
        self._update_working_entry_fields(working_entry, transaction_entry, diffs)
        return timeline_event

    def timeline(self) -> None:
        msg = "Subclasses must implement timeline."
        raise NotImplementedError(msg)
