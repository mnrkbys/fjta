#
# Copyright 2025 Minoru Kobayashi <unknownbit@gmail.com> (@unkn0wnbit)
#
#    This file is part of Forensic Journal Timeline Analyzer (FJTA).
#    Usage or distribution of this code is subject to the terms of the Apache License, Version 2.0.
#

from dataclasses import dataclass, field
from enum import Flag, IntEnum, auto

import pytsk3
from construct import Container


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
    CREATE = auto()
    DELETE = auto()
    RENAME = auto()
    MOVE = auto()
    ACCESS = auto()
    CHANGE = auto()
    MODIFY = auto()
    SETUID = auto()
    SETGID = auto()
    CHANGE_UID = auto()
    CHANGE_GID = auto()
    CHANGE_MODE = auto()
    SIZE_UP = auto()
    SIZE_DOWN = auto()
    TIMESTOMP = auto()
    CHANGE_FLAGS = auto()
    CHANGE_SYMLINK_TARGET = auto()
    CHANGE_EA = auto()

class EntryInfoSource(Flag):
    UNKNOWN = 0
    INODE = auto()
    DIR_ENTRY = auto()
    WORKING_ENTRY = auto()


@dataclass
class NameInfo:
    name: str = ""
    dir_inode: int = 0
    parent_inode: int = 0


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
class EntryInfo:
    inode: int = 0
    file_type: FileTypes = FileTypes.UNKNOWN
    name: list[str] = field(default_factory=list)  # multiple names might be assigned to the same inode (hard link)
    dir_inode: int = 0
    parent_inode: int = 0
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
    # dtime: int = 0  # EXT4 only?
    # dtime_nanoseconds: int = 0  # Not needed?
    flags: int = 0
    # link_count: int = 0  # TODO: Need this to distinguish between moving files and creating links?
    symlink_target: str = ""
    extended_attributes: list[ExtendedAttribute] = field(default_factory=list)
    device_number: DeviceNumber = field(default_factory=DeviceNumber)
    entryinfo_source: EntryInfoSource = EntryInfoSource.UNKNOWN


@dataclass
class JournalTransaction[T: EntryInfo]:
    tid: int  # transaction id
    entries: dict[int, T] = field(default_factory=dict)  # dict[inode_num, EntryInfo]

    def set_inode_info(self, inode_num: int, inode: Container, eattrs: list[ExtendedAttribute]) -> None:
        msg = "Subclasses must implement set_inode_info."
        raise NotImplementedError(msg)

    def set_dir_entry_info(self, inode_num: int, dir_entry: Container) -> None:
        msg = "Subclasses must implement set_dir_entry_info."
        raise NotImplementedError(msg)


@dataclass
class TimelineEventInfo:
    transaction_id: int = 0
    inode: int = 0
    file_type: FileTypes = FileTypes.UNKNOWN
    name: list[str] = field(default_factory=list)
    action: Actions = Actions.UNKNOWN
    dir_inode: int = 0
    parent_inode: int = 0
    mode: int = 0
    uid: int = 0
    gid: int = 0
    size: int = 0
    atime: float = 0
    ctime: float = 0
    mtime: float = 0
    crtime: float = 0
    dtime: float = 0  # EXT4 only?
    flags: int = 0
    symlink_target: str = ""
    extended_attributes: list[ExtendedAttribute] = field(default_factory=list)
    device_number: DeviceNumber = field(default_factory=DeviceNumber)
    info: str = ""

    def __str__(self) -> str:
        name_str = ", ".join(self.name)
        extended_attributes_str = ", ".join([f"{ea.name}: {ea.value}" for ea in self.extended_attributes])
        return f"{self.transaction_id}|{self.inode}|{self.file_type}|{name_str}|{self.action}|{self.dir_inode}|{self.parent_inode}|{self.mode:04o}|{self.uid}|{self.gid}|{extended_attributes_str}|{self.info}"

    def to_dict(self) -> dict:
        result = {}
        for tl_field in self.__dataclass_fields__:
            value = getattr(self, tl_field)
            if isinstance(value, FileTypes | Actions):
                result[tl_field] = value.name
            elif isinstance(value, list) and all(isinstance(item, ExtendedAttribute) for item in value):
                result[tl_field] = [item.to_dict() for item in value]
            elif isinstance(value, DeviceNumber):
                result[tl_field] = value.to_dict()
            else:
                result[tl_field] = value
        return result


class JournalParserCommon[T: JournalTransaction, U: EntryInfo]:
    def __init__(self, img_info: pytsk3.Img_Info, fs_info: pytsk3.FS_Info) -> None:
        self.img_info = img_info
        self.fs_info = fs_info
        self.block_size = self.fs_info.info.block_size
        self.endian = self.fs_info.info.endian  # 1 = pytsk3.TSK_LIT_ENDIAN, 2 = pytsk3.TSK_BIG_ENDIAN
        self.journal_file = None
        if self.fs_info.info.journ_inum != 0:
            self.journal_file = self.fs_info.open_meta(self.fs_info.info.journ_inum)
        self.transactions: dict[int, T] = {}  # dict[transaction_id, JournalTransaction]

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
    def _compare_entry_fields(current_entry: U, new_entry: U) -> list[tuple[str, any, any]]:
        differences: list[tuple] = []
        for entry_field in current_entry.__dataclass_fields__:
            current_value = getattr(current_entry, entry_field)
            new_value = getattr(new_entry, entry_field)
            if entry_field == "name" and (current_value == [] or new_value == []):
                continue
            if entry_field in ("file_type", "dir_inode", "parent_inode") and (current_value == 0 or new_value == 0):
                continue
            if current_value != new_value:
                differences.append((entry_field, current_value, new_value))
        return differences

    @staticmethod
    def _filter_differences(differences: list[tuple[str, any, any]], field: str) -> tuple[str, any, any] | tuple:
        filterd_diffs = list(filter(lambda x: x[0] == field, differences))
        if filterd_diffs:
            return filterd_diffs[0]
        return ()

    @staticmethod
    def _append_msg(orig_msg: str, msg: str) -> str:
        if orig_msg:
            return f"{orig_msg}|{msg}"
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

    def timeline(self) -> None:
        msg = "Subclasses must implement timeline."
        raise NotImplementedError(msg)
