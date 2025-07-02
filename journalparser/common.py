#
# Copyright 2025 Minoru Kobayashi <unknownbit@gmail.com> (@unkn0wnbit)
#
#    This file is part of Forensic Journal Timeline Analyzer (FJTA).
#    Usage or distribution of this code is subject to the terms of the Apache License, Version 2.0.
#

import copy
from argparse import Namespace
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Flag, IntEnum, auto

import pytsk3
from construct import Container, StreamError


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
class DentInfo:
    dir_inode: int = 0  # Inode number of the directory containing this entry
    parent_inode: int = 0  # Actually not needed?
    entries: dict[int, list[str]] = field(default_factory=dict)  # dict[inode_num, list[name]]

    def __hash__(self) -> int:
        # Convert entries to a tuple to ensure immutability for hashing
        entries_tuple = tuple((inode, tuple(names)) for inode, names in self.entries.items())
        return hash((self.dir_inode, entries_tuple))

    def __str__(self) -> str:
        return f"dir_inode: {self.dir_inode}, parent_inode: {self.parent_inode}, entries: {[{inode: names} for inode, names in self.entries.items()]}"

    def to_dict(self) -> dict:
        return {
            "dir_inode": self.dir_inode,
            "parent_inode": self.parent_inode,
            "entries": self.entries,
        }


@dataclass
class EntryInfo:
    inode: int = 0
    file_type: FileTypes = FileTypes.UNKNOWN
    associated_dirs: list[int] = field(default_factory=list)  # list of dir_inode numbers where this inode is referenced
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


@dataclass
class JournalTransaction[T: EntryInfo]:
    tid: int  # transaction id
    entries: dict[int, T] = field(default_factory=dict)  # dict[inode_num, EntryInfo]
    dents: dict[int, DentInfo] = field(default_factory=dict)  # dict[dir_inode, DentInfo]

    def set_inode_info(self, inode_num: int, inode: Container, eattrs: list[ExtendedAttribute]) -> None:
        msg = "Subclasses must implement set_inode_info."
        raise NotImplementedError(msg)

    def set_dir_entry_info(self, inode_num: int, dir_entry: Container) -> None:
        msg = "Subclasses must implement set_dir_entry_info."
        raise NotImplementedError(msg)

    def set_dent_info(self, dir_inode_num: int, parent_inode_num: int, inode_num: int, dir_entry: Container) -> None:
        msg = "Subclasses must implement set_dent_info."
        raise NotImplementedError(msg)


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

    # def __str__(self) -> str:
    #     name_str = ", ".join(self.name)
    #     extended_attributes_str = ", ".join([f"{ea.name}: {ea.value}" for ea in self.extended_attributes])
    #     return f"{self.transaction_id}|{self.inode}|{self.file_type}|{name_str}|{self.action}|{self.dir_inode}|{self.parent_inode}|{self.mode:04o}|{self.uid}|{self.gid}|{extended_attributes_str}|{self.info}"

    def to_dict(self) -> dict:
        result = {}
        for tl_field in self.__dataclass_fields__:
            value = getattr(self, tl_field)
            if isinstance(value, Flag | FileTypes | Actions):
                result[tl_field] = value.name
            elif isinstance(value, list) and all(isinstance(item, ExtendedAttribute) for item in value):
                result[tl_field] = [item.to_dict() for item in value]
            elif isinstance(value, dict) and all(isinstance(entry, DentInfo) for entry in value.values()):
                result[tl_field] = {dir_inode: entry.to_dict() for dir_inode, entry in value.items()}
            elif isinstance(value, DeviceNumber):
                result[tl_field] = value.to_dict()
            else:
                result[tl_field] = value
        return result


class JournalParserCommon[T: JournalTransaction, U: EntryInfo]:
    def __init__(self, img_info: pytsk3.Img_Info, fs_info: pytsk3.FS_Info, args: Namespace) -> None:
        self.img_info = img_info
        self.fs_info = fs_info
        self.offset = args.offset
        self.debug = args.debug
        self.special_inodes = args.special_inodes
        self.block_size = self.fs_info.info.block_size
        self.endian = self.fs_info.info.endian  # 1 = pytsk3.TSK_LIT_ENDIAN, 2 = pytsk3.TSK_BIG_ENDIAN
        self.journal_file = None
        if self.fs_info.info.journ_inum != 0:
            self.journal_file = self.fs_info.open_meta(self.fs_info.info.journ_inum)
        self.transactions: dict[int, T] = {}  # dict[transaction_id, JournalTransaction]

    def dbg_print(self, msg: str | Container | StreamError) -> None:
        if self.debug:
            print(msg)

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
    def _build_names_from_entries(
        working_entry: U,
        transaction_entry: U,
        transaction_dents: dict[int, DentInfo],
    ) -> tuple[dict[int, list[str]], dict[int, list[str]]]:
        # Build a directory entry (file name) list of inode (past transactions)
        prev_names: dict[int, list[str]] = {}
        prev_names = copy.deepcopy(working_entry.names)

        # Build a directory entry (file name) list of inode (current transaction)
        current_names: dict[int, list[str]] = {}
        current_names = copy.deepcopy(working_entry.names)
        if not (transaction_entry.entryinfo_source & EntryInfoSource.DIR_ENTRY):
            if working_entry.link_count == transaction_entry.link_count:
                transaction_entry.associated_dirs = copy.deepcopy(working_entry.associated_dirs)
                transaction_entry.names = copy.deepcopy(working_entry.names)
        else:
            for associated_dir in transaction_entry.associated_dirs:
                if not transaction_dents.get(associated_dir) or not transaction_dents[associated_dir].entries.get(transaction_entry.inode):
                    # transaction_dents[associated_dir].entries[transaction_entry.inode] = []
                    continue
                current_names.update({associated_dir: transaction_dents[associated_dir].entries[transaction_entry.inode]})

        # added_assciated_dirs = set(transaction_entry.associated_dirs) - set(working_entry.associated_dirs)
        deleted_associated_dirs = set(working_entry.associated_dirs) - set(transaction_entry.associated_dirs)
        for associated_dir in deleted_associated_dirs:
            current_names.pop(associated_dir, None)
        transaction_entry.names = copy.deepcopy(current_names)

        return prev_names, current_names

    @staticmethod
    def _compare_entry_fields(current_entry: U, new_entry: U) -> list[tuple[str, any, any]]:
        differences: list[tuple] = []
        for entry_field in current_entry.__dataclass_fields__:
            if entry_field in ("entryinfo_source",):
                continue
            current_value = getattr(current_entry, entry_field)
            new_value = getattr(new_entry, entry_field)
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
    def _contains_control_chars(s: str, include_null: bool = False) -> bool:
        if include_null:
            return any(0x00 <= ord(c) <= 0x1F for c in s)
        # except for null (0x00)
        return any(0x01 <= ord(c) <= 0x1F for c in s)

    @classmethod
    def _contains_control_chars_bytes(cls, data: bytes, include_null: bool = False) -> bool:
        try:
            s = data.decode("utf-8")
        except UnicodeDecodeError:
            return True
        return cls._contains_control_chars(s, include_null)

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

    def timeline(self) -> None:
        msg = "Subclasses must implement timeline."
        raise NotImplementedError(msg)
