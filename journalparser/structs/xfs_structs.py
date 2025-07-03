#
# Copyright 2025 Minoru Kobayashi <unknownbit@gmail.com> (@unkn0wnbit)
#
#    This file is part of Forensic Journal Timeline Analyzer (FJTA).
#    Usage or distribution of this code is subject to the terms of the Apache License, Version 2.0.
#

# References:
# https://github.com/torvalds/linux/blob/master/fs/xfs/libxfs/xfs_log_format.h
# https://github.com/torvalds/linux/blob/master/fs/xfs/libxfs/xfs_fs.h
# https://github.com/torvalds/linux/blob/master/fs/xfs/libxfs/xfs_format.h
# https://github.com/torvalds/linux/blob/master/fs/xfs/libxfs/xfs_da_format.h
# https://github.com/torvalds/linux/blob/master/include/uapi/linux/stat.h

from enum import IntEnum, IntFlag, auto

from construct import (
    Array,
    Bytes,
    Const,
    Int8sb,
    Int8sl,
    Int8ub,
    Int8ul,
    Int16ub,
    Int16ul,
    Int32sb,
    Int32sl,
    Int32ub,
    Int32ul,
    Int64sb,
    Int64sl,
    Int64ub,
    Int64ul,
    Padding,
    Struct,
    Switch,
    Union,
)

# XFS Superblock Constants
XFS_SB_MAGIC = b"\x58\x46\x53\x42"  # XFS Superblock magic number

# XFS Superblock structure
xfs_dsb = Struct(
    "sb_magicnum" / Const(XFS_SB_MAGIC),  # 0x00: Identifies the filesystem. Its value is XFS_SB_MAGIC “XFSB” (0x58465342).
    "sb_blocksize" / Int32ub,  # 0x04: The size of a basic unit of space allocation in bytes.
    "sb_dblocks" / Int64ub,  # 0x08: Total number of blocks available for data and metadata on the filesystem.
    "sb_rblocks" / Int64ub,  # 0x10: Number blocks in the real-time disk device.
    "sb_rextents" / Int64ub,  # 0x18: Number of extents on the real-time device.
    "sb_uuid" / Bytes(16),  # 0x20: UUID (Universally Unique ID) for the filesystem.
    "sb_logstart" / Int64ub,  # 0x30: First block number for the journaling log if the log is internal.
    "sb_rootino" / Int64ub,  # 0x38: Root inode number for the filesystem.
    "sb_rbmino" / Int64ub,  # 0x40: Bitmap inode for real-time extents.
    "sb_rsumino" / Int64ub,  # 0x48: Summary inode for real-time bitmap.
    "sb_rextsize" / Int32ub,  # 0x50: Realtime extent size in blocks.
    "sb_agblocks" / Int32ub,  # 0x54: Size of each AG in blocks.
    "sb_agcount" / Int32ub,  # 0x58: Number of AGs in the filesystem.
    "sb_rbmblocks" / Int32ub,  # 0x5C: Number of real-time bitmap blocks.
    "sb_logblocks" / Int32ub,  # 0x60: Number of blocks for the journaling log.
    "sb_versionnum" / Int16ub,  # 0x64: Filesystem version number.
    "sb_sectsize" / Int16ub,  # 0x66: Specifies the underlying disk sector size in bytes.
    "sb_inodesize" / Int16ub,  # 0x68: Size of the inode in bytes.
    "sb_inopblock" / Int16ub,  # 0x6A: Number of inodes per block.
    "sb_fname" / Bytes(12),  # 0x6C: Name for the filesystem.
    "sb_blocklog" / Int8ub,  # 0x78: log2 value of sb_blocksize.
    "sb_sectlog" / Int8ub,  # 0x79: log2 value of sb_sectsize.
    "sb_inodelog" / Int8ub,  # 0x7A: log2 value of sb_inodesize.
    "sb_inopblog" / Int8ub,  # 0x7B: log2 value of sb_inopblock.
    "sb_agblklog" / Int8ub,  # 0x7C: log2 value of sb_agblocks (rounded up).
    "sb_rextslog" / Int8ub,  # 0x7D: log2 value of sb_rextents.
    "sb_inprogress" / Int8ub,  # 0x7E: Flag specifying that the filesystem is being created.
    "sb_imax_pct" / Int8ub,  # 0x7F: Maximum percentage of filesystem space that can be used for inodes.
    "sb_icount" / Int64ub,  # 0x80: Global count for number inodes allocated on the filesystem.
    "sb_ifree" / Int64ub,  # 0x88: Global count of free inodes on the filesystem.
    "sb_fdblocks" / Int64ub,  # 0x90: Global count of free data blocks on the filesystem.
    "sb_frextents" / Int64ub,  # 0x98: Global count of free real-time extents on the filesystem.
    "sb_uquotino" / Int64ub,  # 0xA0: Inode for user quotas.
    "sb_gquotino" / Int64ub,  # 0xA8: Inode for group or project quotas.
    "sb_qflags" / Int16ub,  # 0xB0: Quota flags.
    "sb_flags" / Int8ub,  # 0xB2: Miscellaneous flags.
    "sb_shared_vn" / Int8ub,  # 0xB3: Reserved and must be zero.
    "sb_inoalignmt" / Int32ub,  # 0xB4: Inode chunk alignment in fsblocks.
    "sb_unit" / Int32ub,  # 0xB8: Underlying stripe or raid unit in blocks.
    "sb_width" / Int32ub,  # 0xBC: Underlying stripe or raid width in blocks.
    "sb_dirblklog" / Int8ub,  # 0xC0: log2 multiplier that determines the granularity of directory block allocations in fsblocks.
    "sb_logsectlog" / Int8ub,  # 0xC1: log2 value of the log subvolume's sector size.
    "sb_logsectsize" / Int16ub,  # 0xC2: The log's sector size in bytes if the filesystem uses an external log device.
    "sb_logsunit" / Int32ub,  # 0xC4: The log device's stripe or raid unit size.
    "sb_features2" / Int32ub,  # 0xC8: Additional version flags.
    "sb_bad_features2" / Int32ub,  # 0xCC: Mirrors sb_features2, due to past 64-bit alignment errors.
    "sb_features_compat" / Int32ub,  # 0xD0: Read-write compatible feature flags.
    "sb_features_ro_compat" / Int32ub,  # 0xD4: Read-only compatible feature flags.
    "sb_features_incompat" / Int32ub,  # 0xD8: Read-write incompatible feature flags.
    "sb_features_log_incompat" / Int32ub,  # 0xDC: Read-write incompatible feature flags for the log.
    "sb_crc" / Int32ul,  # 0xE0: Superblock checksum.
    "sb_spino_align" / Int32ub,  # 0xE4: Sparse inode alignment, in fsblocks.
    "sb_pquotino" / Int64ub,  # 0xE8: Project quota inode.
    "sb_lsn" / Int64ub,  # 0xF0: Log sequence number of the last superblock update.
    "sb_meta_uuid" / Bytes(16),  # 0xF8: Metadata UUID.
    "sb_metadirino" / Int64ub,  # 0x108: Points to the inode of the root directory of the metadata directory tree.
    "sb_rgcount" / Int32ub,  # 0x110: Count of realtime groups in the filesystem.
    "sb_rgextents" / Int32ub,  # 0x114: Maximum number of realtime extents that can be contained within a realtime group.
    "sb_rgblklog" / Int8ub,  # 0x118: log2 value of sb_rgextents * sb_rextsize (rounded up).
    "sb_pad" / Bytes(7),  # 0x119: Zeroes, if the XFS_SB_FEAT_RO_INCOMPAT_METADIR feature is enabled.
)


# XFS Log Record Header Constants
XLOG_HEADER_MAGIC = 0xFEEDBABE  # XFS Log Record Header magic number
XLOG_HEADER_CYCLE_SIZE = 32 * 1024
BBSHIFT = 9
BBSIZE = 1 << BBSHIFT

# XFS Log Record Header structure
xlog_rec_header = Struct(
    "h_magicno" / Int32ub,  # 0x00: The magic number of log records, 0xfeedbabe.
    "h_cycle" / Int32ub,  # 0x04: Cycle number of this log record.
    "h_version" / Int32ub,  # 0x08: Log record version, currently 2.
    "h_len" / Int32ub,  # 0x0C: Length of the log record, in bytes. Must be aligned to a 64-bit boundary.
    "h_lsn" / Int64ub,  # 0x10: Log sequence number of this record.
    "h_tail_lsn" / Int64ub,  # 0x18: Log sequence number of the first log record with uncommitted buffers.
    "h_crc" / Int32ul,  # 0x20: Checksum of the log record header, the cycle data, and the log records themselves.
    "h_prev_block" / Int32ub,  # 0x24: Block number of the previous log record.
    "h_num_logops" / Int32ub,  # 0x28: The number of log operations in this record.
    "h_cycle_data" / Array(XLOG_HEADER_CYCLE_SIZE // BBSIZE, Int32ub),  # 0x2C: The first u32 of each log sector must contain the cycle number.
    "h_fmt" / Int32ub,  # 0x12C: Format of the log record.
    "h_fs_uuid" / Bytes(16),  # 0x130: Filesystem UUID.
    "h_size" / Int32ub,  # 0x134: In-core log record size.
)

# Log record formats
XLOG_FMT_UNKNOWN = 0  # Unknown. Perhaps this log is corrupt.
XLOG_FMT_LINUX_LE = 1  # Little-endian Linux.
XLOG_FMT_LINUX_BE = 2  # Big-endian Linux.
XLOG_FMT_IRIX_BE = 3  # Big-endian Irix.


# XFS Log Operation Header structure
xlog_op_header = Struct(
    "oh_tid" / Int32ub,  # 0x00: Transaction ID of this operation.
    "oh_len" / Int32ub,  # 0x04: Number of bytes in the data region.
    "oh_clientid" / Int8ub,  # 0x08: The originator of this operation.
    "oh_flags" / Int8ub,  # 0x09: Specifies flags associated with this operation.
    "oh_res2" / Padding(2),  # 0x0A: Padding.
)

# Log Operation Client ID
XFS_TRANSACTION = 0x69  # Operation came from a transaction.
XFS_VOLUME = 0x2  # Unused?
XFS_LOG = 0xAA  # ???

# Log Operation Flags
XLOG_START_TRANS = 0x01  # Start a new transaction. The next operation header should describe a transaction header.
XLOG_COMMIT_TRANS = 0x02  # Commit this transaction.
XLOG_CONTINUE_TRANS = 0x04  # Continue this transaction into a new log record.
XLOG_WAS_CONT_TRANS = 0x08  # This transaction started in a previous log record.
XLOG_END_TRANS = 0x10  # End of a continued transaction.
XLOG_UNMOUNT_TRANS = 0x20  # Transaction to unmount a filesystem.
XLOG_OPERATION_FLAGS_ALL = XLOG_START_TRANS | XLOG_COMMIT_TRANS | XLOG_CONTINUE_TRANS | XLOG_WAS_CONT_TRANS | XLOG_END_TRANS | XLOG_UNMOUNT_TRANS


# XFS Log Item structure
xfs_log_item_be = Struct(
    "magic" / Int16ub,  # 0x00: Magic number of the log item.
    "size" / Int16ub,  # 0x02: Size of the log item.
)

# XFS Log Item structure (little endian)
xfs_log_item_le = Struct(
    "magic" / Int16ul,  # 0x00: Magic number of the log item.
    "size" / Int16ul,  # 0x02: Size of the log item.
)

# Log Operation Magic Numbers
XFS_TRANS_HEADER_MAGIC = 0x5452414E  # Log Transaction Header ("TRAN")
XFS_LI_EFI = 0x1236  # Extent Freeing Intent
XFS_LI_EFD = 0x1237  # Extent Freeing Done
XFS_LI_IUNLINK = 0x1238  # Unknown?
XFS_LI_INODE = 0x123B  # Inode Updates
XFS_LI_BUF = 0x123C  # Buffer Writes
XFS_LI_DQUOT = 0x123D  # Update Quota
XFS_LI_QUOTAOFF = 0x123E  # Quota Off
XFS_LI_ICREATE = 0x123F  # Inode Creation
XFS_LI_RUI = 0x1240  # Reverse Mapping Update Intent
XFS_LI_RUD = 0x1241  # Reverse Mapping Update Done
XFS_LI_CUI = 0x1242  # Reference Count Update Intent
XFS_LI_CUD = 0x1243  # Reference Count Update Done
XFS_LI_BUI = 0x1244  # File Block Mapping Update Intent
XFS_LI_BUD = 0x1245  # File Block Mapping Update Done
XFS_LI_ATTRI = 0x1246  # Extended Attribute Update Intent
XFS_LI_ATTRD = 0x1247  # Extended Attribute Update Done
XFS_LI_XMI = 0x1248  # File Mapping Exchange Intent
XFS_LI_XMD = 0x1249  # File Mapping Exchange Done


# XFS Transaction Header structure
xfs_trans_header_be = Struct(
    # "th_magic" / Int32ub,  # 0x00: The signature of a transaction header, “TRAN” (0x5452414e).
    "th_magic" / Const(b"TRAN"),  # 0x00: The signature of a transaction header, “TRAN” (0x5452414e).
    "th_type" / Int32ub,  # 0x04: Transaction type.
    "th_tid" / Int32ub,  # 0x08: Transaction ID.
    "th_num_items" / Int32ub,  # 0x0C: The number of operations appearing after this operation, not including the commit operation.
)

# XFS Transaction Header structure (little endian)
xfs_trans_header_le = Struct(
    # "th_magic" / Int32ul,  # 0x00: The signature of a transaction header, “TRAN” (0x5452414e).
    "th_magic" / Const(b"NART"),  # 0x00: The signature of a transaction header, “TRAN” (0x5452414e).
    "th_type" / Int32ul,  # 0x04: Transaction type.
    "th_tid" / Int32ul,  # 0x08: Transaction ID.
    "th_num_items" / Int32ul,  # 0x0C: The number of operations appearing after this operation, not including the commit operation.
)

# Transaction Types
XFS_TRANS_CHECKPOINT = 40


# XFS Timestamp structure
xfs_legacy_timestamp_be = Struct(
    "t_sec" / Int32ub,  # 0x00: Seconds since the epoch.
    "t_nsec" / Int32ub,  # 0x04: Nanoseconds.
)

XFS_DINODE_MAGIC = 0x494E  # 'IN'

# XFS Dinode Core structure (big endian)
xfs_dinode_core_be = Struct(
    # "di_magic" / Const(b"IN"),  # 0x00: The inode signature; these two bytes are “IN” (0x494e).
    "di_magic" / Int16ub,  # 0x00: The inode signature; these two bytes are “IN” (0x494e).
    "di_mode" / Int16ub,  # 0x02: Specifies the mode access bits and type of file.
    "di_version" / Int8ub,  # 0x04: Specifies the inode version.
    "di_format" / Int8ub,  # 0x05: Specifies the format of the data fork.
    "di_onlink" / Int16ub,  # 0x06: Number of links to the inode from directories (v1 inodes).
    "di_uid" / Int32ub,  # 0x08: Specifies the owner's UID of the inode.
    "di_gid" / Int32ub,  # 0x0C: Specifies the owner's GID of the inode.
    "di_nlink" / Int32ub,  # 0x10: Number of links to the inode from directories.
    "di_projid" / Int16ub,  # 0x14: Specifies the owner's project ID in v2 inodes.
    "di_projid_hi" / Int16ub,  # 0x16: Specifies the high 16 bits of the owner's project ID in v2 inodes.
    "di_flushiter" / Int16ub,  # 0x18: Incremented on flush (v2 inodes).
    "di_big_nextents" / Int64ub,  # 0x1A: Number of data fork extents if NREXT64 is set. Padding for V3 inodes without NREXT64 set.
    "di_atime"
    / Union(  # 0x20: Last access time.
        0,
        "legacy" / xfs_legacy_timestamp_be,
        "bigtime" / Int64ub,
    ),
    "di_mtime"
    / Union(  # 0x28: Last modification time.
        0,
        "legacy" / xfs_legacy_timestamp_be,
        "bigtime" / Int64ub,
    ),
    "di_ctime"
    / Union(  # 0x30: Last status change time.
        0,
        "legacy" / xfs_legacy_timestamp_be,
        "bigtime" / Int64ub,
    ),
    "di_size" / Int64sb,  # 0x38: EOF of the inode in bytes.
    "di_nblocks" / Int64ub,  # 0x40: Number of filesystem blocks used to store the inode's data.
    "di_extsize" / Int32ub,  # 0x48: Extent size for filesystems with real-time devices or an extent size hint for standard filesystems.
    "di_nextents" / Int32ub,  # 0x4C: Number of data extents associated with this inode.
    "di_anextents" / Int16ub,  # 0x50: Number of extended attribute extents associated with this inode.
    "di_forkoff" / Int8ub,  # 0x52: Offset into the inode's literal area where the extended attribute fork starts.
    "di_aformat" / Int8sb,  # 0x53: Format of the attribute fork.
    "di_dmevmask" / Int32ub,  # 0x54: DMAPI event mask.
    "di_dmstate" / Int16ub,  # 0x58: DMAPI state.
    "di_flags" / Int16ub,  # 0x5A: Flags associated with the inode.
    "di_gen" / Int32ub,  # 0x5C: Generation number used for inode identification.
    "di_next_unlinked" / Int32ub,  # 0x60: Non-core field in the old dinode.
    "di_crc" / Int32ul,  # 0x64: Checksum of the inode.
    "di_changecount" / Int64ub,  # 0x68: Counts the number of changes made to the attributes in this inode.
    "di_lsn" / Int64ub,  # 0x70: Log sequence number of the last inode write.
    "di_flags2" / Int64ub,  # 0x78: Extended flags associated with a v3 inode.
    "di_cowextsize" / Int32ub,  # 0x80: Extent size hint for copy on write operations.
    "di_pad2" / Bytes(12),  # 0x84: Padding for future expansion of the inode.
    "di_crtime"
    / Union(  # 0x90: Time when this inode was created.
        0,
        "legacy" / xfs_legacy_timestamp_be,
        "bigtime" / Int64ub,
    ),
    "di_ino" / Int64ub,  # 0x98: Full inode number of this inode.
    "di_uuid" / Bytes(16),  # 0xA0: UUID of this inode.
)

# XFS Timestamp structure (little endian)
xfs_legacy_timestamp_le = Struct(
    "t_sec" / Int32ul,  # 0x00: Seconds since the epoch.
    "t_nsec" / Int32ul,  # 0x04: Nanoseconds.
)

# XFS Dinode Core structure (little endian)
xfs_dinode_core_le = Struct(
    # "di_magic" / Const(b"NI"),  # 0x00: The inode signature; these two bytes are “IN” (0x494e).
    "di_magic" / Int16ul,  # 0x00: The inode signature; these two bytes are “IN” (0x494e).
    "di_mode" / Int16ul,  # 0x02: Specifies the mode access bits and type of file.
    "di_version" / Int8ul,  # 0x04: Specifies the inode version.
    "di_format" / Int8ul,  # 0x05: Specifies the format of the data fork.
    "di_onlink" / Int16ul,  # 0x06: Number of links to the inode from directories (v1 inodes).
    "di_uid" / Int32ul,  # 0x08: Specifies the owner's UID of the inode.
    "di_gid" / Int32ul,  # 0x0C: Specifies the owner's GID of the inode.
    "di_nlink" / Int32ul,  # 0x10: Number of links to the inode from directories.
    "di_projid" / Int16ul,  # 0x14: Specifies the owner's project ID in v2 inodes.
    "di_projid_hi" / Int16ul,  # 0x16: Specifies the high 16 bits of the owner's project ID in v2 inodes.
    # "di_flushiter" / Int16ul,  # 0x18: Incremented on flush (v2 inodes).
    "di_big_nextents" / Int64ul,  # 0x18: Number of data fork extents if NREXT64 is set. Padding for V3 inodes without NREXT64 set.
    "di_atime"
    / Union(  # 0x20: Last access time.
        0,
        "legacy" / xfs_legacy_timestamp_le,
        "bigtime" / Int64ul,
    ),
    "di_mtime"
    / Union(  # 0x28: Last modification time.
        0,
        "legacy" / xfs_legacy_timestamp_le,
        "bigtime" / Int64ul,
    ),
    "di_ctime"  # 0x30: Last status change time.
    / Union(
        0,
        "legacy" / xfs_legacy_timestamp_le,
        "bigtime" / Int64ul,
    ),
    "di_size" / Int64sl,  # 0x38: EOF of the inode in bytes.
    "di_nblocks" / Int64ul,  # 0x40: Number of filesystem blocks used to store the inode's data.
    "di_extsize" / Int32ul,  # 0x48: Extent size for filesystems with real-time devices or an extent size hint for standard filesystems.
    "di_nextents" / Int32ul,  # 0x4C: Number of data extents associated with this inode.
    "di_anextents" / Int16ul,  # 0x50: Number of extended attribute extents associated with this inode.
    "di_forkoff" / Int8ul,  # 0x52: Offset into the inode's literal area where the extended attribute fork starts.
    "di_aformat" / Int8sl,  # 0x53: Format of the attribute fork.
    "di_dmevmask" / Int32ul,  # 0x54: DMAPI event mask.
    "di_dmstate" / Int16ul,  # 0x58: DMAPI state.
    "di_flags" / Int16ul,  # 0x5A: Flags associated with the inode.
    "di_gen" / Int32ul,  # 0x5C: Generation number used for inode identification.
    "di_next_unlinked" / Int32ul,  # 0x60: Non-core field in the old dinode.
    "di_crc" / Int32ul,  # 0x64: Checksum of the inode.
    "di_changecount" / Int64ul,  # 0x68: Counts the number of changes made to the attributes in this inode.
    "di_lsn" / Int64ul,  # 0x70: Log sequence number of the last inode write.
    "di_flags2" / Int64ul,  # 0x78: Extended flags associated with a v3 inode.
    "di_cowextsize" / Int32ul,  # 0x80: Extent size hint for copy on write operations.
    "di_pad2" / Bytes(12),  # 0x84: Padding for future expansion of the inode.
    "di_crtime"  # 0x90: Time when this inode was created.
    / Union(
        0,
        "legacy" / xfs_legacy_timestamp_le,
        "bigtime" / Int64ul,
    ),
    "di_ino" / Int64ul,  # 0x98: Full inode number of this inode.
    "di_uuid" / Bytes(16),  # 0xA0: UUID of this inode.
)

# File type constants
S_IFMT = 0o170000  # 00170000
S_IFSOCK = 0o140000  # 0140000
S_IFLNK = 0o120000  # 0120000
S_IFREG = 0o100000  # 0100000
S_IFBLK = 0o060000  # 0060000
S_IFDIR = 0o040000  # 0040000
S_IFCHR = 0o020000  # 0020000
S_IFIFO = 0o010000  # 0010000

# File mode constants
S_ISUID = 0o4000  # 0004000
S_ISGID = 0o2000  # 0002000
S_ISVTX = 0o1000  # 0001000

# XFS Dinode Format Constants
XFS_DINODE_FMT_DEV = 0  # Device
XFS_DINODE_FMT_LOCAL = 1  # Local
XFS_DINODE_FMT_EXTENTS = 2  # Extents
XFS_DINODE_FMT_BTREE = 3  # B+tree
XFS_DINODE_FMT_UUID = 4  # UUID
XFS_DINODE_FMT_RMAP = 5  # Reverse Mapping B+tree

# XFS Metafile Type Constants
XFS_METAFILE_USRQUOTA = 0  # User quota
XFS_METAFILE_GRPQUOTA = 1  # Group quota
XFS_METAFILE_PRJQUOTA = 2  # Project quota
XFS_METAFILE_RTBITMAP = 3  # Realtime bitmap
XFS_METAFILE_RTSUMMARY = 4  # Realtime summary

# XFS di_flags constants
XFS_DIFLAG_REALTIME = 1 << 0  # file's blocks come from rt area
XFS_DIFLAG_PREALLOC = 1 << 1  # file space has been preallocated
XFS_DIFLAG_NEWRTBM = 1 << 2  # for rtbitmap inode, new format
XFS_DIFLAG_IMMUTABLE = 1 << 3  # inode is immutable
XFS_DIFLAG_APPEND = 1 << 4  # inode is append-only
XFS_DIFLAG_SYNC = 1 << 5  # inode is written synchronously
XFS_DIFLAG_NOATIME = 1 << 6  # do not update atime
XFS_DIFLAG_NODUMP = 1 << 7  # do not dump
XFS_DIFLAG_RTINHERIT = 1 << 8  # create with realtime bit set
XFS_DIFLAG_PROJINHERIT = 1 << 9  # create with parents projid
XFS_DIFLAG_NOSYMLINKS = 1 << 10  # disallow symlink creation
XFS_DIFLAG_EXTSIZE = 1 << 11  # inode extent size allocator hint
XFS_DIFLAG_EXTSZINHERIT = 1 << 12  # inherit inode extent size
XFS_DIFLAG_NODEFRAG = 1 << 13  # do not reorganize/defragment
XFS_DIFLAG_FILESTREAM = 1 << 14  # use filestream allocator

class XfsDiflags(IntFlag):
    REALTIME = 1 << 0  # file's blocks come from rt area
    PREALLOC = 1 << 1  # file space has been preallocated
    NEWRTBM = 1 << 2  # for rtbitmap inode, new format
    IMMUTABLE = 1 << 3  # inode is immutable
    APPEND = 1 << 4  # inode is append-only
    SYNC = 1 << 5  # inode is written synchronously
    NOATIME = 1 << 6  # do not update atime
    NODUMP = 1 << 7  # do not dump
    RTINHERIT = 1 << 8  # create with realtime bit set
    PROJINHERIT = 1 << 9  # create with parents projid
    NOSYMLINKS = 1 << 10  # disallow symlink creation
    EXTSIZE = 1 << 11  # inode extent size allocator hint
    EXTSZINHERIT = 1 << 12  # inherit inode extent size
    NODEFRAG = 1 << 13  # do not reorganize/defragment
    FILESTREAM = 1 << 14  # use filestream allocator


XFS_DIFLAG_ANY = (
    XFS_DIFLAG_REALTIME
    | XFS_DIFLAG_PREALLOC
    | XFS_DIFLAG_NEWRTBM
    | XFS_DIFLAG_IMMUTABLE
    | XFS_DIFLAG_APPEND
    | XFS_DIFLAG_SYNC
    | XFS_DIFLAG_NOATIME
    | XFS_DIFLAG_NODUMP
    | XFS_DIFLAG_RTINHERIT
    | XFS_DIFLAG_PROJINHERIT
    | XFS_DIFLAG_NOSYMLINKS
    | XFS_DIFLAG_EXTSIZE
    | XFS_DIFLAG_EXTSZINHERIT
    | XFS_DIFLAG_NODEFRAG
    | XFS_DIFLAG_FILESTREAM
)

# XFS di_flags2 constants
XFS_DIFLAG2_DAX = 1 << 0  # use DAX for this inode
XFS_DIFLAG2_REFLINK = 1 << 1  # file's blocks may be shared
XFS_DIFLAG2_COWEXTSIZE = 1 << 2  # copy on write extent size hint
XFS_DIFLAG2_BIGTIME = 1 << 3  # big timestamps
XFS_DIFLAG2_NREXT64 = 1 << 4  # large extent counters
XFS_DIFLAG2_METADATA = 1 << 5  # metadata inode


# for detecting the size of xfs_dir2_sf_*
xsf_dir2_sf_hdr_x = Struct(
    "count" / Int8ub,  # 0x00: Number of directory entries.
    "i8count" / Int8ub,  # 0x01: Number of directory entries requiring 64-bit entries.
)

# XFS Directory Shortform Header structure
xfs_dir2_sf_hdr_4 = Struct(
    "count" / Int8ub,  # 0x00: Number of directory entries.
    "i8count" / Int8ub,  # 0x01: Number of directory entries requiring 64-bit entries.
    "parent" / Int32ub,  # 0x02: Parent inode number.
)
# XFS Directory Shortform Entry structure
xfs_dir2_sf_entry_4 = Struct(
    "namelen" / Int8ub,  # 0x00: Length of the name, in bytes.
    "offset" / Int16ub,  # 0x01: Offset tag used to assist with directory iteration.
    "name" / Bytes(lambda ctx: ctx.namelen),  # 0x03: The name of the directory entry.
    "ftype" / Int8ub,  # 0x03 + namelen: The type of the inode.
    "inumber" / Int32ub,  # 0x04 + namelen: The inode number.
)

# XFS Directory Shortform Header structure
xfs_dir2_sf_hdr_8 = Struct(
    "count" / Int8ub,  # 0x00: Number of directory entries.
    "i8count" / Int8ub,  # 0x01: Number of directory entries requiring 64-bit entries.
    "parent" / Int64ub,  # 0x02: Parent inode number.
)
# XFS Directory Shortform Entry structure
xfs_dir2_sf_entry_8 = Struct(
    "namelen" / Int8ub,  # 0x00: Length of the name, in bytes.
    "offset" / Int16ub,  # 0x01: Offset tag used to assist with directory iteration.
    "name" / Bytes(lambda ctx: ctx.namelen),  # 0x03: The name of the directory entry.
    "ftype" / Int8ub,  # 0x03 + namelen: The type of the inode.
    "inumber" / Int64ub,  # 0x04 + namelen: The inode number.
)

# XFS Directory Entry File Types
XFS_DIR3_FT_UNKNOWN = 0  # Entry points to an unknown inode type. This should never appear on disk.
XFS_DIR3_FT_REG_FILE = 1  # Entry points to a file.
XFS_DIR3_FT_DIR = 2  # Entry points to another directory.
XFS_DIR3_FT_CHRDEV = 3  # Entry points to a character device.
XFS_DIR3_FT_BLKDEV = 4  # Entry points to a block device.
XFS_DIR3_FT_FIFO = 5  # Entry points to a FIFO.
XFS_DIR3_FT_SOCK = 6  # Entry points to a socket.
XFS_DIR3_FT_SYMLINK = 7  # Entry points to a symbolic link.
XFS_DIR3_FT_WHT = 8  # Entry points to an overlayfs whiteout file. This (as far as the author knows) has never appeared on disk.


# XFS Attribute Shortform Header structure
xfs_attr_sf_hdr = Struct(
    "totsize" / Int16ub,  # 0x00: Total size of the attribute structure in bytes.
    "count" / Int8ul,  # 0x02: The number of entries that can be found in this structure.
    "pad" / Padding(1),  # 0x03: Padding.
)

# XFS Attribute Shortform Entry structure
xfs_attr_sf_entry = Struct(
    "namelen" / Int8ul,  # 0x00: Length of the name, in bytes.
    "valuelen" / Int8ul,  # 0x01: Length of the value, in bytes.
    "flags" / Int8ul,  # 0x02: Flags indicating the attribute's namespace and state.
    "nameval" / Bytes(lambda ctx: ctx.namelen + ctx.valuelen),  # 0x03: The name and value of the attribute.
)

# XFS Attribute Shortform structure
xfs_attr_shortform = Struct(
    "hdr" / xfs_attr_sf_hdr,  # 0x00: Header of the attribute shortform.
    "list" / xfs_attr_sf_entry[lambda ctx: ctx.hdr.count],  # 0x03: List of attribute entries.
)

# Attribute Flags
XFS_ATTR_LOCAL = 1 << 0  # The attribute value is contained within this block.
XFS_ATTR_ROOT = 1 << 1  # The attribute's namespace is “trusted”.
XFS_ATTR_SECURE = 1 << 2  # The attribute's namespace is “secure”.
XFS_ATTR_PARENT = 1 << 3  # This attribute is a parent pointer.
XFS_ATTR_INCOMPLETE = 1 << 7  # This attribute is being modified.
XFS_ATTR_ALL = XFS_ATTR_LOCAL | XFS_ATTR_ROOT | XFS_ATTR_SECURE | XFS_ATTR_PARENT | XFS_ATTR_INCOMPLETE

# XFS Inode Log Format 64 structure (big endian)
xfs_inode_log_format_64_be = Struct(
    "ilf_type" / Int16ub,  # 0x00: The signature of an inode update operation, 0x123b.
    "ilf_size" / Int16ub,  # 0x02: Number of operations involved in this update, including this format operation.
    "ilf_fields" / Int32ub,  # 0x04: Specifies which parts of the inode are being updated.
    "ilf_asize" / Int16ub,  # 0x08: Size of the attribute fork, in bytes.
    "ilf_dsize" / Int16ub,  # 0x0A: Size of the data fork, in bytes.
    "ilf_pad" / Int32ub,  # 0x0C: Padding.
    "ilf_ino" / Int64ub,  # 0x10: Absolute node number.
    "ilf_u"
    / Union(  # 0x18: Union for device number or UUID.
        0,
        "ilfu_rdev" / Int32ub,
        "ilfu_uuid" / Bytes(16),
    ),
    "ilf_blkno" / Int64sb,  # 0x28: Block number of the inode buffer, in sectors.
    "ilf_len" / Int32sb,  # 0x30: Length of inode buffer, in sectors.
    "ilf_boffset" / Int32sb,  # 0x34: Byte offset of the inode in the buffer.
)

# XFS Inode Log Format 64 structure (little endian)
xfs_inode_log_format_64_le = Struct(
    "ilf_type" / Int16ul,  # 0x00: The signature of an inode update operation, 0x123b.
    "ilf_size" / Int16ul,  # 0x02: Number of operations involved in this update, including this format operation.
    "ilf_fields" / Int32ul,  # 0x04: Specifies which parts of the inode are being updated.
    "ilf_asize" / Int16ul,  # 0x08: Size of the attribute fork, in bytes.
    "ilf_dsize" / Int16ul,  # 0x0A: Size of the data fork, in bytes.
    "ilf_pad" / Int32ul,  # 0x0C: Padding.
    "ilf_ino" / Int64ul,  # 0x10: Absolute node number.
    "ilf_u"
    / Union(  # 0x18: Union for device number or UUID.
        0,
        "ilfu_rdev" / Int32ul,
        "ilfu_uuid" / Bytes(16),
    ),
    "ilf_blkno" / Int64sl,  # 0x28: Block number of the inode buffer, in sectors.
    "ilf_len" / Int32sl,  # 0x30: Length of inode buffer, in sectors.
    "ilf_boffset" / Int32sl,  # 0x34: Byte offset of the inode in the buffer.
)

# XFS Inode Log Format Type
XFS_ILOG_CORE = 0x0001
XFS_ILOG_DDATA = 0x0002
XFS_ILOG_DEXT = 0x0004
XFS_ILOG_DBROOT = 0x0008
XFS_ILOG_DEV = 0x0010
XFS_ILOG_UUID = 0x0020
XFS_ILOG_ADATA = 0x0040
XFS_ILOG_AEXT = 0x0080
XFS_ILOG_ABROOT = 0x0100
XFS_ILOG_DOWNER = 0x0200
XFS_ILOG_AOWNER = 0x0400
XFS_ILOG_TIMESTAMP = 0x4000
XFS_ILOG_IVERSION = 0x8000
XFS_ILOG_NONCORE = (
    XFS_ILOG_DDATA
    | XFS_ILOG_DEXT
    | XFS_ILOG_DBROOT
    | XFS_ILOG_DEV
    | XFS_ILOG_UUID
    | XFS_ILOG_ADATA
    | XFS_ILOG_AEXT
    | XFS_ILOG_ABROOT
    | XFS_ILOG_DOWNER
    | XFS_ILOG_AOWNER
)
XFS_ILOG_DFORK = XFS_ILOG_DDATA | XFS_ILOG_DEXT | XFS_ILOG_DBROOT
XFS_ILOG_AFORK = XFS_ILOG_ADATA | XFS_ILOG_AEXT | XFS_ILOG_ABROOT
XFS_ILOG_ALL = (
    XFS_ILOG_CORE
    | XFS_ILOG_DDATA
    | XFS_ILOG_DEXT
    | XFS_ILOG_DBROOT
    | XFS_ILOG_DEV
    | XFS_ILOG_UUID
    | XFS_ILOG_ADATA
    | XFS_ILOG_AEXT
    | XFS_ILOG_ABROOT
    | XFS_ILOG_TIMESTAMP
    | XFS_ILOG_DOWNER
    | XFS_ILOG_AOWNER
)


# XFS Buffer Log Format structure (big endian)
xfs_buf_log_format_be = Struct(
    "blf_type" / Int16ub,  # 0x00: Magic number to specify a buffer log item, 0x123c.
    "blf_size" / Int16ub,  # 0x02: Number of buffer data items following this item.
    "blf_flags" / Int16ub,  # 0x04: Flags associated with the buffer item.
    "blf_len" / Int16ub,  # 0x06: Number of sectors affected by this buffer.
    "blf_blkno" / Int64sb,  # 0x08: Block number to write, in sectors.
    "blf_map_size" / Int32ub,  # 0x10: The size of blf_data_map, in 32-bit words.
    # "blf_data_map" / Array(lambda ctx: ctx.blf_map_size, Int32ub),  # 0x14: Dirty bitmap for the logged buffer.
)

# XFS Buffer Log Format structure (little endian)
xfs_buf_log_format_le = Struct(
    "blf_type" / Int16ul,  # 0x00: Magic number to specify a buffer log item, 0x123c.
    "blf_size" / Int16ul,  # 0x02: Number of buffer data items following this item.
    "blf_flags" / Int16ul,  # 0x04: Flags associated with the buffer item.
    "blf_len" / Int16ul,  # 0x06: Number of sectors affected by this buffer.
    "blf_blkno" / Int64sl,  # 0x08: Block number to write, in sectors.
    "blf_map_size" / Int32ul,  # 0x10: The size of blf_data_map, in 32-bit words.
    # "blf_data_map" / Array(lambda ctx: ctx.blf_map_size, Int32ul),  # 0x14: Dirty bitmap for the logged buffer.
)

# Buffer Log Format Flags
# XFS_BLF_INODE_BUF = 1 << 0  # Inode buffer. These must be recovered before replaying items that change this buffer.
# XFS_BLF_CANCEL = 1 << 1  # Don't recover this buffer, blocks are being freed.
# XFS_BLF_UDQUOT_BUF = 1 << 2  # User quota buffer, don't recover if there's a subsequent quotaoff.
# XFS_BLF_PDQUOT_BUF = 1 << 3  # Project quota buffer, don't recover if there's a subsequent quotaoff.
# XFS_BLF_GDQUOT_BUF = 1 << 4  # Group quota buffer, don't recover if there's a subsequent quotaoff.

XFS_BLFT_BITS = 5
XFS_BLFT_SHIFT = 11
# XFS_BLFT_MASK = ((1 << XFS_BLFT_BITS) - 1) << XFS_BLFT_SHIFT


# Buffer Log Format Flags
class XfsBlft(IntEnum):
    XFS_BLFT_UNKNOWN_BUF = 0
    XFS_BLFT_UDQUOT_BUF = auto()
    XFS_BLFT_PDQUOT_BUF = auto()
    XFS_BLFT_GDQUOT_BUF = auto()
    XFS_BLFT_BTREE_BUF = auto()
    XFS_BLFT_AGF_BUF = auto()
    XFS_BLFT_AGFL_BUF = auto()
    XFS_BLFT_AGI_BUF = auto()
    XFS_BLFT_DINO_BUF = auto()
    XFS_BLFT_SYMLINK_BUF = auto()
    XFS_BLFT_DIR_BLOCK_BUF = auto()
    XFS_BLFT_DIR_DATA_BUF = auto()
    XFS_BLFT_DIR_FREE_BUF = auto()
    XFS_BLFT_DIR_LEAF1_BUF = auto()
    XFS_BLFT_DIR_LEAFN_BUF = auto()
    XFS_BLFT_DA_NODE_BUF = auto()
    XFS_BLFT_ATTR_LEAF_BUF = auto()
    XFS_BLFT_ATTR_RMT_BUF = auto()
    XFS_BLFT_SB_BUF = auto()
    XFS_BLFT_RTBITMAP_BUF = auto()
    XFS_BLFT_RTSUMMARY_BUF = auto()
    XFS_BLFT_MAX_BUF = 1 << XFS_BLFT_BITS


# XFS Directory Block Header structure
xfs_dir3_blk_hdr = Struct(
    "magic" / Int32ub,  # 0x00: Magic number for this directory block.
    "crc" / Int32ub,  # 0x04: Checksum of the directory block.
    "blkno" / Int64ub,  # 0x08: Block number of this directory block.
    "lsn" / Int64ub,  # 0x10: Log sequence number of the last write to this block.
    "uuid" / Bytes(16),  # 0x18: The UUID of this block.
    "owner" / Int64ub,  # 0x28: The inode number that this directory block belongs to.
)

# XFS Directory Data Header structure
xfs_dir3_data_hdr = Struct(
    "hdr" / xfs_dir3_blk_hdr,  # 0x00: The v5 directory/attribute block header.
    "best_free" / Array(3, Int32ub),  # 0x30: An array pointing to free regions in the directory block.
    "pad" / Int32ub,  # 0x3C: Padding to maintain a 64-bit alignment.
)

# XFS Directory Data Entry structure
xfs_dir2_data_entry = Struct(
    "inumber" / Int64ub,  # 0x00: The inode number that this entry points to.
    "namelen" / Int8ub,  # 0x08: Length of the name, in bytes.
    "name" / Bytes(lambda ctx: ctx.namelen),  # 0x09: The name associated with this entry.
    "ftype" / Int8ub,  # 0x09 + namelen: The type of the inode.
    "pad" / Padding(lambda ctx: (8 - (0x8 + 0x1 + ctx.namelen + 0x1 + 0x2) % 8) % 8),  # Padding to align to 8 bytes. Not stated in the specification.
    "tag" / Int16ub,  # 0x0A + namelen + pad: Starting offset of the entry, in bytes.
)

# XFS Directory Data Unused structure
xfs_dir2_data_unused = Struct(
    "freetag" / Int16ub,  # 0x00: Magic number signifying that this is an unused entry. Must be 0xFFFF.
    "length" / Int16ub,  # 0x02: Length of this unused entry, in bytes.
    "tag" / Int16ub,  # 0x04: Starting offset of the entry, in bytes.
)

# # XFS Directory Data Union structure
# xfs_dir2_data_union = Union(
#     0,
#     "entry" / xfs_dir2_data_entry,  # 0x00: A directory entry.
#     "unused" / xfs_dir2_data_unused,  # 0x00: An unused entry.
# )

# XFS Directory Data Union structure using Switch
xfs_dir2_data_union = Struct(
    "type" / Int16ub,  # 0x00: Type indicator (0xFFFF for unused, otherwise directory entry)
    "data"
    / Switch(
        lambda ctx: ctx.type,
        {
            0xFFFF: xfs_dir2_data_unused,  # Unused entry
        },
        default=xfs_dir2_data_entry,  # Directory entry
    ),
)
