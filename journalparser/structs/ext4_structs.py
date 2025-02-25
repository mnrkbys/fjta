#
# Copyright 2024 Minoru Kobayashi <unknownbit@gmail.com> (@unkn0wnbit)
#
#    This file is part of Forensic Journal Timeline Analyzer (FJTA).
#    Usage or distribution of this code is subject to the terms of the Apache License, Version 2.0.
#

# References:
# https://www.kernel.org/doc/html/latest/filesystems/ext4/journal.html
# https://www.kernel.org/doc/html/latest/filesystems/ext4/dynamic.html
# https://www.kernel.org/doc/html/latest/filesystems/ext4/overview.html#special-inodes
# https://github.com/torvalds/linux/blob/master/include/linux/jbd2.h
# https://github.com/torvalds/linux/blob/master/fs/ext4/namei.c
# https://github.com/torvalds/linux/blob/master/fs/ext4/ext4.h


from construct import (
    Array,
    Bytes,
    Const,
    Int8ub,
    Int8ul,
    Int16ub,
    Int16ul,
    Int32ub,
    Int32ul,
    Int64ub,
    Int64ul,
    Padding,
    Struct,
)

# EXT4 superblock structure
ext4_superblock_s = Struct(
    "s_inodes_count" / Int32ul,  # 0x0: Total inode count
    "s_blocks_count_lo" / Int32ul,  # 0x4: Total block count
    "s_r_blocks_count_lo" / Int32ul,  # 0x8: Blocks reserved for super-user
    "s_free_blocks_count_lo" / Int32ul,  # 0xC: Free block count
    "s_free_inodes_count" / Int32ul,  # 0x10: Free inode count
    "s_first_data_block" / Int32ul,  # 0x14: First data block
    "s_log_block_size" / Int32ul,  # 0x18: Block size
    "s_log_cluster_size" / Int32ul,  # 0x1C: Cluster size
    "s_blocks_per_group" / Int32ul,  # 0x20: Blocks per group
    "s_clusters_per_group" / Int32ul,  # 0x24: Clusters per group
    "s_inodes_per_group" / Int32ul,  # 0x28: Inodes per group
    "s_mtime" / Int32ul,  # 0x2C: Mount time
    "s_wtime" / Int32ul,  # 0x30: Write time
    "s_mnt_count" / Int16ul,  # 0x34: Number of mounts since last fsck
    "s_max_mnt_count" / Int16ul,  # 0x36: Max number of mounts before fsck
    "s_magic" / Int16ul,  # 0x38: Magic signature
    "s_state" / Int16ul,  # 0x3A: File system state
    "s_errors" / Int16ul,  # 0x3C: Behaviour when detecting errors
    "s_minor_rev_level" / Int16ul,  # 0x3E: Minor revision level
    "s_lastcheck" / Int32ul,  # 0x40: Time of last check
    "s_checkinterval" / Int32ul,  # 0x44: Maximum time between checks
    "s_creator_os" / Int32ul,  # 0x48: Creator OS
    "s_rev_level" / Int32ul,  # 0x4C: Revision level
    "s_def_resuid" / Int16ul,  # 0x50: Default uid for reserved blocks
    "s_def_resgid" / Int16ul,  # 0x52: Default gid for reserved blocks
    "s_first_ino" / Int32ul,  # 0x54: First non-reserved inode
    "s_inode_size" / Int16ul,  # 0x58: Size of inode structure
    "s_block_group_nr" / Int16ul,  # 0x5A: Block group # of this superblock
    "s_feature_compat" / Int32ul,  # 0x5C: Compatible feature set
    "s_feature_incompat" / Int32ul,  # 0x60: Incompatible feature set
    "s_feature_ro_compat" / Int32ul,  # 0x64: Readonly-compatible feature set
    "s_uuid" / Bytes(16),  # 0x68: 128-bit UUID for volume
    "s_volume_name" / Bytes(16),  # 0x78: Volume label
    "s_last_mounted" / Bytes(64),  # 0x88: Directory where filesystem was last mounted
    "s_algorithm_usage_bitmap" / Int32ul,  # 0xC8: For compression
    "s_prealloc_blocks" / Int8ul,  # 0xCC: Number of blocks to preallocate for files
    "s_prealloc_dir_blocks" / Int8ul,  # 0xCD: Number of blocks to preallocate for directories
    "s_reserved_gdt_blocks" / Int16ul,  # 0xCE: Number of reserved GDT entries for future filesystem expansion
    "s_journal_uuid" / Bytes(16),  # 0xD0: UUID of journal superblock
    "s_journal_inum" / Int32ul,  # 0xE0: Inode number of journal file
    "s_journal_dev" / Int32ul,  # 0xE4: Device number of journal file
    "s_last_orphan" / Int32ul,  # 0xE8: Start of list of orphaned inodes to delete
    "s_hash_seed" / Array(4, Int32ul),  # 0xEC: HTREE hash seed
    "s_def_hash_version" / Int8ul,  # 0xFC: Default hash algorithm to use for directory hashes
    "s_jnl_backup_type" / Int8ul,  # 0xFD: Journal backup type
    "s_desc_size" / Int16ul,  # 0xFE: Size of group descriptors
    "s_default_mount_opts" / Int32ul,  # 0x100: Default mount options
    "s_first_meta_bg" / Int32ul,  # 0x104: First metablock block group
    "s_mkfs_time" / Int32ul,  # 0x108: When the filesystem was created
    "s_jnl_blocks" / Array(17, Int32ul),  # 0x10C: Backup copy of the journal inode's i_block[] array
    "s_blocks_count_hi" / Int32ul,  # 0x150: High 32-bits of the block count
    "s_r_blocks_count_hi" / Int32ul,  # 0x154: High 32-bits of the reserved block count
    "s_free_blocks_count_hi" / Int32ul,  # 0x158: High 32-bits of the free block count
    "s_min_extra_isize" / Int16ul,  # 0x15C: All inodes have at least # bytes
    "s_want_extra_isize" / Int16ul,  # 0x15E: New inodes should reserve # bytes
    "s_flags" / Int32ul,  # 0x160: Miscellaneous flags
    "s_raid_stride" / Int16ul,  # 0x164: RAID stride
    "s_mmp_interval" / Int16ul,  # 0x166: Seconds to wait in multi-mount prevention checking
    "s_mmp_block" / Int64ul,  # 0x168: Block # for multi-mount protection data
    "s_raid_stripe_width" / Int32ul,  # 0x170: RAID stripe width
    "s_log_groups_per_flex" / Int8ul,  # 0x174: Size of a flexible block group
    "s_checksum_type" / Int8ul,  # 0x175: Metadata checksum algorithm type
    "s_reserved_pad" / Int16ul,  # 0x176: Reserved padding
    "s_kbytes_written" / Int64ul,  # 0x178: Number of KiB written to this filesystem over its lifetime
    "s_snapshot_inum" / Int32ul,  # 0x180: Inode number of active snapshot
    "s_snapshot_id" / Int32ul,  # 0x184: Sequential ID of active snapshot
    "s_snapshot_r_blocks_count" / Int64ul,  # 0x188: Number of blocks reserved for active snapshot's future use
    "s_snapshot_list" / Int32ul,  # 0x190: Inode number of the head of the on-disk snapshot list
    "s_error_count" / Int32ul,  # 0x194: Number of errors seen
    "s_first_error_time" / Int32ul,  # 0x198: First time an error happened
    "s_first_error_ino" / Int32ul,  # 0x19C: Inode involved in first error
    "s_first_error_block" / Int64ul,  # 0x1A0: Number of block involved in first error
    "s_first_error_func" / Bytes(32),  # 0x1A8: Name of function where the error happened
    "s_first_error_line" / Int32ul,  # 0x1C8: Line number where error happened
    "s_last_error_time" / Int32ul,  # 0x1CC: Time of most recent error
    "s_last_error_ino" / Int32ul,  # 0x1D0: Inode involved in most recent error
    "s_last_error_line" / Int32ul,  # 0x1D4: Line number where most recent error happened
    "s_last_error_block" / Int64ul,  # 0x1D8: Number of block involved in most recent error
    "s_last_error_func" / Bytes(32),  # 0x1E0: Name of function where the most recent error happened
    "s_mount_opts" / Bytes(64),  # 0x200: ASCIIZ string of mount options
    "s_usr_quota_inum" / Int32ul,  # 0x240: Inode number of user quota file
    "s_grp_quota_inum" / Int32ul,  # 0x244: Inode number of group quota file
    "s_overhead_blocks" / Int32ul,  # 0x248: Overhead blocks/clusters in fs
    "s_backup_bgs" / Array(2, Int32ul),  # 0x24C: Block groups containing superblock backups
    "s_encrypt_algos" / Bytes(4),  # 0x254: Encryption algorithms in use
    "s_encrypt_pw_salt" / Bytes(16),  # 0x258: Salt for the string2key algorithm for encryption
    "s_lpf_ino" / Int32ul,  # 0x268: Inode number of lost+found
    "s_prj_quota_inum" / Int32ul,  # 0x26C: Inode that tracks project quotas
    "s_checksum_seed" / Int32ul,  # 0x270: Checksum seed used for metadata_csum calculations
    "s_wtime_hi" / Int8ul,  # 0x274: Upper 8 bits of the s_wtime field
    "s_mtime_hi" / Int8ul,  # 0x275: Upper 8 bits of the s_mtime field
    "s_mkfs_time_hi" / Int8ul,  # 0x276: Upper 8 bits of the s_mkfs_time field
    "s_lastcheck_hi" / Int8ul,  # 0x277: Upper 8 bits of the s_lastcheck field
    "s_first_error_time_hi" / Int8ul,  # 0x278: Upper 8 bits of the s_first_error_time field
    "s_last_error_time_hi" / Int8ul,  # 0x279: Upper 8 bits of the s_last_error_time field
    "s_pad" / Bytes(2),  # 0x27A: Zero padding
    "s_encoding" / Int16ul,  # 0x27C: Filename charset encoding
    "s_encoding_flags" / Int16ul,  # 0x27E: Filename charset encoding flags
    "s_orphan_file_inum" / Int32ul,  # 0x280: Orphan file inode number
    "s_reserved" / Bytes(94 * 4),  # 0x284: Padding to the end of the block
    "s_checksum" / Int32ul,  # 0x3FC: Superblock checksum
)

# File system state flags
EXT4_VALID_FS = 0x0001  # Unmounted cleanly
EXT4_ERROR_FS = 0x0002  # Errors detected
EXT4_ORPHAN_FS = 0x0004  # Orphans being recovered
EXT4_FC_REPLAY = 0x0020  # Fast commit replay ongoing

# Behaviour when detecting errors
EXT4_ERRORS_CONTINUE = 1  # Continue execution
EXT4_ERRORS_RO = 2  # Remount fs read-only
EXT4_ERRORS_PANIC = 3  # Panic
EXT4_ERRORS_DEFAULT = EXT4_ERRORS_CONTINUE  # Default behavior

# Filesystem creator
EXT4_OS_LINUX = 0  # Linux
EXT4_OS_HURD = 1  # Hurd
EXT4_OS_MASIX = 2  # Masix
EXT4_OS_FREEBSD = 3  # FreeBSD
EXT4_OS_LITES = 4  # Lites

# Superblock revision levels
EXT4_GOOD_OLD_REV = 0  # The good old (original) format
EXT4_DYNAMIC_REV = 1  # V2 format w/ dynamic inode sizes

# Superblock incompatible features
EXT4_FEATURE_INCOMPAT_COMPRESSION = 0x0001  # Compression
EXT4_FEATURE_INCOMPAT_FILETYPE = 0x0002  # Directory entries record the file type
EXT4_FEATURE_INCOMPAT_RECOVER = 0x0004  # Filesystem needs recovery
EXT4_FEATURE_INCOMPAT_JOURNAL_DEV = 0x0008  # Filesystem has a separate journal device
EXT4_FEATURE_INCOMPAT_META_BG = 0x0010  # Meta block groups
EXT4_FEATURE_INCOMPAT_EXTENTS = 0x0040  # Files in this filesystem use extents
EXT4_FEATURE_INCOMPAT_64BIT = 0x0080  # Enable a filesystem size of 2^64 blocks
EXT4_FEATURE_INCOMPAT_MMP = 0x0100  # Multiple mount protection
EXT4_FEATURE_INCOMPAT_FLEX_BG = 0x0200  # Flexible block groups
EXT4_FEATURE_INCOMPAT_EA_INODE = 0x0400  # Inodes can be used to store large extended attribute values
EXT4_FEATURE_INCOMPAT_DIRDATA = 0x1000  # Data in directory entry (Not implemented?)
EXT4_FEATURE_INCOMPAT_CSUM_SEED = 0x2000  # Metadata checksum seed is stored in the superblock
EXT4_FEATURE_INCOMPAT_LARGEDIR = 0x4000  # Large directory >2GB or 3-level htree
EXT4_FEATURE_INCOMPAT_INLINE_DATA = 0x8000  # Data in inode
EXT4_FEATURE_INCOMPAT_ENCRYPT = 0x10000  # Encrypted inodes are present on the filesystem

# EXT4 group descriptor structure
ext4_group_desc = Struct(
    "bg_block_bitmap_lo" / Int32ul,  # 0x0: Lower 32-bits of location of block bitmap
    "bg_inode_bitmap_lo" / Int32ul,  # 0x4: Lower 32-bits of location of inode bitmap
    "bg_inode_table_lo" / Int32ul,  # 0x8: Lower 32-bits of location of inode table
    "bg_free_blocks_count_lo" / Int16ul,  # 0xC: Lower 16-bits of free block count
    "bg_free_inodes_count_lo" / Int16ul,  # 0xE: Lower 16-bits of free inode count
    "bg_used_dirs_count_lo" / Int16ul,  # 0x10: Lower 16-bits of directory count
    "bg_flags" / Int16ul,  # 0x12: Block group flags
    "bg_exclude_bitmap_lo" / Int32ul,  # 0x14: Lower 32-bits of location of snapshot exclusion bitmap
    "bg_block_bitmap_csum_lo" / Int16ul,  # 0x18: Lower 16-bits of the block bitmap checksum
    "bg_inode_bitmap_csum_lo" / Int16ul,  # 0x1A: Lower 16-bits of the inode bitmap checksum
    "bg_itable_unused_lo" / Int16ul,  # 0x1C: Lower 16-bits of unused inode count
    "bg_checksum" / Int16ul,  # 0x1E: Group descriptor checksum
    "bg_block_bitmap_hi" / Int32ul,  # 0x20: Upper 32-bits of location of block bitmap
    "bg_inode_bitmap_hi" / Int32ul,  # 0x24: Upper 32-bits of location of inodes bitmap
    "bg_inode_table_hi" / Int32ul,  # 0x28: Upper 32-bits of location of inodes table
    "bg_free_blocks_count_hi" / Int16ul,  # 0x2C: Upper 16-bits of free block count
    "bg_free_inodes_count_hi" / Int16ul,  # 0x2E: Upper 16-bits of free inode count
    "bg_used_dirs_count_hi" / Int16ul,  # 0x30: Upper 16-bits of directory count
    "bg_itable_unused_hi" / Int16ul,  # 0x32: Upper 16-bits of unused inode count
    "bg_exclude_bitmap_hi" / Int32ul,  # 0x34: Upper 32-bits of location of snapshot exclusion bitmap
    "bg_block_bitmap_csum_hi" / Int16ul,  # 0x38: Upper 16-bits of the block bitmap checksum
    "bg_inode_bitmap_csum_hi" / Int16ul,  # 0x3A: Upper 16-bits of the inode bitmap checksum
    "bg_reserved" / Int32ul,  # 0x3C: Padding to 64 bytes
)

# Block group flags
EXT4_BG_INODE_UNINIT = 0x1  # inode table and bitmap are not initialized
EXT4_BG_BLOCK_UNINIT = 0x2  # block bitmap is not initialized
EXT4_BG_INODE_ZEROED = 0x4  # inode table is zeroed

# Linear (Classic) Directories
ext4_dir_entry_2 = Struct(
    "inode" / Int32ul,
    "rec_len" / Int16ul,
    "name_len" / Int8ul,
    "file_type" / Int8ul,
    "name" / Bytes(lambda ctx: ctx.name_len),
)

# Directory file types
EXT4_FT_UNKNOWN = 0x0  # Unknown
EXT4_FT_REG_FILE = 0x1  # Regular file
EXT4_FT_DIR = 0x2  # Directory
EXT4_FT_CHRDEV = 0x3  # Character device file
EXT4_FT_BLKDEV = 0x4  # Block device file
EXT4_FT_FIFO = 0x5  # FIFO
EXT4_FT_SOCK = 0x6  # Socket
EXT4_FT_SYMLINK = 0x7  # Symbolic link

ext4_dir_entry_tail = Struct(
    "det_reserved_zero1" / Int32ul,  # 0x0: Inode number, which must be zero
    "det_rec_len" / Int16ul,  # 0x4: Length of this directory entry, which must be 12
    "det_reserved_zero2" / Int8ul,  # 0x6: Length of the file name, which must be zero
    "det_reserved_ft" / Int8ul,  # 0x7: File type, which must be 0xDE
    "det_checksum" / Int32ul,  # 0x8: Directory leaf block checksum
)

dx_entry = Struct(
    "hash" / Int32ul,
    "block" / Int32ul,
)

# The following fields should be fixed data if the directory file is a dx_root structure.
# If not, try to parse the directory file as a linear directory.
# dot.rec_len = 12
# dot.name_len = 1
# dot.file_type = 2
# dot.name = b".\x00\x00\x00"
# dotdot.rec_len = block_size - 12 (in many cases, 4096 - 12 = 4084 = 0xFF4)
# dotdot.name_len = 2
# dotdot.file_type = 2
# dotdot.name = b"..\x00\x00"
# dx_root_info.reserved_zero = 0
# dx_root_info.hash_version = from 0 to 6
# dx_root_info.info_length = 8
# dx_root_info.indirect_levels = from 0 to 2 (if the INCOMPAT_LARGEDIR feature is set, to 3)
dx_root = Struct(
    "dot" / ext4_dir_entry_2,  # 0x0: inode number of this directory
    # 0x4: Length of this record, 12
    # 0x6: Length of the name, 1
    # 0x7: File type of this entry, 0x2 (directory)
    # 0x8: ".000"
    "dotdot" / ext4_dir_entry_2,  # 0xC: inode number of parent directory
    # 0x10: block_size - 12
    # 0x12: Length of the name, 2
    # 0x13: File type of this entry, 0x2 (directory)
    # 0x14: "..00"
    "dx_root_info"
    / Struct(  # struct dx_root_info
        "reserved_zero" / Int32ul,  # 0x18: Zero
        "hash_version" / Int8ul,  # 0x1C: Hash type
        "info_length" / Int8ul,  # 0x1D: Length of the tree information, 0x8
        "indirect_levels" / Int8ul,  # 0x1E: Depth of the htree
        "unused_flags" / Int8ul,  # 0x1F: Unused flags
    ),
    "limit" / Int16ul,  # 0x20: Maximum number of dx_entries that can follow this header
    "count" / Int16ul,  # 0x22: Actual number of dx_entries that follow this header
    "block" / Int32ul,  # 0x24: The block number that goes with hash=0
    "entries" / Array(lambda ctx: ctx.count - 1, dx_entry),  # 0x28: As many 8-byte struct dx_entry as fits in the rest of the data block
)


#
# Journal (JBD2) structures
#
JBD2_MAGIC_NUMBER = b"\xc0\x3b\x39\x98"

# Descriptor block types
JBD2_DESCRIPTOR_BLOCK = 1
JBD2_COMMIT_BLOCK = 2
JBD2_SUPERBLOCK_V1 = 3
JBD2_SUPERBLOCK_V2 = 4
JBD2_REVOKE_BLOCK = 5

journal_header_s = Struct(
    "h_magic" / Const(JBD2_MAGIC_NUMBER),
    "h_blocktype" / Int32ub,
    "h_sequence" / Int32ub,
)

# Checksum types
JBD2_CRC32_CHKSUM = 1
JBD2_MD5_CHKSUM = 2
JBD2_SHA1_CHKSUM = 3
JBD2_CRC32C_CHKSUM = 4

JBD2_CHECKSUM_BYTES = 32 // Int32ub.sizeof()

commit_header = Struct(
    "s_header" / journal_header_s,
    "h_chksum_type" / Int8ub,
    "h_chksum_size" / Int8ub,
    "h_padding" / Padding(2),
    "h_chksum" / Array(JBD2_CHECKSUM_BYTES, Int32ub),
    "h_commit_sec" / Int64ub,
    "h_commit_nsec" / Int32ub,
)

journal_block_tag3_s = Struct(
    "t_blocknr" / Int32ub,
    "t_flags" / Int32ub,
    "t_blocknr_high" / Int32ub,
    "t_checksum" / Int32ub,
)

journal_block_tag_s = Struct(
    "t_blocknr" / Int32ub,
    "t_checksum" / Int16ub,
    "t_flags" / Int16ub,
    "t_blocknr_high" / Int32ub,
)

# Tail of a descriptor or revoke block
jbd2_journal_block_tail = Struct(
    "t_checksum" / Int32ub,
)

jdb2_journal_revoke_header = Struct(
    "r_header" / journal_header_s,  # Common block header
    "r_count" / Int32ub,  # Number of bytes used in this block
)

# Definitions for the journal tag flags field (t_flags)
JBD2_FLAG_ESCAPE = 1  # on-disk block is escaped
JBD2_FLAG_SAME_UUID = 2  # block has same uuid as previous
JBD2_FLAG_DELETED = 4  # block deleted by this transaction
JBD2_FLAG_LAST_TAG = 8  # last tag in this descriptor block

journal_superblock_s = Struct(
    "s_header" / journal_header_s,
    "s_blocksize" / Int32ub,
    "s_maxlen" / Int32ub,
    "s_first" / Int32ub,
    "s_sequence" / Int32ub,
    "s_start" / Int32ub,
    "s_errno" / Int32ub,
    "s_feature_compat" / Int32ub,
    "s_feature_incompat" / Int32ub,
    "s_feature_ro_compat" / Int32ub,
    "s_uuid" / Bytes(16),
    "s_nr_users" / Int32ub,
    "s_dynsuper" / Int32ub,
    "s_max_transaction" / Int32ub,
    "s_max_trans_data" / Int32ub,
    "s_checksum_type" / Int8ub,
    "s_padding2" / Padding(3),
    "s_padding" / Padding(4 * 42),
    "s_checksum" / Int32ub,
    "s_users" / Array(48, Bytes(16)),
)

JBD2_FEATURE_COMPAT_CHECKSUM = 0x00000001

JBD2_FEATURE_INCOMPAT_REVOKE = 0x00000001
JBD2_FEATURE_INCOMPAT_64BIT = 0x00000002
JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT = 0x00000004
JBD2_FEATURE_INCOMPAT_CSUM_V2 = 0x00000008
JBD2_FEATURE_INCOMPAT_CSUM_V3 = 0x00000010
JBD2_FEATURE_INCOMPAT_FAST_COMMIT = 0x00000020


i_osd1_linux = Struct(
    "l_i_version" / Int32ub,
)

i_osd2_linux = Struct(
    "l_i_blocks_high" / Int16ul,
    "l_i_file_acl_high" / Int16ul,
    "l_i_uid_high" / Int16ul,
    "l_i_gid_high" / Int16ul,
    "l_i_checksum_lo" / Int16ul,
    "l_i_reserved" / Int16ul,
)

ext4_inode = Struct(
    "i_mode" / Int16ul,  # 0x0: File mode
    "i_uid" / Int16ul,  # 0x2: Lower 16-bits of Owner UID
    "i_size_lo" / Int32ul,  # 0x4: Lower 32-bits of size in bytes
    "i_atime" / Int32ul,  # 0x8: Last access time
    "i_ctime" / Int32ul,  # 0xC: Last inode change time
    "i_mtime" / Int32ul,  # 0x10: Last data modification time
    "i_dtime" / Int32ul,  # 0x14: Deletion Time
    "i_gid" / Int16ul,  # 0x18: Lower 16-bits of GID
    "i_links_count" / Int16ul,  # 0x1A: Hard link count
    "i_blocks_lo" / Int32ul,  # 0x1C: Lower 32-bits of block count
    "i_flags" / Int32ul,  # 0x20: Inode flags
    "i_osd1" / i_osd1_linux,  # 0x24: OS dependent 1
    "i_block" / Array(15, Int32ul),  # 0x28: Block map or extent tree
    "i_generation" / Int32ul,  # 0x64: File version (for NFS)
    "i_file_acl_lo" / Int32ul,  # 0x68: Lower 32-bits of extended attribute block
    "i_size_high" / Int32ul,  # 0x6C: Upper 32-bits of file/directory size
    "i_obso_faddr" / Int32ul,  # 0x70: (Obsolete) fragment address
    "i_osd2" / i_osd2_linux,  # 0x74: OS dependent 2
    "i_extra_isize" / Int16ul,  # 0x80: Size of this inode - 128
    "i_checksum_hi" / Int16ul,  # 0x82: Upper 16-bits of the inode checksum
    "i_ctime_extra" / Int32ul,  # 0x84: Extra change time bits
    "i_mtime_extra" / Int32ul,  # 0x88: Extra modification time bits
    "i_atime_extra" / Int32ul,  # 0x8C: Extra access time bits
    "i_crtime" / Int32ul,  # 0x90: File creation time
    "i_crtime_extra" / Int32ul,  # 0x94: Extra file creation time bits
    "i_version_hi" / Int32ul,  # 0x98: Upper 32-bits for version number
    "i_projid" / Int32ul,  # 0x9C: Project ID
)

# i_mode flags
# Permission bits
S_IXOTH = 0x1  # Others may execute
S_IWOTH = 0x2  # Others may write
S_IROTH = 0x4  # Others may read
S_IXGRP = 0x8  # Group members may execute
S_IWGRP = 0x10  # Group members may write
S_IRGRP = 0x20  # Group members may read
S_IXUSR = 0x40  # Owner may execute
S_IWUSR = 0x80  # Owner may write
S_IRUSR = 0x100  # Owner may read
S_ISVTX = 0x200  # Sticky bit
S_ISGID = 0x400  # Set GID
S_ISUID = 0x800  # Set UID
# File types (mutually-exclusive)
S_IFIFO = 0x1000  # FIFO
S_IFCHR = 0x2000  # Character device
S_IFDIR = 0x4000  # Directory
S_IFBLK = 0x6000  # Block device
S_IFREG = 0x8000  # Regular file
S_IFLNK = 0xA000  # Symbolic link
S_IFSOCK = 0xC000  # Socket

# i_flags field values
EXT4_SECRM_FL = 0x1  # This file requires secure deletion (not implemented)
EXT4_UNRM_FL = 0x2  # This file should be preserved, should undeletion be desired (not implemented)
EXT4_COMPR_FL = 0x4  # File is compressed (not really implemented)
EXT4_SYNC_FL = 0x8  # All writes to the file must be synchronous
EXT4_IMMUTABLE_FL = 0x10  # File is immutable
EXT4_APPEND_FL = 0x20  # File can only be appended
EXT4_NODUMP_FL = 0x40  # The dump(1) utility should not dump this file
EXT4_NOATIME_FL = 0x80  # Do not update access time
EXT4_DIRTY_FL = 0x100  # Dirty compressed file (not used)
EXT4_COMPRBLK_FL = 0x200  # File has one or more compressed clusters (not used)
EXT4_NOCOMPR_FL = 0x400  # Do not compress file (not used)
EXT4_ENCRYPT_FL = 0x800  # Encrypted inode (previously EXT4_ECOMPR_FL, not used)
EXT4_INDEX_FL = 0x1000  # Directory has hashed indexes
EXT4_IMAGIC_FL = 0x2000  # AFS magic directory
EXT4_JOURNAL_DATA_FL = 0x4000  # File data must always be written through the journal
EXT4_NOTAIL_FL = 0x8000  # File tail should not be merged (not used by ext4)
EXT4_DIRSYNC_FL = 0x10000  # All directory entry data should be written synchronously
EXT4_TOPDIR_FL = 0x20000  # Top of directory hierarchy
EXT4_HUGE_FILE_FL = 0x40000  # This is a huge file
EXT4_EXTENTS_FL = 0x80000  # Inode uses extents
EXT4_VERITY_FL = 0x100000  # Verity protected file
EXT4_EA_INODE_FL = 0x200000  # Inode stores a large extended attribute value in its data blocks
EXT4_EOFBLOCKS_FL = 0x400000  # This file has blocks allocated past EOF (deprecated)
EXT4_SNAPFILE_FL = 0x01000000  # Inode is a snapshot (not in mainline)
EXT4_SNAPFILE_DELETED_FL = 0x04000000  # Snapshot is being deleted (not in mainline)
EXT4_SNAPFILE_SHRUNK_FL = 0x08000000  # Snapshot shrink has completed (not in mainline)
EXT4_INLINE_DATA_FL = 0x10000000  # Inode has inline data
EXT4_PROJINHERIT_FL = 0x20000000  # Create children with the same project ID
EXT4_RESERVED_FL = 0x80000000  # Reserved for ext4 library
# Aggregate flags
EXT4_FL_USER_VISIBLE = 0x705BDFFF  # User-visible flags
EXT4_FL_USER_MODIFIABLE = 0x604BC0FF  # User-modifiable flags


#
# Extended attributes
#
EXT4_XATTR_MAGIC = b"\x00\x00\x02\xea"
# Extended attributes after the inode
ext4_xattr_ibody_header = Struct(
    "h_magic" / Const(EXT4_XATTR_MAGIC),  # Magic number for identification, 0xEA020000
)

# The beginning of an extended attribute block
ext4_xattr_header = Struct(
    "h_magic" / Const(EXT4_XATTR_MAGIC),  # Magic number for identification, 0xEA020000
    "h_refcount" / Int32ul,  # Reference count
    "h_blocks" / Int32ul,  # Number of disk blocks used
    "h_hash" / Int32ul,  # Hash value of all attributes
    "h_checksum" / Int32ul,  # Checksum of the extended attribute block
    "h_reserved" / Array(3, Int32ul),  # Reserved (zero)
)

# Extended attribute entry
ext4_xattr_entry = Struct(
    "e_name_len" / Int8ul,  # Length of name
    "e_name_index" / Int8ul,  # Attribute name index
    "e_value_offs" / Int16ul,  # Location of this attribute's value on the disk block where it is stored
    "e_value_inum" / Int32ul,  # The inode where the value is stored
    "e_value_size" / Int32ul,  # Length of attribute value
    "e_hash" / Int32ul,  # Hash value of attribute name and attribute value
    "e_name" / Bytes(lambda ctx: ctx.e_name_len),  # Attribute name
    # "padding" / Padding(lambda ctx: 4 - (ctx.e_name_len % 4)),  # Padding to align to 4 bytes
)

EXT4_XATTR_INDEX_USER = 1  # user.
EXT4_XATTR_INDEX_POSIX_ACL_ACCESS = 2  # system.posix_acl_access
EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT = 3  # system.posix_acl_default
EXT4_XATTR_INDEX_TRUSTED = 4  # trusted.
EXT4_XATTR_INDEX_LUSTRE = 5  # lustre.
EXT4_XATTR_INDEX_SECURITY = 6  # security.
EXT4_XATTR_INDEX_SYSTEM = 7  # system.
EXT4_XATTR_INDEX_RICHACL = 8  # system.richacl
EXT4_XATTR_INDEX_ENCRYPTION = 9  # system.encryption
EXT4_XATTR_INDEX_HURD = 10  # Reserved for Hurd
