import pytsk3

from . import ext4, xfs


class JournalParser:
    def __init__(self, img_file: str) -> None:
        self.img_info = pytsk3.Img_Info(img_file)
        self.fs_info = pytsk3.FS_Info(self.img_info)
        if self.fs_info.info.ftype == pytsk3.TSK_FS_TYPE_EXT4:
            self.journal_parser = ext4.Ext4JournalParser(self.img_info, self.fs_info)
        elif self.fs_info.info.ftype == 0x80000:  # pytsk3.TSK_FS_TYPE_XFS:
            self.journal_parser = xfs.JournalParserXfs(self.img_info, self.fs_info)
        else:
            msg = "File system is not supported."
            raise TypeError(msg)

    def parse_journal(self) -> None:
        self.journal_parser.parse_journal()

    def print_transactions(self) -> None:
        print("===== Transactions =====")
        for tid in self.journal_parser.transactions:
            print(f"Transaction ID: {tid}")
            transaction = self.journal_parser.transactions[tid]
            print("Entry Info:")
            for inode_num in transaction.entries:
                entry = transaction.entries[inode_num]
                print(f"Inode: {inode_num}")
                print(f"  Dir Inode: {entry.dir_inode}")
                print(f"  Parent Inode: {entry.parent_inode}")
                print(f"  File Type: {entry.file_type}")
                print(f"  Name: {entry.name}")
                print(f"  Mode: {entry.mode:04o}")
                print(f"  UID: {entry.uid}")
                print(f"  GID: {entry.gid}")
                print(f"  Size: {entry.size}")
                print(f"  Atime: {entry.atime}")
                print(f"  Ctime: {entry.ctime}")
                print(f"  Mtime: {entry.mtime}")
                print(f"  Crtime: {entry.crtime}")
                # print(f"  Dtime: {entry.dtime}")
                print(f"  Flags: {entry.flags}")
                if entry.extended_attributes:
                    print("  Extended Attributes:")
                    for ea in entry.extended_attributes:
                        print(f"    Name: {ea.name}")
                        print(f"    Value: {ea.value}")

    def timeline(self) -> None:
        self.journal_parser.timeline()
