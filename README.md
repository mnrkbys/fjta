# FJTA - Forensic Journal Timeline Analyzer

FJTA (Forensic Journal Timeline Analyzer) is a tool that analyzes Linux filesystem (ext4, XFS) journals (not systemd-journald logs), generates timelines, and detects suspicious activities.

> [!CAUTION]
> Since testing is only being done with simple disk images, there may be many issues when analyzing more practical disk images.

## Features

- **Journal Analysis**: Scans ext4 and XFS journals to visualize modification history.
- **Timeline Generation**: Organizes events within the journal in chronological order.
- **Suspicious Activity Detection**: Identifies deleted files and potentially tampered operations.
- **Cross-Platform**: Written in Python, allowing analysis on any operating system.

## Supported Artifacts in Filesystem Journals

| Artifacts                              |  ext4  |  XFS  |
|----------------------------------------|:------:|:-----:|
| inode                                  | ✅     | ✅    |
| Directories with few entries           | ✅     | ✅    |
| Directories with many entries          | ✅[^1] | ✅    |
| Short symlink target names             | ✅     | ✅    |
| Long symlink target names[^2]          | ✅     | ❌    |
| Short extended attributes              | ✅     | ✅    |
| Long extended attributes[^3]           | ✅     | ❌    |
| Non-regular files (e.g. block devices) | ✅     | ✅    |
| Year 2038 problem                      | ✅     | ✅    |
| Exported journals                      | ✅     | ✅    |

[^1]: Currently, only linear directories can be parsed. Support for hash tree directories will be added in future versions.
[^2]: Symlink target names stored outside an inode.
[^3]: Extended attributes stored outside an inode.

## Detectable Activities

| Activities                            |  ext4  |  XFS  |
|---------------------------------------|:------:|:-----:|
| Creating files                        | ✅     | ✅    |
| Deleting files                        | ✅     | ✅    |
| Modification of extended attributes   | ✅     | ✅    |
| Timestomping (timestamp manipulation) | ✅     | ✅    |
| Other inode metadata changes[^4]      | ✅     | ✅    |

[^4]: "Other inode metadata changes" include updates to MACB timestamps (mtime, atime, ctime, and crtime), file size changes, and setting file flags, and more.

## Requirements

Tested with the following software and libraries:

- [Python](https://www.python.org/) 3.12
- [The Sleuth Kit](https://github.com/sleuthkit/sleuthkit) 4.14.0
- [pytsk3](https://github.com/py4n6/pytsk) 20250729
- [Construct](https://github.com/construct/construct) 2.10.70
- [python-magic](https://github.com/ahupp/python-magic) 0.4.27
- [libewf-python](https://pypi.org/project/libewf-python/) 20240506
- [libvmdk-python](https://pypi.org/project/libvmdk-python/) 20240510
- [libvhdi-python](https://pypi.org/project/libvhdi-python/) 20240509
- [tqdm](https://github.com/tqdm/tqdm) 4.67.1

## Installation From Source

Compile and install the TSK.

> [!NOTE]
> TSK also requires other libraries such as libewf, libvmdk, and so on.

```bash
wget https://github.com/sleuthkit/sleuthkit/releases/download/sleuthkit-4.14.0/sleuthkit-4.14.0.tar.gz
tar xvzf sleuthkit-4.14.0.tar.gz
cd sleuthkit-4.14.0
./configure
make
sudo make install
sudo echo /usr/local/lib > /etc/ld.so.conf.d/local-lib.conf
sudo ldconfig
```

Then, clone FJTA.

```bash
git clone https://github.com/mnrkbys/fjta.git
cd fjta
```

Finally, install required Python packages.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install pytsk3 construct python-magic libewf-python libvmdk-python libvhdi-python
```

## Installation From Packages

Install the TSK package from the Linux distribution you are using.

> [!NOTE]
> In older versions of libvmdk, you cannot open VMDK files created with VMware Workstation for Windows (Japanese edition).
> The patch was integrated in [2022](https://github.com/libyal/libvmdk/pull/31).

```bash
sudo apt install sleuthkit python3-tsk libewf2 libvmdk1 libvhdi1 python3-libewf python3-libvmdk python3-libvhdi
```

Then, clone FJTA.

```bash
git clone https://github.com/mnrkbys/fjta.git
cd fjta
```

Finally, install required Python packages.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install construct python-magic
```

## Usage

### Basic

```bash
python ./fjta.py -i ~/ext4.img | jq
```

### Filtering with an inode number

```bash
python ./fjta.py -s 0 -i ~/xfs.img | jq 'select(.inode == 101040435)' | less
```

### Filtering with crtime

The to_epoch() function is defined in the helper.sh file, so you need to import it before executing the following command.

```bash
source scripts/helper.sh
python ./fjta.py -s 0 -i ~/xfs.img | jq --argjson threshold $(to_epoch "2025-06-23 07:33:20.123456789") 'select(.crtime >= $threshold)'
```

### Filtering with a filename

```bash
python ./fjta.py -s 0 -i ~/xfs.img | jq 'select(.names? and ([.names[][]] | index("backdoor.c")))'
```

### Filtering with a string

```bash
python ./fjta.py -s 0 -i ~/xfs.img | jq 'select(.info | contains("Added EA: security.selinux"))'
```

### Filtering with a regex pattern

```bash
python ./fjta.py -s 0 -i ~/xfs.img | jq 'select(.info | test("added ea: security\\.selinux"; "i"))'
```

## Sample Output (timestomping)

```bash
...
{
  "transaction_id": 3,
  "action": "CREATE_INODE|CREATE_HARDLINK",
  "inode": 12,
  "file_type": "REGULAR_FILE",
  "names": {
    "2": [
      "test.txt"
    ]
  },
  "mode": 420,
  "uid": 0,
  "gid": 0,
  "size": 0,
  "atime": 1729038807.9101748,
  "ctime": 1729038807.9101748,
  "mtime": 1729038807.9101748,
  "crtime": 1729038807.9101748,
  "dtime": 0.0,
  "flags": 524288,
  "link_count": 1,
  "symlink_target": "",
  "extended_attributes": [],
  "device_number": {
    "major": 0,
    "minor": 0
  },
  "info": "Crtime: 2024-10-16 00:33:27.910174879 UTC|Link Count: 1"
}
...
{
  "transaction_id": 23,
  "action": "CREATE_INODE|ACCESS|CHANGE|MODIFY|TIMESTOMP",
  "inode": 12,
  "file_type": "REGULAR_FILE",
  "names": {
    "2": [
      "test.txt"
    ]
  },
  "mode": 420,
  "uid": 0,
  "gid": 0,
  "size": 0,
  "atime": 978312225.8287878,
  "ctime": 978312225.8287878,
  "mtime": 978312225.8287878,
  "crtime": 978312225.8287878,
  "dtime": 0.0,
  "flags": 524288,
  "link_count": 1,
  "symlink_target": "",
  "extended_attributes": [],
  "device_number": {
    "major": 0,
    "minor": 0
  },
  "info": "Atime: 2024-10-18 08:25:51.385837319 UTC -> 2001-01-01 01:23:45.828787850 UTC (Timestomp)|Ctime: 2024-10-18 08:25:51.385837319 UTC -> 2001-01-01 01:23:45.828787850 UTC (Timestomp)|Mtime: 2024-10-18 08:25:51.385837319 UTC -> 2001-01-01 01:23:45.828787850 UTC (Timestomp)|Crtime: 2024-10-16 00:33:27.910174879 UTC -> 2001-01-01 01:23:45.828787850 UTC (Timestomp)"
}
...
```

## How to export filesystem journals

FJTA can analyze exported journals. However, some parameters required for analysis are not included in the exported data. Therefore, the corresponding superblock information must also be dumped.

### ext4

```bash
sudo dumpe2fs /dev/sda3 > sda3.dumpe2fs
sudo debugfs -R 'dump <8> sda3.journal' /dev/sda3
```

### XFS

```bash
sudo xfs_info /dev/mapper/rl-root > rl-root.xfs_info
sudo xfs_logprint -C rl-root.journal /dev/mapper/rl-root
```

## Tested on

- Ubuntu 24.10 with kernel 6.8.0-63
- Rocky Linux 9.4 with kernel 5.14.0-427.31.1.el9_4.x86_64

## Supported Formats

- RAW
- EWF
- VMDK
- VHD / VHDX
- Directly filesystem (ext4 and XFS partitions)

## Contributing

Contributions are welcome! If you wish to contribute, please fork the repository and create a feature branch. Pull requests are greatly appreciated.

## Limitations

- FJTA is still under development, so some filesystem data may not be available for analysis. Additionally, the output format is subject to change.
- FJTA can analyze only ext4 and XFS version 5 (inode version 3).
- FJTA does not support LVM.
- Only ext4 journals stored with "data=ordered" are supported. data=ordered is the default journaling mode in most Linux distributions.
- Fast commit on ext4 is not supported.
- External journals are not supported.

## Author

[Minoru Kobayashi](https://x.com/unkn0wnbit)

## License

FJTA (Forensic Journal Timeline Analyzer) is released under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0). See the LICENSE file for more details.
