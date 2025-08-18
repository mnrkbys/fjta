# FJTA - Forensic Journal Timeline Analyzer

FJTA (Forensic Journal Timeline Analyzer) is a tool that analyzes Linux filesystem (ext4, XFS) journals (not systemd-journald logs), generates timelines, and detects suspicious activities.

> [!CAUTION]
> Since testing is only being done with simple disk images, there may be many issues when analyzing more practical disk images.

## Features

- **Journal Analysis**: Scans ext4 and XFS journals to visualize modification history.
- **Timeline Generation**: Organizes events within the journal in chronological order.
- **Suspicious Activity Detection**: Identifies deleted files and potentially tampered operations.
- **Cross-Platform Compatibility**: Written in Python, allowing analysis on any operating system.

## Supported Artifacts in Filesystem Journals

| Artifacts                              |  ext4  |  XFS  |
|----------------------------------------|:------:|:-----:|
| inode                                  | ✅     | ✅    |
| Directories with few entries           | ✅     | ✅    |
| Directories with many entries          | ✅     | ✅    |
| Short symlink target names             | ✅     | ✅    |
| Long symlink target names[^1]          | ✅     | ❌    |
| Short extended attributes              | ✅     | ✅    |
| Long extended attributes[^2]           | ✅     | ❌    |
| Non-regular files (e.g. block devices) | ✅     | ✅    |
| Year 2038 problem                      | ✅     | ✅    |

[^1]: Symlink target names stored outside the inode.
[^2]: Extended attributes stored outside the inode.

## Detectable Activities

| Activities                            |  ext4  |  XFS  |
|---------------------------------------|:------:|:-----:|
| Creating files                        | ✅     | ✅    |
| Deleting files                        | ✅     | ✅    |
| Modification of extended attributes   | ✅     | ✅    |
| Timestomping (timestamp manipulation) | ✅     | ✅    |
| Other inode metadata changes[^3]      | ✅     | ✅    |

[^3]: "Other inode metadata changes" include updates to MACB timestamps (mtime, atime, ctime, and crtime), file size changes, and setting file flags, and more.

## Requirements

Tested with the following software and libraries:

- Python 3.12 or later
- [The Sleuth Kit](https://github.com/sleuthkit/sleuthkit) 4.13.0 or later
- [pytsk3](https://github.com/py4n6/pytsk) 20250312 or later
- [Construct](https://github.com/construct/construct) 2.10 or later

## Installation

Compile and install the TSK, or simply install the package from the Linux distribution you are using.

> [!NOTE]
> TSK also requires other libraries such as libewf, libvmdk, and so on.

```bash
wget https://github.com/sleuthkit/sleuthkit/releases/download/sleuthkit-4.13.0/sleuthkit-4.13.0.tar.gz
tar xvzf sleuthkit-4.13.0.tar.gz
cd sleuthkit-4.13.0
./configure
make
sudo make install
sudo ldconfig
```

Or, you can install the TSK package, if the Linux distribution you're using provide it.

```bash
sudo apt install sleuthkit
```

Then, install required Python packages.

```bash
python3 -m venv .venv
PYTHONPATH=/usr/local/lib/python3/dist-packages/:$PYTHONPATH source .venv/bin/activate
pip install pytsk3 construct
```

Clone FJTA.

```bash
git clone https://github.com/mnrkbys/fjta.git
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

## Tested on

- Ubuntu 24.10 with kernel 6.8.0-63
- Rocky Linux 9.4 with kernel 5.14.0-427.31.1.el9_4.x86_64

## Contributing

Contributions are welcome! If you wish to contribute, please fork the repository and create a feature branch. Pull requests are greatly appreciated.

## Limitations

- FJTA is still under development, so some filesystem data may not be available for analysis. Additionally, the output format is subject to change.
- FJTA only supports RAW disk images.
- FJTA can analyze only ext4 and XFS version 5 (inode version 3).
- Only ext4 journals stored with "data=ordered" are supported.
- Fast commit on ext4 is not supported.
- External journals are not supported.

## Author

[Minoru Kobayashi](https://x.com/unkn0wnbit)

## License

FJTA (Forensic Journal Timeline Analyzer) is released under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0). See the LICENSE file for more details.
