# FJTA - Forensic Journal Timeline Analyzer

FJTA (Forensic Journal Timeline Analyzer) is a tool that analyzes Linux filesystem (EXT4, XFS) journals (not systemd-journald), generates timelines, and detects suspicious activities.

> [!CAUTION]
> Since testing is only being done with simple disk images, there may be many issues when using more practical disk images.

## Features

- **Journal Analysis**: Scans EXT4 and XFS journals to visualize modification history.
- **Timeline Generation**: Organizes events within the journal in chronological order.
- **Suspicious Activity Detection**: Identifies deleted files and potentially tampered operations.
- **Cross-Platform Compatibility**: Written in Python, allowing analysis on any operating system.

> [!IMPORTANT]
>
> - FJTA only supports EXT4 and XFS version 5 (inode version 3).
> - Only EXT4 journals stored with "data=ordered" are supported.
> - External journals are not supported.

## Analyzable artifacts within filesystem journals

| Artifacts                        |  EXT4  |  XFS  |
|----------------------------------|:------:|:-----:|
| inode                            | ✅     | ✅    |
| Few files in directory entries   | ✅     | ✅    |
| Many files in directory entries  | ✅     | ✅    |
| Short symlink target names       | ✅     | ✅    |
| Long symlink target names        | ✅     | ❌    |
| Short extended attributes        | ✅     | ✅    |
| Long extended attributes         | ✅     | ❌    |
| Device number                    | ✅     | ✅    |
| Year 2038 problem                | ✅     | ✅    |

## Detectable activities

| Activities                         |  EXT4  |  XFS  |
|------------------------------------|:------:|:-----:|
| Creating files                     | ✅     | ✅    |
| Deleting files                     | ❌     | ❌    |
| Modification of crtime             | ✅     | ✅    |
| Modification of atime              | ✅     | ✅    |
| Modification of ctime              | ✅     | ✅    |
| Modification of mtime              | ✅     | ✅    |
| Timestomping (time manipulation)   | ✅     | ✅    |
| File size change                   | ✅     | ✅    |
| Modification of extended attributes| ✅     | ✅    |
| Set immutable flag                 | ✅     | ✅    |

## Requirements

- Python 3.12 or later
- [The Sleuth Kit](https://github.com/sleuthkit/sleuthkit) (develop branch is needed)
- [pytsk](https://github.com/py4n6/pytsk) (needs to compile with TSK's develop branch)
- [Construct](https://github.com/construct/construct)

## Installation

```bash
git clone https://github.com/mnrkbys/fjta.git
```

## Usage

```bash
python ./fjta.py -i ~/ext4.img | jq
```

## Execution results

```bash
{
  "transaction_id": 2,
  "inode": 7,
  "file_type": "REGULAR_FILE",
  "name": [
    "Reserved group descriptors inode"
  ],
  "action": "CREATE",
  "dir_inode": 0,
  "parent_inode": 0,
  "mode": 384,
  "uid": 0,
  "gid": 0,
  "size": 4299210752,
  "atime": 1729038659.0,
  "ctime": 1729038659.0,
  "mtime": 1729038659.0,
  "crtime": 1729038659.0,
  "dtime": 0,
  "flags": 0,
  "symlink_target": "",
  "extended_attributes": [],
  "info": "Crtime: 2024-10-16 00:30:59.000000000 UTC"
}
...
{
  "transaction_id": 23,
  "inode": 12,
  "file_type": "REGULAR_FILE",
  "name": [
    "test.txt"
  ],
  "action": "CREATE|ACCESS|CHANGE|MODIFY|TIMESTOMP",
  "dir_inode": 2,
  "parent_inode": 2,
  "mode": 420,
  "uid": 0,
  "gid": 0,
  "size": 0,
  "atime": 978312225.8287878,
  "ctime": 978312225.8287878,
  "mtime": 978312225.8287878,
  "crtime": 978312225.8287878,
  "dtime": 0,
  "flags": 524288,
  "symlink_target": "",
  "extended_attributes": [],
  "info": "Atime: 2024-10-18 08:25:51.385837319 UTC -> 2001-01-01 01:23:45.828787850 UTC (Timestomp)|Ctime: 2024-10-18 08:25:51.385837319 UTC -> 2001-01-01 01:23:45.828787850 UTC (Timestomp)|Mtime: 2024-10-18 08:25:51.385837319 UTC -> 2001-01-01 01:23:45.828787850 UTC (Timestomp)|Crtime: 2024-10-16 00:33:27.910174879 UTC -> 2001-01-01 01:23:45.828787850 UTC (Timestomp)"
}
...
```

## Contributing

Contributions are welcome! If you wish to contribute, please fork the repository and create a feature branch. Pull requests are greatly appreciated.

## Limitations

This tool is still under development, so some filesystem information may not be available for analysis. Additionally, the output format is subject to change.

## Author

[Minoru Kobayashi](https://x.com/unkn0wnbit)

## License

FJTA (Forensic Journal Timeline Analyzer) is released under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0). See the LICENSE file for more details.
