# SeedVault Backup Parser

This is a tool to decrypt the android backups make by [Seedvault](https://github.com/stevesoltys/seedvault/)


## Usage
To decrypt a backup stored in the folder `1601080173780` into `decrypted`, run
```
./parse.py decrypt 1601080173780 decrypted
```

The script will ask for your 12 word mnemonic key at runtime. It has to be lowercase, words separated by a single space.
Example:

```
fish test thing gift mercy siren erode acoustic mango veteran soup bus
```

## Requirements
For the AES decryption, the python dependency `pycryptodome` is needed.
Script only tested on Linux.


## Backup Format
The current backup format (as of 2020/10/04) is Version 0. Each file starts with a single byte specifying the used version. After that, a list of segments follows. Each is:

```
2 Bytes Segment Length x | 12 Bytes Encryption IV | x Bytes Encryted Segment Content
```

For Key-Value backups, the first segment contains a VersionHeader, which specifies the app and key.

## License
This application is available as open source under the terms of the [Apache-2.0 License](https://opensource.org/licenses/Apache-2.0).
