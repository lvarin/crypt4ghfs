# Crypt4GH File System

crypt4ghfs is a fuse layer exposing Crypt4GH-encrypted files, as if they were decrypted

	crypt4ghfs [-o options] <mountpoint>
	
The default options are: `ro,allow_root,default_permissions,seckey=~/.c4gh/sec.key`

`seckey` must point to a [Crypt4GH private key](https://crypt4gh.readthedocs.io/en/latest/keys.html) or an ED25519 ssh key. This option is required.

`rootdir=<path>` must point to the root directory where the Crypt4GH-encrypted files reside. This option is required.

Extra debug output is available if the options `debug_fuse` and/or `debug=LEVEL` are used (where `LEVEL` is a [Python logging levels](https://docs.python.org/3/library/logging.html#levels))
