# Crypt4GH File System

crypt4ghfs is a fuse layer exposing Crypt4GH-encrypted files, as if they were decrypted

	crypt4ghfs [-f|--foreground] [--conf conf_file] <mountpoint>
	
The default configuration file is in `~/.c4gh/fs.conf`.

See [the configuration sample](crypt4ghfs.conf.sample) for examples.

By default, we daemonize the process. Use `-f` (or `--foreground`) to keep it in the foreground. This is useful to see the logs, since `stdout`/`stderr` are otherwise redirected to `/dev/null` when the process is daemonized.

* `seckey` must point to a [Crypt4GH private key](https://crypt4gh.readthedocs.io/en/latest/keys.html) or an ED25519 ssh key. This option is required.
* `rootdir` must point to the root directory where the Crypt4GH-encrypted files reside. This option is required.

Extra debug output is available if `log_level=LEVEL` is used (where `LEVEL` is a [Python logging levels](https://docs.python.org/3/library/logging.html#levels))

In the case of an encrypting file system (ie not read-only mode), a list of recipients must be specified (potentially only including
yourself).

