# Crypt4GH File System

crypt4ghfs is a read-only fuse layer exposing Crypt4GH-encrypted files, as if they were decrypted

	crypt4ghfs [-f|--foreground] [--conf conf_file] <mountpoint>
	
The default configuration file is in `~/.c4gh/fs.conf`.

See [the configuration sample](crypt4ghfs.conf.sample) for examples.

* `seckey` must point to a [Crypt4GH private key](https://crypt4gh.readthedocs.io/en/latest/keys.html) or an ED25519 ssh key. This option is required.
* `rootdir` must point to the root directory where the Crypt4GH-encrypted files reside. This option is required.
* when _not_ in read-only mode, a list of recipients must be specified (potentially only including yourself), for the case of an encrypting file system.

By default, we daemonize the process. Use `-f` (or `--foreground`) to keep it in the foreground. This is useful to see the logs, since `stdout`/`stderr` are otherwise redirected to `/dev/null` when the process is daemonized.

Extra debug output is available if `log_level=LEVEL` is used (where `LEVEL` is a [Python logging levels](https://docs.python.org/3/library/logging.html#levels))

## Example

Assume you have Crypt4GH-encrypted files in `~/encrypted-files`, and your private key in `~/.c4gh/mykey`.
You can create a configuration file in `~/.c4gh/fs.conf` with

	[DEFAULT]
	rootdir=~/encrypted-files
	[CRYPT4GH]
	seckey = ~/.c4gh/mykey

Create an (empty) directory, `~/clear-files` and mount the Crypt4GH file system in it with:

	crypt4ghfs ~/clear-files
	
You can now read files in `~/encrypted-files` as if they were decrypted.  
Instead of 

	crypt4gh decrypt --sk ~/.c4gh/mykey < ~/encrypted-files/example.txt.c4gh | less

you can now simply, use

	cat ~/clear-files/example.txt
	# or any other tool using the POSIX file abstraction

> Tips: if you mount sshfs from the [EGA distribution system](https://ega-archive.org/doc/distribution), you can download chunk-by-chunk
> the files from the EGA, as Crypt4GH files, and use _all_ of them with 2 commands: `sshfs -o uid=$(id -u),gid=$(id -g) -f <remote-url>:. ~/encrypted-files`, followed by `crypt4ghfs ~/clear-files`. After that, you keep your prompt and can "use" the files in `ls -al ~/clear-files`.
		

## Installation

The [code](ingestion/lega) is written in Python
(3.6+). [libfuse](https://github.com/libfuse/libfuse) and
[pyfuse3](https://github.com/libfuse/pyfuse3) are required. To install
libfuse, you'll need `cmake`, `meson` and `ninja`.

On Ubuntu, run:

	apt-get install ca-certificates pkg-config git gcc make automake autoconf libtool bzip2 zlib1g-dev libssl-dev libedit-dev ninja-build cmake udev libc6-dev
	pip install -U pip
    pip install meson pytest

Install the (latest) libfuse (v3.10) with:

    git clone https://github.com/libfuse/libfuse.git
    cd libfuse
    git checkout fuse-3.10.0
    mkdir build
    cd build
    meson ..
    ninja
    ninja install

Finally, install the python packages:

	pip install crypt4ghfs
	# this will install crypt4gh, trio and pyfuse3 too

For the (latest) SSHFS (v3.7), useful to test the above tips:

	git clone https://github.com/libfuse/sshfs.git
    cd sshfs
    git checkout sshfs-3.7.0
    mkdir build
    cd build
    meson ..
    ninja
    ninja install
