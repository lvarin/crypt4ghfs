
import os
import sys
from argparse import ArgumentParser
import errno
import logging
import stat
from os import fsencode, fsdecode
from functools import partial

import pyfuse3
from pyfuse3 import FUSEError

from .decryptor import FileDecryptor

LOG = logging.getLogger(__name__)

async def _not_permitted_func(name, *args, **kwargs):
    LOG.debug('Function %s not permitted', name)
    raise FUSEError(errno.EPERM) # not permitted

class NotPermittedMetaclass(type):
    """Declare extra functions as not permitted."""

    def __new__(mcs, name, bases, attrs):
        not_permitted = attrs.pop('_not_permitted', [])
        for func in not_permitted:
            attrs[func] = partial(_not_permitted_func, func)
        new_class = super().__new__(mcs, name, bases, attrs)
        return new_class

class Crypt4ghFS(pyfuse3.Operations, metaclass=NotPermittedMetaclass):

    _not_permitted = [
        'readlink'
        'unlink',
        'rmdir',
        'symlink',
        'rename',
        'link',
        'setattr',
        'mknod',
        'mkdir',
        'create',
        'write',
   ]

    supports_dot_lookup = True
    enable_writeback_cache = False
    enable_acl = False

    __slots__ = ('_inode2path',
                 '_fd2decryptors',
                 '_inode2enties',
                 '_inode2mtime',
                 'rootdir',
                 'keys')

    def __init__(self, rootdir, seckey):

        self.rootdir = rootdir
        self._inode2path = { pyfuse3.ROOT_INODE: rootdir }
        self.keys = [(0, seckey, None)]
        self._fd2decryptors = dict()
        super(pyfuse3.Operations, self).__init__()
        self._inode2mtime = dict()
        self._inode2entries = dict()

    def _inode_to_path(self, inode):
        path = self._inode2path.get(inode)
        if path is None:
            raise FUSEError(errno.ENOENT)
        return path

    # async def forget(self, inode_list):
    #     for (inode, nlookup) in inode_list:
    #         if self._lookup_cnt[inode] > nlookup:
    #             self._lookup_cnt[inode] -= nlookup
    #             continue
    #         LOG.debug('forgetting about inode %d', inode)
    #         assert inode not in self._inode2fd
    #         del self._lookup_cnt[inode]
    #         try:
    #             del self._inode_path_map[inode]
    #         except KeyError: # may have been deleted
    #             pass

    async def lookup(self, inode_p, name, ctx=None):
        name = fsdecode(name)
        LOG.info('lookup for %s in %d', name, inode_p)
        path = os.path.join(self._inode_to_path(inode_p), name)
        return self._getattr(path=path)

    async def getattr(self, inode, ctx=None):
        return self._getattr(self._inode_to_path(inode))

    def _getattr(self, path):
        LOG.debug('_getattr: path=%s', path)
        try:
            s = os.lstat(path)
        except OSError as exc:
            raise FUSEError(exc.errno)
        self._inode2path[s.st_ino] = path
        return self._stats2entry(s)

    def _stats2entry(self, s):
        entry = pyfuse3.EntryAttributes()
        for attr in ('st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
                     'st_rdev', 'st_size', 'st_atime_ns', 'st_mtime_ns',
                     'st_ctime_ns'):
            setattr(entry, attr, getattr(s, attr))
        entry.generation = 0
        entry.entry_timeout = 0
        entry.attr_timeout = 0
        entry.st_blksize = 512
        entry.st_blocks = ((entry.st_size+entry.st_blksize-1) // entry.st_blksize)
        return entry

    async def opendir(self, inode, ctx):

        path = self._inode_to_path(inode)
        LOG.info('opening %s', path)
        mtime = self._inode2mtime.get(inode)
        entry = self._getattr(path)

        # cache up to date
        if mtime and mtime == entry.st_mtime_ns:
            LOG.debug('cache uptodate, not modified since %s', mtime)
            return inode

        # update cache
        LOG.debug('Fetching entries for %s', path)
        entries = []
        self._inode2mtime[inode] = entry.st_mtime_ns
        with os.scandir(path) as it: # read entirely. TODO: check if we can read it sorted.
            for entry in it:
                if not entry.name.startswith('.'):
                    entries.append((entry.inode(), entry.name, entry.stat()))
        self._inode2entries[inode] = sorted(entries)
        return inode

    async def readdir(self, inode, off, token):
        if not off:
            off = -1

        path = self._inode_to_path(inode)
        LOG.info('readdir %s [inode %s]', path, inode)
        LOG.debug('\toffset %s', off)
        entries = self._inode2entries[inode]
        LOG.debug('read %d entries, starting at %d', len(entries), off)

        # Sort them for the offset
        for (ino, name, attrs) in entries:
            if ino <= off:
                continue
            entry = self._stats2entry(attrs)
            entry_path = os.path.join(path, name)
            self._inode2path[attrs.st_ino] = entry_path
            LOG.debug('%s contains %s', path, entry_path)
            LOG.debug('%s with stats %s', entry_path, attrs)
            res = pyfuse3.readdir_reply(token, fsencode(name), entry, ino)
            LOG.debug('---------- REPLY %s: %s %s', fsencode(name), res,
                      ' | '.join(f'{attr}: {getattr(entry, attr)}' for attr in ('st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
                                                                             'st_rdev', 'st_size', 'st_atime_ns', 'st_mtime_ns',
                                                                             'st_ctime_ns')))

        return False # over


    async def open(self, inode, flags, ctx):

        if (flags & os.O_RDWR
            or flags & os.O_WRONLY
            or flags & os.O_APPEND
            or flags & os.O_CREAT
            or flags & os.O_TRUNC):
            raise pyfuse3.FUSEError(errno.EPERM)

        try:
            path = self._inode_to_path(inode)
            dec = FileDecryptor(path, flags, self.keys)
            fd = dec.fd()
            self._fd2decryptors[fd] = dec
        except OSError as exc:
            LOG.error('OSError opening %s: %s', path, exc)
            raise FUSEError(exc.errno)
        except Exception as exc:
            LOG.error('Error opening %s: %s', path, exc)
            raise FUSEError(errno.EACCES)
        return pyfuse3.FileInfo(fh=fd)

    async def read(self, fd, offset, length):
        dec = self._fd2decryptors[fd]
        return b''.join(data for data in dec.read(offset, length)) # inefficient

    async def flush(self, fd):
        LOG.info('flush fd %s', fd)
        try:
            del self._fd2decryptors[fd]
        except KeyError as exc:
            LOG.error('Already closed: %s', exc)
        except Exception as exc:
            LOG.error('Error closing %d: %s', fd, exc)
            raise FUSEError(errno.EBADF)

    async def statfs(self, ctx):
        LOG.info('Getting statfs')
        s = pyfuse3.StatvfsData()
        try:
            statfs = os.statvfs(self.rootdir)
        except OSError as exc:
            raise FUSEError(exc.errno)
        for attr in ('f_bsize', 'f_frsize', 'f_blocks', 'f_bfree', 'f_bavail',
                     'f_files', 'f_ffree', 'f_favail'):
            setattr(s, attr, getattr(statfs, attr))
        s.f_namemax = statfs.f_namemax - (len(self.rootdir)+1)
        return s
