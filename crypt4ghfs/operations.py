"""
Crypt4GH file system
"""
import os
import sys
from argparse import ArgumentParser
import errno
import logging
import stat
from functools import partial

import pyfuse3
from pyfuse3 import FUSEError
from crypt4gh import VERSION
from crypt4gh.lib import SEGMENT_SIZE, CIPHER_SEGMENT_SIZE, CIPHER_DIFF
from crypt4gh.header import MAGIC_NUMBER

from .c4gh_files import FileDecryptor
from .entry import Entry

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

def capture_oserror(func):
    async def decorator(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except OSError as exc:
            raise FUSEError(exc.errno)
    return decorator



class Crypt4ghFS(pyfuse3.Operations, metaclass=NotPermittedMetaclass):

    _not_permitted = [
        'readlink'
        'unlink',
        'symlink',
        'link',
        'mknod',
        'setattr',
        'mkdir',
        'rmdir',
        'create',
        'rename',
        'write'
   ]

    supports_dot_lookup = True
    enable_writeback_cache = False
    enable_acl = False

    __slots__ = ('_inodes',
                 '_entries',
                 '_cryptors',
                 'extension',
                 'header_size_hint',
                 'assume_same_size_headers',
                 'keys')

    def __init__(self, rootdir, rootfd, seckey,
                 extension, header_size_hint, assume_same_size_headers,
                 entry_timeout = 300, attr_timeout = 300):

        self.keys = [(0, seckey, None)]

        LOG.info('rootfd: %s', rootfd)
        s = os.stat(".", dir_fd=rootfd, follow_symlinks=False)
        LOG.info('stat: %s', s)

        self._cryptors = dict()
        self._entries = dict()

        root_entry = Entry(rootfd, rootdir, s)
        root_entry.entry.st_ino = pyfuse3.ROOT_INODE
        root_entry.refcount += 1
        self._inodes = { pyfuse3.ROOT_INODE: root_entry }
        LOG.info('inodes: %s', self._inodes)

        self.extension = extension or ''
        LOG.info('Extension: %s', self.extension)
        self.header_size_hint = header_size_hint or None
        LOG.info('Header size hint: %s', self.header_size_hint)
        self.assume_same_size_headers = assume_same_size_headers

        super(pyfuse3.Operations, self).__init__()

    def fd(self, inode):
        try:
            return self._inodes[inode].fd
        except Exception as e:
            LOG.error('fd error: %s', e)
            raise FUSEError(errno.ENOENT)

    def _do_lookup(self, inode_p, name, s=None):
        #LOG.debug('do lookup %d/%s', inode_p, name)
        parent_fd = self.fd(inode_p)
        if s is None:
            s = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        n = self._inodes.get(s.st_ino)
        if n:
            return n

        n = Entry(parent_fd, name, s,
                  extension=self.extension,
                  header_size_hint=self.header_size_hint,
                  assume_same_size_headers=self.assume_same_size_headers)
        LOG.debug('creating entry(%d) %s', s.st_ino, n)
        self._inodes[s.st_ino] = n
        return n

    @capture_oserror
    async def lookup(self, inode_p, name, ctx=None):
        name = os.fsdecode(name)
        LOG.info('lookup for [%d]/%s', inode_p, name)
        try:
            return self._do_lookup(inode_p, name).entry
        except OSError as e:
            if not self.extension:
                raise e
            name += self.extension
            LOG.info('lookup (again) for [%d]/%s', inode_p, name)
            return self._do_lookup(inode_p, name).entry
        
    @capture_oserror
    async def getattr(self, inode, ctx=None):
        LOG.info('getattr inode: %d', inode)
        return self._inodes[inode].entry

    @capture_oserror
    async def statfs(self, ctx):
        LOG.info('Getting statfs')
        s = pyfuse3.StatvfsData()
        statfs = os.statvfs("", dir_fd=self.rootfd)
        for attr in ('f_bsize', 'f_frsize', 'f_blocks', 'f_bfree', 'f_bavail',
                     'f_files', 'f_ffree', 'f_favail'):
            setattr(s, attr, getattr(statfs, attr))
        return s

    async def forget(self, inode_list):
        for inode, nlookup in inode_list:
            LOG.info('Forget %d (by %d)', inode, nlookup)
            v = self._inodes[inode]
            v.refcount -= nlookup
            assert( v.refcount >= 0)
            if v.refcount == 0:
                LOG.debug('Deleting inode %d: %s', inode, v)
                if v.fd > 0:
                    os.close(v.fd)
                del self._inodes[inode]

    #############################
    ## Directories
    #############################

    def _scandir(self, parent_inode, parent_fd):
        #LOG.debug('Fetching entries for inode %d', parent_inode)
        with os.scandir(parent_fd) as it: # oh lord, read entirely!
            for entry in it:
                s = entry.stat()
                #LOG.debug('entry path %s | ino %d', entry.path, s.st_ino)
                yield self._do_lookup(parent_inode, entry.name, s=s)

    @capture_oserror
    async def opendir(self, inode, ctx):
        LOG.info('opendir inode %d', inode)
        fd = os.open(".", os.O_RDONLY, dir_fd=self.fd(inode))
        entries = sorted(self._scandir(inode, fd), key=lambda n: n.entry.st_ino)
        #LOG.debug('opendir entries: %s', entries)
        self._entries[inode] = entries
        os.close(fd)
        return inode

    async def readdir(self, inode, off, token):
        if not off:
            off = -1
        LOG.info('readdir inode %d | offset %s', inode, off)
        for n in self._entries[inode]:
            ino = n.entry.st_ino
            if ino < off:
                continue
            if not pyfuse3.readdir_reply(token, n.encoded_name(), n.entry, ino+1):
                break
        else:
            return False # over

    async def releasedir(self, inode):
        LOG.info('releasedir inode %d', inode)
        self._entries.pop(inode, None)

    @capture_oserror
    async def mkdir(self, inode_p, name, mode, ctx):
        LOG.info('mkdir in %d with name %s [mode: %o]', inode_p, name, mode)
        os.mkdir(os.fsdecode(name), mode=(mode & ~ctx.umask), dir_fd=self.fd(inode_p))
        return await self.lookup(inode_p, name, ctx=ctx)

    @capture_oserror
    async def rmdir(self, inode_p, name, ctx):
        LOG.info('rmdir in %d with name %s', inode_p, name)
        s = os.stat(name, dir_fd=self.fd(inode_p), follow_symlinks=False)
        os.rmdir(os.fsdecode(name), dir_fd=self.fd(inode_p))
        self._inodes.pop(s.st_ino, None)

    #############################
    ## Files
    #############################

    # In case the lookup succeed
    @capture_oserror
    async def open(self, inode, flags, ctx):

        LOG.info('open with flags %x', flags)
        
        # We don't allow to append or open in RW mode
        if (flags & os.O_RDWR or flags & os.O_APPEND):
            LOG.error('read-write or append is not supported')
            raise pyfuse3.FUSEError(errno.EPERM)

        try:
            path = f"/proc/self/fd/{self.fd(inode)}"
            flags &= ~os.O_NOFOLLOW
            fd = os.open(path, flags)
            dec = FileDecryptor(fd, flags, self.keys)
            self._cryptors[fd] = dec
            return pyfuse3.FileInfo(fh=fd)
        except Exception as exc:
            LOG.error('Error opening %s: %s', path, exc)
            raise FUSEError(errno.EACCES)

    async def read(self, fd, offset, length):
        LOG.info('read fd %d | offset %d | %d bytes', fd, offset, length)
        dec = self._cryptors[fd]
        return b''.join(data for data in dec.read(offset, length)) # inefficient

    async def release(self, fd):
        LOG.info('release fd %s', fd)
        # Since we opened all files with its own fd,
        # we only need to close the fd, and not care about lookup count
        try:
            del self._cryptors[fd]
        except KeyError as exc:
            LOG.error('Already closed: %s', exc)
        except Exception as exc:
            LOG.error('Error closing %d: %s', fd, exc)
            raise FUSEError(errno.EBADF)
