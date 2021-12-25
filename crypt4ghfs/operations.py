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

from .c4gh_files import FileDecryptor, FileEncryptor
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
        'setattr',
        'mknod',
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
                 'keys',
                 'recipients')

    def __init__(self, rootdir, rootfd, seckey, recipients, extension, header_size_hint, assume_same_size_headers,
                 entry_timeout = 300, attr_timeout = 300):

        self.keys = [(0, seckey, None)]
        self.recipients = recipients

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

    def _fd_to_cryptors(self, fd):
        v = self._cryptors.get(fd)
        if v is None:
            LOG.error('Error finding cryptor for %d: %r', fd, exc)
            raise FUSEError(errno.EBADF)
        return v

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

    # async def mkdir(self, inode_p, name, mode, ctx):
    #     LOG.info('mkdir in %d with name %s [mode: %o]', inode_p, name, mode)
    #     # Get the real underlying path
    #     path = os.path.join(self._inode_to_path(inode_p), os.fsdecode(name))
    #     try:
    #         os.mkdir(path, mode=(mode & ~ctx.umask))
    #         #os.chown(path, ctx.uid, ctx.gid) # should already run as uid/gid
    #     except OSError as exc:
    #         raise FUSEError(exc.errno)
    #     return self._getattr(path, no_extension=True)

    # async def rmdir(self, inode_p, name, ctx):
    #     LOG.info('rmdir in %d with name %s', inode_p, name)
    #     # Get the real underlying path
    #     path = os.path.join(self._inode_to_path(inode_p), os.fsdecode(name))
    #     try:
    #         os.rmdir(path)
    #     except OSError as exc:
    #         raise FUSEError(exc.errno)
    #     inode = self._path2inode.pop(path, None)
    #     if inode is None:
    #         raise FUSEError(errno.EINVAL)
    #     del self._inode2path[inode]

    #############################
    ## Files
    #############################

    # In case the lookup succeed
    @capture_oserror
    async def open(self, inode, flags, ctx):

        LOG.info('open with flags %x', flags)
        
        # We don't allow to append or open in RW mode
        if (flags & os.O_RDWR or flags & os.O_APPEND):
            raise pyfuse3.FUSEError(errno.EPERM)

        # If we create the file
        if(flags & os.O_WRONLY):
            # Sanity check: Since we must have one of O_RDWR/O_RDONLY/O_WRONLY
            if flags & os.O_RDONLY:
                raise pyfuse3.FUSEError(errno.EINVAL)
            attrs = self._getattr(path, no_extension=True)
            # We enforce truncation
            fd = await self._create(path, attrs.st_mode, flags | os.O_TRUNC | os.O_CLOEXEC)
            return pyfuse3.FileInfo(fh=fd)

        # we are reading a file
        try:
            dec = FileDecryptor(self.fd(inode), flags, self.keys)
            self._cryptors[dec.fd] = dec
            return pyfuse3.FileInfo(fh=dec.fd)
        except Exception as exc:
            LOG.error('Error opening %s: %s', path, exc)
            raise FUSEError(errno.EACCES)

    async def read(self, fd, offset, length):
        LOG.info('read fd %d | offset %d | %d bytes', fd, offset, length)
        dec = self._cryptors[fd]
        return b''.join(data for data in dec.read(offset, length)) # inefficient


    # In case the lookup fails
    async def create(self, inode_p, name, mode, flags, ctx):
        LOG.info('create in %d with name %s | mode %o | flags %x', inode_p, name, mode, flags)
        name = self.add_extension(os.fsdecode(name))
        path = os.path.join(self._inode_to_path(inode_p), name)
        fd = await self._create(path, mode, flags | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC)
        return (pyfuse3.FileInfo(fh=fd), self._getattr(path))

    async def _create(self, path, mode, flags):
        if not self.recipients:
            LOG.error('Cannot create file for no recipient')
            raise FUSEError(errno.EINVAL) # or errno.ENOSYS ?
        try:
            LOG.debug('internal creating %s', path)
            enc = FileEncryptor(path, mode, flags, self.recipients)
            fd = enc.fd
            self._fd2cryptors[fd] = enc
            return fd
        except OSError as exc:
            LOG.error('OSError creating %s: %s', path, exc)
            raise FUSEError(exc.errno)
        except Exception as exc:
            LOG.error('Error creating %s: %s', path, exc)
            raise FUSEError(errno.EACCES)
        

    async def write(self, fd, offset, data):
        LOG.info('write to %d | offset %d | %d bytes', fd, offset, len(data))
        enc = self.cryptors[fd]
        return enc.write(offset, data)

    # async def flush(self, fd):
    #     LOG.debug('flush %d', fd)
    #     # Since we opened all files with its own fd,
    #     # we only need to close the fd, and not care about lookup count
    #     try:
    #         del self._fd2cryptors[fd]
    #     except KeyError as exc:
    #         LOG.error('Already closed: %s', exc)
    #     except Exception as exc:
    #         LOG.error('Error closing %d: %s', fd, exc)
    #         raise FUSEError(errno.EBADF)

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

    async def rename(self, inode_p_old, name_old, inode_p_new, name_new, flags, ctx):
        LOG.info('rename')
        if flags != 0:
            raise FUSEError(errno.EINVAL)

        path_old = self.add_extension(os.path.join(self._inode_to_path(inode_p_old), os.fsdecode(name_old)))
        path_new = self.add_extension(os.path.join(self._inode_to_path(inode_p_new), os.fsdecode(name_new)))
        LOG.debug('rename path_old: %s', path_old)
        LOG.debug('rename path_new: %s', path_new)
        
        if flags == pyfuse3.RENAME_NOREPLACE and os.path.exists(path_new):
            LOG.error("Cannot overwrite an existing file when flags is RENAME_NOREPLACE")
            raise FUSEError(errno.EPERM)

        try:
            os.rename(path_old, path_new)
            inode = os.lstat(path_new).st_ino
        except OSError as exc:
            raise FUSEError(exc.errno)

        # delete the old path
        old_inode = self._path2inode.pop(path_old, None)
        if old_inode:
            self._inode2path.pop(old_inode, None)
        # add the new path
        self._inode2path[inode] = path_new
        self._path2inode[path_new] = inode


    async def unlink(self, inode_p, name, ctx):
        LOG.info('unlink %s from %s', name, inode_p)
        path = self.add_extension(os.path.join(self._inode_to_path(inode_p), os.fsdecode(name)))
        try:
            os.unlink(path)
        except OSError as exc:
            raise FUSEError(exc.errno)
