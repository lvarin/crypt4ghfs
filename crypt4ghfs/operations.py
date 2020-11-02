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

from .c4gh_files import FileDecryptor, FileEncryptor
from .c4gh_files import flags2str

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
        'symlink',
        'link',
        'setattr',
        'mknod',
   ]

    supports_dot_lookup = True
    enable_writeback_cache = False
    enable_acl = False

    __slots__ = ('_inode2path',
                 '_path2inode',
                 '_fd2cryptors',
                 '_inode2entries',
                 '_inode2mtime',
                 'rootdir',
                 'keys',
                 'cache_directories',
                 'recipients')

    def __init__(self, rootdir, seckey, recipients, extension, cache_directories):

        self.rootdir = rootdir
        self.keys = [(0, seckey, None)]
        self.recipients = recipients

        self._inode2path = { pyfuse3.ROOT_INODE: rootdir }
        self._path2inode = { rootdir: pyfuse3.ROOT_INODE }

        self._fd2cryptors = dict()
        self._inode2mtime = dict()
        self._inode2entries = dict()

        self.extension = extension or ''
        self.extension_len = len(self.extension)
        LOG.info('Extension: %s (%d)', self.extension, self.extension_len)

        self.cache_directories = cache_directories

        super(pyfuse3.Operations, self).__init__()


    def _inode_to_path(self, inode):
        v = self._inode2path.get(inode)
        if v is None:
            raise FUSEError(errno.ENOENT)
        return v

    def _fd_to_cryptors(self, fd):
        v = self._fd2cryptors.get(fd)
        if v is None:
            LOG.error('Error finding cryptor for %d: %r', fd, exc)
            raise FUSEError(errno.EBADF)
        return v

    def strip_extension(self, name):
        if self.extension_len and name.endswith(self.extension):
            return name[:-self.extension_len]
        return name

    def add_extension(self, name):
        if not self.extension_len:
            return name
        if name.endswith(self.extension):
            return name
        return name + self.extension

    async def lookup(self, inode_p, name, ctx=None):
        name = fsdecode(name)
        LOG.info('lookup for %s in %d', name, inode_p)
        path = os.path.join(self._inode_to_path(inode_p), name)
        attrs = self._getattr(path)
        self._inode2path[attrs.st_ino] = path
        return attrs
        
    async def getattr(self, inode, ctx=None):
        LOG.info('getattr inode: %d', inode)
        path = self._inode_to_path(inode)
        return self._getattr(path)

    def _getattr(self, path, no_extension=False):
        LOG.debug('_getattr: path=%s', path)
        try:
            s = os.lstat(path)
        except OSError as exc:
            if no_extension:
                raise FUSEError(errno.ENOENT)
            try:
                path += self.extension
                LOG.debug('_getattr (again): path=%s', path)
                s = os.lstat(path)
            except OSError as exc:
                raise FUSEError(exc.errno)
        return self._stats2entry(s)

    def _stats2entry(self, s):
        entry = pyfuse3.EntryAttributes()
        for attr in ('st_ino', 'st_nlink', 'st_uid', 'st_gid',
                     'st_rdev', 'st_size', 'st_atime_ns', 'st_mtime_ns',
                     'st_ctime_ns'):
            setattr(entry, attr, getattr(s, attr))
        entry.st_mode = s.st_mode & ~stat.S_IRWXO & ~stat.S_IRWXG # remove group and world access
        entry.generation = 0
        entry.entry_timeout = 0
        entry.attr_timeout = 0
        entry.st_blksize = 512
        entry.st_blocks = ((entry.st_size+entry.st_blksize-1) // entry.st_blksize)
        return entry

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
        #s.f_namemax = statfs.f_namemax - (len(self.rootdir)+1)
        return s

    async def fsync(fh, datasync):
        LOG.info('fsync %d | datasync %s', fh, datasync)

    # async def setattr(self, inode, attr, fields, fh, ctx):
    #     # Use f* functions if possible so that we handle setattr()
    #     # call for an inode without associated directory handle.
    #     if fh is None:
    #         handle = self._inode_to_path(inode)
    #         truncate = os.truncate
    #         chmod = os.chmod
    #         chown = os.chown
    #         stat = os.lstat
    #     else:
    #         handle = fh
    #         truncate = os.ftruncate
    #         chmod = os.fchmod
    #         chown = os.fchown
    #         stat = os.fstat

    #############################
    ## Directories
    #############################

    async def _scandir(self, path):
        LOG.debug('Fetching entries for %s', path)
        entries = []
        with os.scandir(path) as it: # read entirely. TODO: check if we can read it sorted.
            for entry in it:
                ino = entry.inode()
                s = entry.stat()
                display_name = entry.name if stat.S_ISDIR(s.st_mode) else self.strip_extension(entry.name)
                entry_path = os.path.join(path, display_name)
                self._inode2path[ino] = entry_path
                entries.append((ino, display_name, s))
        return sorted(entries, key=lambda x: x[0])

    async def opendir(self, inode, ctx):
        path = self._inode_to_path(inode)
        LOG.info('opening %s | Context (%d): %s', path, id(ctx), ctx)
        if self.cache_directories:
            mtime = self._inode2mtime.get(inode)
            entry = self._getattr(path, no_extension=True)
            # cache up to date
            if mtime and mtime == entry.st_mtime_ns:
                LOG.debug('cache uptodate, not modified since %s', mtime)
                return inode

        LOG.debug('Fetching entries for %s', path)
        if self.cache_directories:
            self._inode2mtime[inode] = entry.st_mtime_ns
        self._inode2entries[inode] = await self._scandir(path)
        return inode

    async def readdir(self, inode, off, token):
        if not off:
            off = -1

        path = self._inode_to_path(inode)
        LOG.info('readdir %s [inode %s]', path, inode)
        LOG.debug('\toffset %s', off)
        entries = self._inode2entries[inode]
        LOG.info('read %d entries, starting at %d', len(entries), off)

        # Sort them for the offset
        for (ino, name, entry) in entries:
            if ino <= off:
                continue
            attrs = self._stats2entry(entry)
            pyfuse3.readdir_reply(token, fsencode(name), attrs, ino)
            # ignore result?.... or if not: break?

        return False # over

    async def releasedir(self, inode):
        LOG.info('release directory %s', inode)
        if self.cache_directories:
            self._inode2entries.pop(inode, None)
            self._inode2mtime.pop(inode, None)

    async def mkdir(self, inode_p, name, mode, ctx):
        LOG.info('mkdir in %d with name %s [mode: %o]', inode_p, name, mode)
        # Get the real underlying path
        path = os.path.join(self._inode_to_path(inode_p), fsdecode(name))
        try:
            os.mkdir(path, mode=(mode & ~ctx.umask))
            #os.chown(path, ctx.uid, ctx.gid) # should already run as uid/gid
        except OSError as exc:
            raise FUSEError(exc.errno)
        return self._getattr(path, no_extension=True)

    async def rmdir(self, inode_p, name, ctx):
        LOG.info('rmdir in %d with name %s', inode_p, name)
        # Get the real underlying path
        path = os.path.join(self._inode_to_path(inode_p), fsdecode(name))
        try:
            os.rmdir(path)
        except OSError as exc:
            raise FUSEError(exc.errno)
        inode = self._path2inode.pop(path, None)
        if inode is None:
            raise FUSEError(errno.EINVAL)
        del self._inode2path[inode]

    #############################
    ## Files
    #############################

    # In case the lookup succeed
    async def open(self, inode, flags, ctx):

        LOG.info('open with flags %s', flags2str(flags))
        
        # We don't allow to append or open in RW mode
        if (flags & os.O_RDWR or flags & os.O_APPEND):
            raise pyfuse3.FUSEError(errno.EPERM)

        # Get the underlying path
        path = self.add_extension(self._inode_to_path(inode))

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
            dec = FileDecryptor(path, flags, self.keys)
            fd = dec.fd
            self._fd2cryptors[fd] = dec
            LOG.debug('added fd %d to map', fd)
        except OSError as exc:
            LOG.error('OSError opening %s: %s', path, exc)
            raise FUSEError(exc.errno)
        except Exception as exc:
            LOG.error('Error opening %s: %s', path, exc)
            raise FUSEError(errno.EACCES)
        return pyfuse3.FileInfo(fh=fd)

    async def read(self, fd, offset, length):
        LOG.info('read fd %d | offset %d | %d bytes', fd, offset, length)
        dec = self._fd_to_cryptors(fd)
        return b''.join(data for data in dec.read(offset, length)) # inefficient


    # In case the lookup fails
    async def create(self, inode_p, name, mode, flags, ctx):
        LOG.info('create in %d with name %s | mode %o | flags (%d): %s', inode_p, name, mode, flags, flags2str(flags))
        name = self.add_extension(fsdecode(name))
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
        

    async def write(self, fd, offset, buf):
        LOG.info('write to %d | offset %d | %d bytes', fd, offset, len(buf))
        enc = self._fd_to_cryptors(fd)
        return enc.write(offset, buf)

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
            del self._fd2cryptors[fd]
        except KeyError as exc:
            LOG.error('Already closed: %s', exc)
        except Exception as exc:
            LOG.error('Error closing %d: %s', fd, exc)
            raise FUSEError(errno.EBADF)

    async def rename(self, inode_p_old, name_old, inode_p_new, name_new, flags, ctx):
        LOG.info('rename')
        if flags != 0:
            raise FUSEError(errno.EINVAL)

        path_old = self.add_extension(os.path.join(self._inode_to_path(inode_p_old), fsdecode(name_old)))
        path_new = self.add_extension(os.path.join(self._inode_to_path(inode_p_new), fsdecode(name_new)))
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
        path = self.add_extension(os.path.join(self._inode_to_path(inode_p), fsdecode(name)))
        try:
            os.unlink(path)
        except OSError as exc:
            raise FUSEError(exc.errno)
 
