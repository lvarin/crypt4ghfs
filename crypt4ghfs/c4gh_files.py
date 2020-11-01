import io
import os
import logging

from crypt4gh import header as crypt4gh_header
from crypt4gh.lib import (SEGMENT_SIZE,
                          CIPHER_SEGMENT_SIZE,
                          CIPHER_DIFF,
                          decrypt_block,
                          _encrypt_segment)
LOG = logging.getLogger(__name__)

class FileDecryptor():

    __slots__ = ('f',
                 'fd',
                 'session_keys',
                 'hlen',
                 'start_ciphersegment',
                 'ciphersegment',
                 'segment')

    def __init__(self, path, flags, keys):
        # New fd everytime we open, cuz of the segment
        self.fd = os.open(path,flags)
        self.f = os.fdopen(self.fd,
                           mode='rb',
                           buffering=0) # off
        # Parse header (yes, for each fd, small cost for caching segment)
        self.session_keys, edit_list = crypt4gh_header.deconstruct(self.f, keys, sender_pubkey=None)

        # First version: we do not support edit lists
        if edit_list:
            raise ValueError('Edit list are not supported')

        self.hlen = self.f.tell()
        LOG.info('Payload position: %d', self.hlen)

        # Crypt4GH decryption buffer
        self.start_ciphersegment = None
        self.ciphersegment = None
        self.segment = None
    
    def __del__(self):
        LOG.debug('Deleting the FileDecryptor')
        self.close()

    def close(self):
        return os.close(self.fd)

    def read(self, offset, length):
        LOG.debug('Read offset: %s, length: %s', offset, length)
        assert length > 0, "You can't read just 0 bytes"
        while length > 0:
            # Find which segment we are reaching into
            start_segment, off = divmod(offset, SEGMENT_SIZE)
            start_ciphersegment = start_segment * CIPHER_SEGMENT_SIZE
            LOG.debug('Current position: %d | Fast-forwarding %d segments', start_ciphersegment, start_segment)
            if self.start_ciphersegment != start_ciphersegment:
                LOG.debug('We do not have that segment cached')
                self.start_ciphersegment = start_ciphersegment
                pos = self.start_ciphersegment + self.hlen
                # Move to its start
                self.f.seek(pos, io.SEEK_SET)  # move forward
                # Read it
                LOG.debug('Reading ciphersegment at %d', pos)
                self.ciphersegment = self.f.read(CIPHER_SEGMENT_SIZE)
                ciphersegment_len = len(self.ciphersegment)
                if ciphersegment_len == 0:
                    break # We were at the last segment. Exits the loop
                assert( ciphersegment_len > CIPHER_DIFF )
                LOG.debug('Decrypting ciphersegment [%d bytes]', ciphersegment_len)
                self.segment = decrypt_block(self.ciphersegment, self.session_keys)

            data = self.segment[off:off+length] # smooth slicing
            yield data
            datalen = len(data)
            if datalen == 0:
                break
            length -= datalen
            offset += datalen


FLAGS=[s for s in dir(os) if s.startswith('O_')]

def flags2str(flags):
    s = []
    flags2 = flags & 0
    for f in FLAGS:
        flag = getattr(os, f)
        if flags & flag == flag:
            s.append(f)
            flags2 |= flag
    if flags2 != flags:
        LOG.debug('  original flags: %s', bin(flags))
        LOG.debug('recognized flags: %s', bin(flags2))
        LOG.debug('            diff: %s', bin(flags & ~flags2))
        s.append(' + unknown')
    return ','.join(s)

class FileEncryptor():

    __slots__ = ('fd',
                 'already_encrypted',
                 'session_key',
                 'hlen',
                 'slen',
                 'left',
                 'old_offset',
                 'segment')

    def __init__(self, path, mode, flags, recipients):

        self.already_encrypted = None
        # If Windows...
        if os.name == 'nt':
            flags |= os.O_BINARY

        # Open the file
        LOG.info('Creating %s with flags (%d) %s [mode %o]',path, flags, flags2str(flags), mode)
        self.fd = os.open(path, flags, mode=mode)

        # Make the header
        encryption_method = 0 # only choice for this version
        self.session_key = os.urandom(32) # we use one session key for all blocks
        LOG.debug('Creating Crypt4GH header for %d recipients', len(recipients))
        header_content = crypt4gh_header.make_packet_data_enc(encryption_method, self.session_key)
        header_packets = crypt4gh_header.encrypt(header_content, recipients)
        header_bytes = crypt4gh_header.serialize(header_packets)
        hlen = len(header_bytes)
        LOG.debug('header length: %d', hlen)
        # Write it to disk
        self.hlen = os.write(self.fd, header_bytes)
        assert hlen == self.hlen, "Could not write the whole header"
        self.old_offset = 0
        # Crypt4GH encryption buffer
        self.segment = bytearray(SEGMENT_SIZE)
        self.reset_segment()

    def __del__(self):
        LOG.debug('Deleting the FileEncryptor')
        self.close()
        del self.segment


    def write(self, offset, buf):

        if not buf:
            LOG.debug("Eh? no bytes? not doing anything...")
            return 0

        length = len(buf)
        LOG.debug('Write offset: %s, length: %s', offset, length)

        # check if already encrypted
        # That's a weak solution, but should be fine in most cases
        if self.already_encrypted is None and offset == 0 and length >= 8:
            self.already_encrypted = (buf[:8] == crypt4gh_header.MAGIC_NUMBER)
            
        if self.already_encrypted:
            LOG.warning('Data already encrypted')
            os.lseek(self.fd, offset)
            return os.write(self.fd, buf)
            
        if offset != self.old_offset:
            LOG.error('Non-contiguous writes are not supported')
            raise OSError(errno.EINVAL, 'Invalid offset: Non-contiguous writes are not supported')

        while True:
            buf = self.push(buf)
            if not buf: # None or b''
                break

        # Update the offset
        self.old_offset = offset + length
        return length

    def reset_segment(self):
        self.slen = 0
        self.left = SEGMENT_SIZE

    def flush(self):
        """Encrypt and write the current segment"""
        LOG.debug("Flushing segment | buf pos %d | left %d", self.slen, self.left)
        if self.slen == 0:
            return
        if self.slen < SEGMENT_SIZE:
            data = bytes(self.segment[:self.slen]) # slicing
        else:
            data = bytes(self.segment)
        _encrypt_segment(data, lambda d: os.write(self.fd, d), self.session_key)
        self.reset_segment()

    def close(self):
        if not self.already_encrypted:
            self.flush() # in case we still have bytes in the buffer
        return os.close(self.fd)

    def push(self, data):
        data_len = len(data)
        LOG.debug("Pushing %d bytes", data_len)
        assert data_len > 0

        # Adding enough bytes to the segment
        written = min(data_len, self.left)
        LOG.debug("Adding %d bytes to the segment", written)
        assert self.slen+written <= SEGMENT_SIZE
        self.segment[self.slen:self.slen+written] = data

        # Discount them
        self.left -= written
        self.slen += written

        # Should we flush it now?
        if self.left == 0:
            self.flush() # that resets the counters
            return None # No more data to add

        # Return the data that are left to write
        return data[self.left:]

