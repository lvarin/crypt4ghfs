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
                 'session_keys',
                 'hlen',
                 'start_ciphersegment',
                 'ciphersegment',
                 'segment')

    def __init__(self, fd, flags, keys):
        # New fd everytime we open, cuz of the segment
        self.f = os.fdopen(fd, mode='rb', closefd=True, buffering=0) # off
        # Parse header (yes, for each fd, small cost for caching segment)
        self.session_keys, edit_list = crypt4gh_header.deconstruct(self.f, keys, sender_pubkey=None)

        # First version: we do not support edit lists
        if edit_list:
            raise ValueError('Edit list are not supported')

        self.hlen = self.f.tell()
        LOG.info('Payload position: %d', self.hlen)
        LOG.info('Found %d session keys', len(self.session_keys))

        # Crypt4GH decryption buffer
        self.start_ciphersegment = None
        self.ciphersegment = None
        self.segment = None
    
    def __del__(self):
        LOG.debug('Deleting the FileDecryptor | closing %d', self.f.fileno())
        self.f.close()

    def read(self, offset, length):
        LOG.debug('Read offset: %s, length: %s', offset, length)
        assert length > 0, "You can't read just 0 bytes"
        while length > 0:
            # Find which segment we are reaching into
            start_segment, off = divmod(offset, SEGMENT_SIZE)
            start_ciphersegment = start_segment * CIPHER_SEGMENT_SIZE + self.hlen
            LOG.debug('Current position: %d | Fast-forwarding %d segments', start_ciphersegment, start_segment)
            if self.start_ciphersegment != start_ciphersegment:
                LOG.debug('We do not have that segment cached')
                self.start_ciphersegment = start_ciphersegment
                # Move to its start
                pos = self.f.seek(start_ciphersegment, io.SEEK_SET)  # move forward
                # Read it
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
