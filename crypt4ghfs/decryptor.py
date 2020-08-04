import io
import os
import logging

import crypt4gh
from crypt4gh.lib import (SEGMENT_SIZE,
                          CIPHER_SEGMENT_SIZE,
                          CIPHER_DIFF,
                          decrypt_block)
LOG = logging.getLogger(__name__)

class FileDecryptor():

    __slots__ = ('f',
                 'session_keys',
                 'edit_list',
                 'hlen',
                 'pos',
                 'ciphersegment',
                 'segment')

    def __init__(self, path, flags, keys):
        # Parse header (yes, for each fd, small cost for caching segment)
        def opener(p,fl):
            LOG.info('Opening %s',p)
            return os.open(p,fl)
        self.f = open(path,
                      mode='rb',
                      buffering=0, # off
                      opener=opener) # new file descriptor each time we open
        # self.f.seek(0, io.SEEK_SET)  # rewind, just to be sure
        self.session_keys, self.edit_list = crypt4gh.header.deconstruct(self.f, keys, sender_pubkey=None)
        self.hlen = self.f.tell()
        LOG.info('Payload position: %d', self.hlen)

        # First version: we do not support edit lists
        if self.edit_list:
            raise ValueError('Edit list are not supported for this version')

        # Crypt4GH decryption buffer
        self.pos = None
        self.ciphersegment = None # TODO: use the same buffer instead of reallocating bytes
        self.segment = None

    def fd(self):
        return self.f.fileno()

    def __del__(self):
        LOG.debug('Deleting the FileDecryptor')
        # self.ciphersegment = None
        # self.segment = None
        # self.pos = None
        self.f.close()

    def read(self, offset, length):
        LOG.debug('Read offset: %s, length: %s', offset, length)
        assert length > 0, "You can't read just 0 bytes"
        while length > 0:
            # Find which segment we are reaching into
            start_segment, off = divmod(offset, SEGMENT_SIZE)
            # Move to its start
            LOG.debug('Current position: %s | Fast-forwarding %d segments', self.pos, start_segment)
            start_ciphersegment = start_segment * CIPHER_SEGMENT_SIZE
            if self.pos != start_ciphersegment:
                LOG.debug('We do not have that segment cached')
                self.pos = start_ciphersegment
                self.f.seek(self.pos + self.hlen, io.SEEK_SET)  # move forward
                # Read it
                LOG.debug('Reading ciphersegment [%d-%d]', self.pos + self.hlen, self.pos + self.hlen + CIPHER_SEGMENT_SIZE)
                self.ciphersegment = self.f.read(CIPHER_SEGMENT_SIZE)
                ciphersegment_len = len(self.ciphersegment)
                if ciphersegment_len == 0:
                    break # We were at the last segment. Exits the loop
                assert( ciphersegment_len > CIPHER_DIFF )
                LOG.debug('Decrypting ciphersegment [%d bytes]', ciphersegment_len)
                self.segment = decrypt_block(self.ciphersegment, self.session_keys)

            data = self.segment[off:off+length] # smooth slicing
            yield data
            length -= len(data)
            offset += SEGMENT_SIZE
