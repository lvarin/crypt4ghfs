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

    def __init__(self, fd, keys):
        # Parse header (yes, for each fd, small cost for caching segment)
        self.f = os.fdopen(fd)
        self.f.seek(0, io.SEEK_SET)  # rewind, just to be sure
        self.session_keys, self.edit_list = crypt4gh.header.deconstruct(self.f, keys, sender_pubkey=None)
        self.hlen = self.f.tell()

        # First version: we do not support edit lists
        if self.edit_list:
            raise ValueError('Edit list are not supported for this version')

        # Crypt4GH decryption buffer
        self.pos = 0
        self.ciphersegment = None # TODO: use the same buffer instead of reallocating bytes
        self.segment = None

    def seek(self, start, end):
        pass

    def decrypt(self, n):

        crypt4gh.lib.CIPHER_SEGMENT_SIZE
        crypt4gh.lib.decrypt_block(ciphersegment, self.session_keys)

    def __del__(self):
        del self.ciphersegment
        del self.segment
        self.f.close()

    def read(self, offset, length):
        assert length > 0, "You can't read just 0 bytes"
        while length > 0:
            # Find which segment we are reaching into
            start_segment, off = divmod(offset, SEGMENT_SIZE)
            # Move to its start
            LOG.debug('Fast-forwarding %d segments', start_segment)
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
