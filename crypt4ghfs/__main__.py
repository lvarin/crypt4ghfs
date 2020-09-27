#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import logging
from logging.config import dictConfig
import argparse
from functools import partial
from getpass import getpass
from pathlib import Path

import pyfuse3
import trio
from crypt4gh.keys import get_private_key

from .operations import Crypt4ghFS

try:
    import faulthandler
    # See https://docs.python.org/3.8/library/faulthandler.html
except ImportError:
    pass
else:
    faulthandler.enable()

LOG = logging.getLogger(__name__)


def load_logger(level):
    dictConfig({'version': 1,
                'root': {'level': 'NOTSET',
                         'handlers': ['noHandler'] },
                'loggers': {
                    'crypt4ghfs': {'level': level,
                                   'handlers': ['console'],
                                   'propagate': True },
                    'asyncio': { 'level': 'DEBUG',
                              'handlers': ['console'] },
                },
                'handlers': { 'noHandler': { 'class': 'logging.NullHandler',
                                             'level': 'NOTSET' },
                              'console': { 'class': 'logging.StreamHandler',
                                           'formatter': 'simple' if level == 'DEBUG' else 'short',
                                           'stream': 'ext://sys.stderr'}
                },
                'formatters': {
                    'simple': {'format': '[{name:^10}][{levelname:^6}] (L{lineno}) {message}',
                               'style': '{' },
                    'short': {'format': '[{levelname:^6}] {message}',
                              'style': '{' },
                }
    })

def retrieve_secret_key(seckey):
    seckeypath = os.path.expanduser(seckey)
    LOG.info('Loading secret key from %s', seckeypath)
    if not os.path.exists(seckeypath):
        raise ValueError('Secret key not found')

    passphrase = os.getenv('C4GH_PASSPHRASE')
    if passphrase:
        #LOG.warning("Using a passphrase in an environment variable is insecure")
        print("Warning: Using a passphrase in an environment variable is insecure", file=sys.stderr)
        cb = lambda : passphrase
    else:
        cb = partial(getpass, prompt=f'Passphrase for {seckey}: ')

    return get_private_key(seckeypath, cb)
    
def parse_options():
    parser = argparse.ArgumentParser(description='Crypt4GH filesystem')
    parser.add_argument('mountpoint', help='mountpoint for the Crypt4GH filesystem')
    parser.add_argument('-o', metavar='options',
                        help='comma-separated list of mount options',
                        default='ro,allow_root,default_permissions,seckey=~/.c4gh/sec.key')

    args = parser.parse_args()

    # Defaults
    rootdir = None
    debug_level = 'CRITICAL'

    # Parse options
    options = args.o.split(',')
    fuse_options = []
    seckey = None
    foreground = False
    for option in options:
        LOG.debug('Inspecting option: %s', option)
        if option == 'debug_fuse':
            fuse_options.append('debug')
        elif option.startswith('debug'):
            # Logging
            try:
                _, debug_level = option.split('=')
                load_logger(debug_level)
            except:
                pass
        elif option.startswith('rootdir='):
            rootdir = os.path.expanduser(option[8:])
            if not os.path.exists(rootdir):
                raise ValueError(f'Root directory "{rootdir}" does not exist')
        elif option.startswith('seckey='):
            seckeypath = option[7:]
        elif option == 'foreground':
            foreground = True
        else:
            fuse_options.append(option)

    # Load the secret key
    if not seckeypath:
        raise ValueError('Missing secret key')
    seckey = retrieve_secret_key(seckeypath)

    return args.mountpoint, rootdir, seckey, fuse_options, foreground


def _main(mountpoint, rootdir, seckey, options):

    fs = Crypt4ghFS(rootdir, seckey)
    pyfuse3.init(fs, mountpoint, options)

    try:
        LOG.debug('Entering main loop')
        trio.run(pyfuse3.main)
        # This is an infinite loop.
        # Ctrl-C / KeyboardInterrupt will be propagated (properly?)
        # - https://trio.readthedocs.io/en/stable/reference-core.html
        # - https://vorpus.org/blog/control-c-handling-in-python-and-trio/
    except Exception as e:
        LOG.debug("%r", e)
        raise
    finally:
        pyfuse3.close(unmount=True)

    LOG.debug('Unmounting')
    pyfuse3.close()
    # The proper way to exit is to call:
    # umount <the-mountpoint>
    return 0

def detach(umask=0):
    '''PEP 3143

    https://www.python.org/dev/peps/pep-3143/#correct-daemon-behaviour
    https://daemonize.readthedocs.io/en/latest/_modules/daemonize.html#Daemonize
    '''
    try:
        LOG.info('Forking current process, and exiting the parent')
        pid = os.fork()
        if pid > 0:  # make the parent exist
            sys.exit(0)
    except OSError as err:
        print('fork failed:', err, file=sys.stderr)
        sys.exit(1)

    # decouple from parent environment
    LOG.info('decouple from parent environment')
    os.chdir('/')
    os.setsid()
    os.umask(umask)

    # redirect standard file descriptors
    LOG.info('redirect standard file descriptors')
    sys.stdout.flush()
    sys.stderr.flush()
    si = open(os.devnull, 'r')
    so = open(os.devnull, 'a+')
    se = open(os.devnull, 'a+')
    
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())

def main():
    mountpoint, rootdir, seckey, options, foreground = parse_options()

    LOG.debug('Mountpoint: %s | Root dir: %s', mountpoint, rootdir)
    LOG.debug('mount options: %s', options)

    # ....aaand cue music!
    if not foreground:
        detach() # daemonize
    sys.exit(_main(mountpoint, rootdir, seckey, options))

if __name__ == '__main__':
    main()
