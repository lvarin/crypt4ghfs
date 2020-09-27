'''
PEP 3143

https://www.python.org/dev/peps/pep-3143/#correct-daemon-behaviour

https://daemonize.readthedocs.io/en/latest/_modules/daemonize.html#Daemonize

'''

import sys
import os
import time
import atexit
import signal
import logging

LOG = logging.getLogger(__name__)

class Daemon:
    """A generic daemon class.

    Usage: subclass the daemon class and override the run() method.
    """

    def __init__(self, pidfile):
        self.pidfile = pidfile

    def daemonize(self):
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
        os.umask(0)

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

        # remove pidfile when exiting
        LOG.info('remove pidfile when exiting')
        atexit.register(self.delpid)

        LOG.info('Writing the pid into %s', self.pidfile)
        pid = str(os.getpid())
        with open(self.pidfile,'w+') as f:
            f.write(pid + '\n')

    def delpid(self):
        os.remove(self.pidfile)

    def start(self):
        """Start the daemon."""

        # Check for a pidfile to see if the daemon already runs
        try:
            with open(self.pidfile,'r') as pf:
                pid = int(pf.read().strip())
        except IOError:
            pid = None

        if pid:
            print(f"pidfile {self.pidfile} already exist. Daemon already running?", file=sys.stderr)
            sys.exit(1)

        # Start the daemon
        self.daemonize()
        self.run()

    def stop(self):
        """Stop the daemon."""

        # Get the pid from the pidfile
        try:
            with open(self.pidfile,'r') as pf:
                pid = int(pf.read().strip())
        except IOError:
            pid = None

        if not pid:
            print(f"pidfile {self.pidfile} does not exist. Daemon not running?", file=sys.stderr)
            return # not an error in a restart

        # Try killing the daemon process
        try:
            while 1: # max kill retries ?
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.1)
        except OSError as err:
            e = str(err.args)
            if e.find("No such process") > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                print(str(err.args), file=sys.stderr)
                sys.exit(1)

    def restart(self):
        """Restart the daemon."""
        self.stop()
        self.start()

    def run(self):
        """You should override this method when you subclass Daemon.

        It will be called after the process has been daemonized by 
        start() or restart()."""
