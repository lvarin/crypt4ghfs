#!/usr/bin/env python3

# -*- coding: utf-8 -*-
# __init__ is here so that we don't collapse in sys.path with another module

"""The pipeline package contains code to start an *Ingestion pipeline*."""

__title__ = 'Crypt4GH Filesystem'
__version__ = '1.1'
__author__ = 'Frédéric Haziza'
__license__ = 'Apache 2.0'
__copyright__ = 'Crypt4ghFS @ CRG, Barcelona'

import sys
if sys.version_info < (3, 6):
    print("crypt4ghfs requires python3.6", file=sys.stderr)
    sys.exit(1)

# Send warnings using the package warnings to the logging system
# The warnings are logged to a logger named 'py.warnings' with a severity of WARNING.
# See: https://docs.python.org/3/library/logging.html#integration-with-the-warnings-module
import logging
import warnings
logging.captureWarnings(True)
warnings.simplefilter("default")  # do not ignore Deprecation Warnings
