# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
Helpers for testing opsi.
"""

import io
import os
from contextlib import contextmanager

from opsicommon.logging import logging_config


@contextmanager
def log_stream(new_level, format=None):  # pylint: disable=redefined-builtin
	stream = io.StringIO()
	logging_config(stderr_level=new_level, stderr_format=format, stderr_file=stream)
	try:
		yield stream
	finally:
		# somehow revert to previous values? Impossible as logging_config deletes all stream handlers
		pass


@contextmanager
def environment(**env_vars):
	env_bak = os.environ.copy()
	try:
		os.environ.clear()
		os.environ.update(env_vars)
		yield
	finally:
		os.environ = env_bak
