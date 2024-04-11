# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

from contextlib import contextmanager
from fcntl import LOCK_EX, LOCK_NB, LOCK_SH, LOCK_UN, flock
from time import sleep, time
from typing import IO, BinaryIO, Generator, TextIO

from opsicommon.logging import get_logger

LD_LIBRARY_EXCLUDE_LIST = ["/usr/lib/opsiclientd"]

logger = get_logger()


@contextmanager
def lock_file(file: TextIO | BinaryIO | IO, exclusive: bool = False, timeout: float = 5.0) -> Generator[None, None, None]:
	"""
	An exclusive or write lock gives a process exclusive access for writing to the specified part of the file.
	While a write lock is in place, no other process can lock that part of the file.
	A shared or read lock prohibits any other process from requesting a write lock on the file.
	"""
	lock_flags = LOCK_NB | (LOCK_EX if exclusive else LOCK_SH)
	start = time()
	while True:
		try:
			flock(file, lock_flags)
			break
		except (IOError, BlockingIOError):
			if time() >= start + timeout:
				raise TimeoutError(f"Failed to lock file after {timeout:0.2f} seconds") from None
			sleep(0.1)
	try:
		yield
	finally:
		flock(file, LOCK_UN)
