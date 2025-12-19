# opsicommon is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2025 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0-only

"""
This file is part of opsi - https://www.opsi.org
"""

from contextlib import contextmanager
from fcntl import LOCK_EX, LOCK_NB, LOCK_SH, LOCK_UN, flock, lockf
from time import monotonic, sleep, time
from typing import IO, BinaryIO, Generator, Literal, TextIO

from opsicommon.logging import get_logger

LD_LIBRARY_EXCLUDE_LIST = ["/usr/lib/opsiclientd"]

logger = get_logger()


@contextmanager
def lock_file(
	file: TextIO | BinaryIO | IO, exclusive: bool = False, timeout: float = 5.0, lock_method: Literal["flock", "lockf"] | None = None
) -> Generator[None, None, None]:
	"""
	Lock a file using either flock or lockf.
	:param file: The file to lock.
	:param exclusive: If True, acquire an exclusive lock; otherwise, a shared lock.
	:param timeout: Maximum time to wait for the lock in seconds.
	:param lock_method: Use "flock" (default) for fcntl.flock or "lockf" for fcntl.lockf.
	:raises TimeoutError: If the lock cannot be acquired within the specified timeout.
	:raises ValueError: If an invalid lock_method is specified.
	"""
	lock_flags = LOCK_NB | (LOCK_EX if exclusive else LOCK_SH)
	start = monotonic()
	lock_meth = lockf if lock_method == "lockf" else flock
	while True:
		try:
			lock_meth(file, lock_flags)
			break
		except (IOError, BlockingIOError):
			if monotonic() >= start + timeout:
				raise TimeoutError(f"Failed to lock file after {timeout:0.2f} seconds") from None
			sleep(0.1)
	try:
		yield
		file.flush()
	finally:
		lock_meth(file, LOCK_UN)
