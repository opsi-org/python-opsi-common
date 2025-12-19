# opsicommon is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2025 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0-only

"""
This file is part of opsi - https://www.opsi.org
"""

from contextlib import contextmanager
from datetime import datetime
from time import monotonic, sleep
from typing import IO, BinaryIO, Generator, Literal, TextIO

import pywintypes  # type: ignore[import]
import win32api  # type: ignore[import]
import win32con  # type: ignore[import]
import win32file  # type: ignore[import]


def set_system_datetime(utc_datetime: datetime) -> None:
	win32api.SetSystemTime(
		utc_datetime.year,
		utc_datetime.month,
		utc_datetime.weekday(),
		utc_datetime.day,
		utc_datetime.hour,
		utc_datetime.minute,
		utc_datetime.second,
		0,
	)


def get_system_uuid() -> str:
	# Import wmi only when needed
	# Import on module level can lead to problems during opsiclientd start on system startup

	import wmi  # type: ignore[import]

	wmi_inst = wmi.WMI()
	for csp in wmi_inst.Win32_ComputerSystemProduct():
		return csp.UUID.lower()
	raise RuntimeError("Failed to find UUID in Win32_ComputerSystemProduct")


def _lock_file(file: TextIO | BinaryIO | IO, exclusive: bool = False, timeout: float = 5.0) -> None:
	lock_flags = win32con.LOCKFILE_FAIL_IMMEDIATELY | (win32con.LOCKFILE_EXCLUSIVE_LOCK if exclusive else 0)
	start = monotonic()
	while True:
		try:
			hfile = win32file._get_osfhandle(file.fileno())
			win32file.LockFileEx(hfile, lock_flags, 0, 0x7FFF0000, pywintypes.OVERLAPPED())
			break
		except pywintypes.error:
			if monotonic() >= start + timeout:
				raise TimeoutError(f"Failed to lock file after {timeout:0.2f} seconds") from None
			sleep(0.1)


def _unlock_file(file: TextIO | BinaryIO | IO) -> None:
	hfile = win32file._get_osfhandle(file.fileno())
	win32file.UnlockFileEx(hfile, 0, 0x7FFF0000, pywintypes.OVERLAPPED())


@contextmanager
def lock_file(
	file: TextIO | BinaryIO | IO, exclusive: bool = False, timeout: float = 5.0, lock_method: Literal["flock", "lockf"] | None = None
) -> Generator[None, None, None]:
	"""
	An exclusive or write lock gives a process exclusive access for writing to the specified part of the file.
	While a write lock is in place, no other process can lock that part of the file.
	A shared or read lock prohibits any other process from requesting a write lock on the file.
	"""
	_lock_file(file=file, exclusive=exclusive, timeout=timeout)
	try:
		yield
		file.flush()
	finally:
		_unlock_file(file=file)
