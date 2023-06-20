# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

from datetime import datetime
from typing import BinaryIO, Generator, TextIO, IO
from contextlib import contextmanager
from time import time, sleep

import pywintypes  # type: ignore[import] # pylint: disable=import-error
import win32api  # type: ignore[import] # pylint: disable=import-error
import win32con  # type: ignore[import] # pylint: disable=import-error
import win32file  # type: ignore[import] # pylint: disable=import-error


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
	# pylint: disable=import-outside-toplevel
	import wmi  # type: ignore[import] # pylint: disable=import-error

	wmi_inst = wmi.WMI()
	for csp in wmi_inst.Win32_ComputerSystemProduct():
		return csp.UUID.lower()
	raise RuntimeError("Failed to find UUID in Win32_ComputerSystemProduct")


@contextmanager
def lock_file(file: TextIO | BinaryIO | IO, exclusive: bool = False, timeout: float = 5.0) -> Generator[None, None, None]:
	"""
	An exclusive or write lock gives a process exclusive access for writing to the specified part of the file.
	While a write lock is in place, no other process can lock that part of the file.
	A shared or read lock prohibits any other process from requesting a write lock on the file.
	"""
	lock_flags = win32con.LOCKFILE_FAIL_IMMEDIATELY | (win32con.LOCKFILE_EXCLUSIVE_LOCK if exclusive else 0)
	start = time()
	while True:
		try:
			hfile = win32file._get_osfhandle(file.fileno())  # pylint: disable=protected-access
			win32file.LockFileEx(hfile, lock_flags, 0, 0x7FFF0000, pywintypes.OVERLAPPED())
			break
		except pywintypes.error:
			if time() >= start + timeout:
				raise TimeoutError(f"Failed to lock file after {timeout:0.2f} seconds") from None
			sleep(0.1)
	try:
		yield
	finally:
		hfile = win32file._get_osfhandle(file.fileno())  # pylint: disable=protected-access
		win32file.UnlockFileEx(hfile, 0, 0x7FFF0000, pywintypes.OVERLAPPED())
