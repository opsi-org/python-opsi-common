# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
system
"""

import os
import platform
from collections import namedtuple
from typing import Optional

import psutil  # type: ignore[import]

from opsicommon.logging import get_logger

Session = namedtuple("Session", ["id", "type", "username", "terminal", "login_pid", "started"])

SYSTEM = platform.system().lower()


if SYSTEM == "linux":
	from .linux import (
		get_system_uuid,
		get_user_sessions,
		run_process_in_session,
		set_system_datetime,
	)
	from .posix import lock_file
elif SYSTEM == "windows":
	from .windows import get_system_uuid, set_system_datetime, lock_file
elif SYSTEM == "darwin":
	from .darwin import get_system_uuid, set_system_datetime
	from .posix import lock_file


logger = get_logger("opsicommon.general")


def ensure_not_already_running(process_name: Optional[str] = None) -> None:
	container_procs = ("containerd-shim", "lxc-start")
	our_pid = os.getpid()
	other_pid = None
	try:
		our_proc = psutil.Process(our_pid)
		if not process_name:
			process_name = our_proc.name()
		exe_name = f"{process_name}.exe"
		ignore_pids = [p.pid for p in our_proc.children(recursive=True)]
		ignore_pids += [p.pid for p in our_proc.parents()]
		for proc in psutil.process_iter():
			# logger.debug("Found running process: %s", proc)
			if proc.name() == process_name or proc.name() == exe_name:
				logger.debug("Found running '%s' process: %s", process_name, proc)

				running_in_container_pid = 0
				for parent in proc.parents():
					if parent.name() in container_procs:
						running_in_container_pid = parent.pid
						break
				if running_in_container_pid:
					logger.debug("Process is running in container %d, skipping", running_in_container_pid)
					continue

				if proc.pid != our_pid and proc.pid not in ignore_pids:
					other_pid = proc.pid
					break
	except Exception as err:  # pylint: disable=broad-except
		logger.debug("Check for running processes failed: %s", err)

	if other_pid:
		raise RuntimeError(f"Another '{process_name}' process is running (pids: {other_pid} / {our_pid}).")
