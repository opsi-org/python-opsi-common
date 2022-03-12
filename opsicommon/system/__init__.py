# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
system
"""

import os
import sys
from collections import namedtuple

import psutil  # type: ignore[import]

from opsicommon.logging import logger

Session = namedtuple("Session", ["id", "type", "username", "terminal", "login_pid", "started"])

if sys.platform == "linux":
	from .linux import get_user_sessions, run_process_in_session


def ensure_not_already_running(process_name: str = None):
	our_pid = os.getpid()
	other_pid = None
	try:
		our_proc = psutil.Process(our_pid)
		if not process_name:
			process_name = our_proc.name()
		ignore_pids = [p.pid for p in our_proc.children(recursive=True)]
		ignore_pids += [p.pid for p in our_proc.parents()]
		for proc in psutil.process_iter():
			# logger.debug("Found running process: %s", proc)
			if proc.name() == process_name or proc.name() == f"{process_name}.exe":
				logger.debug("Found running '%s' process: %s", process_name, proc)
				if proc.pid != our_pid and proc.pid not in ignore_pids:
					other_pid = proc.pid
					break
	except Exception as err:  # pylint: disable=broad-except
		logger.debug("Check for running processes failed: %s", err)

	if other_pid:
		raise RuntimeError(f"Another '{process_name}' process is running (pids: {other_pid} / {our_pid}).")
