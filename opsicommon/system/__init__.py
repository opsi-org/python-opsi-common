# -*- coding: utf-8 -*-
"""
:copyright: uib GmbH <info@uib.de>
This file is part of opsi - https://www.opsi.org

:license: GNU Affero General Public License version 3
"""

import os
import sys
from collections import namedtuple
import psutil

from opsicommon.logging import logger

Session = namedtuple('Session', ["id", "type", "username", "terminal", "login_pid", "started"])

if sys.platform == "linux":
	from .linux import (
		get_user_sessions,
		run_process_in_session
	)

def ensure_not_already_running(process_name: str = None):
	pid = os.getpid()
	running = None
	try:
		proc = psutil.Process(pid)
		if not process_name:
			process_name = proc.name()
		parent_pid = proc.ppid()
		child_pids = [p.pid for p in proc.children(recursive=True)]
		
		for proc in psutil.process_iter():
			#logger.debug("Found running process: %s", proc)
			if proc.name() == process_name or proc.name() == f"{process_name}.exe":
				logger.debug("Found running '%s' process: %s", process_name, proc)
				if proc.pid != pid and proc.pid != parent_pid and proc.pid not in child_pids:
					running = proc.pid
					break
	except Exception as error:
		logger.debug("Check for running processes failed: %s", error)
	
	if running:
		raise RuntimeError(f"Another '{process_name}' process is running (pids: {running} / {pid}).")
