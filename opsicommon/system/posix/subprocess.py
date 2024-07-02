# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
system.posix.subprocess
"""

import os
import sys
from pathlib import Path
from opsicommon.logging import get_logger

LD_LIBRARY_EXCLUDE_LIST = ["/usr/lib/opsiclientd", "/usr/lib/opsiconfd"]

logger = get_logger()


def _get_executable_path() -> Path:
	return Path(sys.executable).resolve().parent


def get_subprocess_environment(env: dict[str, str] | None = None) -> dict[str, str]:
	if env is None:
		env = os.environ.copy()

	executable_path = _get_executable_path()
	if getattr(sys, "frozen", False):
		# Running in pyinstaller / frozen
		ldlp = []
		for entry in (env.get("LD_LIBRARY_PATH_ORIG") or env.get("LD_LIBRARY_PATH") or "").split(os.pathsep):
			entry = entry.strip()
			if not entry:
				continue
			if entry in LD_LIBRARY_EXCLUDE_LIST:
				continue
			entry_path = Path(entry)
			if executable_path.is_relative_to(entry_path):
				continue
			ldlp.append(entry)
		if ldlp:
			ldlp_str = os.pathsep.join(ldlp)
			logger.debug("Setting LD_LIBRARY_PATH to '%s' in env for subprocess", ldlp_str)
			env["LD_LIBRARY_PATH"] = ldlp_str
		else:
			logger.debug("Removing LD_LIBRARY_PATH from env for subprocess")
			env.pop("LD_LIBRARY_PATH", None)

	return env
