# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
system.posix.subprocess
"""

import os
import sys

from opsicommon.logging import get_logger

LD_LIBRARY_EXCLUDE_LIST = ["/usr/lib/opsiclientd"]

logger = get_logger()


def get_subprocess_environment(env: dict = None):
	sp_env = env
	if sp_env is None:
		sp_env = os.environ.copy()

	if getattr(sys, "frozen", False):
		# Running in pyinstaller / frozen
		lp_orig = sp_env.get("LD_LIBRARY_PATH_ORIG")
		if lp_orig is not None:
			lp_orig = os.pathsep.join([entry for entry in lp_orig.split(os.pathsep) if entry not in LD_LIBRARY_EXCLUDE_LIST])
			# Restore the original, unmodified value
			logger.debug("Setting original LD_LIBRARY_PATH '%s' in env for subprocess", lp_orig)
			sp_env["LD_LIBRARY_PATH"] = lp_orig
		else:
			# This happens when LD_LIBRARY_PATH was not set.
			# Remove the env var as a last resort
			logger.debug("Removing LD_LIBRARY_PATH from env for subprocess")
			sp_env.pop("LD_LIBRARY_PATH", None)

	return sp_env
