# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import functools
import getpass
import grp
import os
import pwd
import subprocess
from typing import List

import psutil  # type: ignore[import]

from opsicommon.logging import get_logger

from .. import Session

logger = get_logger("opsicommon.general")


def get_user_sessions(username: str = None, session_type: str = None):
	for user in psutil.users():  # pylint: disable=dotted-import-in-loop
		if username is not None and user.name != username:  # pylint: disable=loop-invariant-statement
			continue
		_type = None
		terminal = user.terminal
		if terminal.startswith(":"):
			_type = "x11"
		elif terminal.startswith("tty"):
			_type = "tty"
			proc = psutil.Process(user.pid)  # pylint: disable=dotted-import-in-loop
			env = proc.environ()
			# DISPLAY, XDG_SESSION_TYPE, XDG_SESSION_ID
			if env.get("DISPLAY"):
				_type = "x11"
				terminal = env["DISPLAY"]
		elif terminal.startswith("pts"):
			_type = "pts"
		if session_type is not None and session_type != _type:  # pylint: disable=loop-invariant-statement
			continue
		yield Session(id=terminal, type=_type, username=user.name, started=user.started, login_pid=user.pid, terminal=terminal)


def run_process_in_session(command: List[str], session_id: str, shell: bool = False, impersonate: bool = False):
	session = None
	for sess in get_user_sessions():
		if sess.id == session_id:
			session = sess
			break
	if not session:
		raise ValueError(f"Session {session_id} not found")

	procs = [psutil.Process(pid=session.login_pid)]  # pylint: disable=use-tuple-over-list
	procs += procs[0].children(recursive=True)
	env = {}
	for proc in procs:
		try:  # pylint: disable=loop-try-except-usage
			env = proc.environ()
		except psutil.AccessDenied:  # pylint: disable=dotted-import-in-loop,loop-invariant-statement
			pass
		if env and (env.get("DISPLAY") or session.type != "x11"):  # pylint: disable=loop-invariant-statement
			# Need environment var DISPLAY to start process in x11
			break

	preexec_fn = None
	if impersonate and getpass.getuser() != session.username:
		preexec_fn = functools.partial(drop_privileges, session.username)

	return subprocess.Popen(  # pylint: disable=subprocess-popen-preexec-fn
		args=command, preexec_fn=preexec_fn, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=shell, env=env
	)


def drop_privileges(username: str):
	logger.debug("Switching to user %s", username)
	user = pwd.getpwnam(username)
	gids = [user.pw_gid]
	for _grp in grp.getgrall():  # pylint: disable=use-list-comprehension,dotted-import-in-loop
		if user.pw_name in _grp.gr_mem and _grp.gr_gid not in gids:
			gids.append(_grp.gr_gid)
	logger.trace("Set uid=%s, gid=%s, groups=%s", user.pw_uid, gids[0], gids)
	os.setgid(gids[0])
	os.setgroups(gids)
	os.setuid(user.pw_uid)
	os.environ["HOME"] = user.pw_dir
