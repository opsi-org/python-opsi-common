# -*- coding: utf-8 -*-
"""
:copyright: uib GmbH <info@uib.de>
This file is part of opsi - https://www.opsi.org

:license: GNU Affero General Public License version 3
"""

import os
import pwd
import grp
import psutil
import getpass
import subprocess
import functools
from typing import List

from .. import Session

def get_user_sessions(username: str = None, session_type: str = None):
	for user in psutil.users():
		if username is not None and user.name != username:
			continue	
		_type = None
		terminal = user.terminal
		if terminal.startswith(":"):
			_type = "x11"
		elif terminal.startswith("tty"):
			_type = "tty"
			proc = psutil.Process(user.pid)
			env = proc.environ()
			# DISPLAY, XDG_SESSION_TYPE, XDG_SESSION_ID
			if env.get("DISPLAY"):
				_type = "x11"
				terminal = env["DISPLAY"]
		elif terminal.startswith("pts"):
			_type = "pts"
		if session_type is not None and session_type != _type:
			continue
		yield Session(
			id=terminal,
			type=_type,
			username=user.name,
			started=user.started,
			login_pid=user.pid,
			terminal=terminal
		)

def run_process_in_session(command: List[str], session_id: str, shell: bool = False, impersonate: bool = False):
	session = None
	for sess in get_user_sessions():
		if sess.id == session_id:
			session = sess
			break
	if not session:
		raise ValueError(f"Session {session_id} not found")
	
	procs = [ psutil.Process(pid=session.login_pid) ]
	procs += procs[0].children(recursive=True)
	env = {}
	for proc in procs:
		try:
			env = proc.environ()
		except psutil.AccessDenied:
			pass
		if env and (env.get("DISPLAY") or session.type != "x11"):
			# Need environment var DISPLAY to start process in x11
			break
	
	preexec_fn = None
	if impersonate and getpass.getuser() != session.username:
		preexec_fn = functools.partial(drop_privileges, session.username)
	
	return subprocess.Popen(
		args=command,
		preexec_fn=preexec_fn,
		stdin=subprocess.PIPE,
		stdout=subprocess.PIPE,
		stderr=subprocess.PIPE,
		shell=shell,
		env=env
	)

def drop_privileges(username: str):
	#logger.debug("Switching to user %s", username)
	user = pwd.getpwnam(username)
	gids = [user.pw_gid]
	for g in grp.getgrall():
		if user.pw_name in g.gr_mem and not g.gr_gid in gids:
			gids.append(g.gr_gid)
	#logger.debug("Set uid=%s, gid=%s, groups=%s", user.pw_uid, gids[0], gids)
	os.setgid(gids[0])
	os.setgroups(gids)
	os.setuid(user.pw_uid)
	os.environ["HOME"] = user.pw_dir
