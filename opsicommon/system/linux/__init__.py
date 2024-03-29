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
from datetime import datetime
from pathlib import Path
from typing import Generator, List, Optional

import psutil  # type: ignore[import]

from opsicommon.logging import get_logger

from .. import Session

logger = get_logger("opsicommon.general")

CMDLINE_PATH = "/proc/cmdline"


def set_system_datetime(utc_datetime: datetime) -> None:
	try:
		subprocess.run(["date", "--utc", "--set", utc_datetime.strftime("%Y-%m-%d %H:%M:%S")], capture_output=True, check=True)
	except subprocess.CalledProcessError as err:
		raise RuntimeError(
			f"Failed to set system time as uid {os.geteuid()}: {err.returncode} - {err.stderr.decode(errors='replace')}"
		) from err


def get_user_sessions(username: Optional[str] = None, session_type: Optional[str] = None) -> Generator[Session, None, None]:
	for user in psutil.users():
		if username is not None and user.name != username:
			continue
		_type = None
		terminal = user.terminal
		if terminal:
			if terminal.startswith(":"):
				_type = "x11"
			elif terminal.startswith("tty"):
				_type = "tty"
				proc = psutil.Process(int(user.pid))
				env = proc.environ()
				# DISPLAY, XDG_SESSION_TYPE, XDG_SESSION_ID
				if env.get("DISPLAY"):
					_type = "x11"
					terminal = env["DISPLAY"]
			elif terminal.startswith("pts"):
				_type = "pts"
		if session_type is not None and session_type != _type:
			continue
		yield Session(id=terminal, type=_type, username=user.name, started=user.started, login_pid=user.pid, terminal=terminal)


def run_process_in_session(command: List[str], session_id: str, shell: bool = False, impersonate: bool = False) -> subprocess.Popen:
	session = None
	for sess in get_user_sessions():
		if sess.id == session_id:
			session = sess
			break
	if not session:
		raise ValueError(f"Session {session_id} not found")

	procs = [psutil.Process(pid=session.login_pid)]
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
		args=command, preexec_fn=preexec_fn, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=shell, env=env
	)


def drop_privileges(username: str) -> None:
	logger.debug("Switching to user %s", username)
	user = pwd.getpwnam(username)
	gids = [user.pw_gid]
	for _grp in grp.getgrall():
		if user.pw_name in _grp.gr_mem and _grp.gr_gid not in gids:
			gids.append(_grp.gr_gid)
	logger.trace("Set uid=%s, gid=%s, groups=%s", user.pw_uid, gids[0], gids)
	os.setgid(gids[0])
	os.setgroups(gids)
	os.setuid(user.pw_uid)
	os.environ["HOME"] = user.pw_dir


def get_kernel_params() -> dict[str, str]:
	"""
	Reads the kernel cmdline and returns a dict containing all key=value pairs.
	Keys are converted to lower case.
	"""
	cmdline_path = Path(CMDLINE_PATH)
	logger.debug("Reading %s", cmdline_path)
	cmdline = cmdline_path.read_text(encoding="utf-8").strip()

	params: dict[str, str] = {}
	for option in cmdline.split():
		key_value = option.split("=", 1)
		params[key_value[0].strip().lower()] = "" if len(key_value) == 1 else key_value[1].strip()
	return params


def get_system_uuid() -> str:
	uuid_path = Path("/sys/class/dmi/id/product_uuid")
	if uuid_path.exists():
		return uuid_path.read_text(encoding="utf-8").strip().lower()
	logger.debug("'%s' not available, trying dmidecode", uuid_path)
	system_uuid = (
		subprocess.run(["dmidecode", "-s", "system-uuid"], shell=False, check=True, timeout=10, capture_output=True, encoding="utf-8")
		.stdout.strip()
		.lower()
	)
	if not system_uuid:
		raise RuntimeError("Failed to get system uuid from dmidecode")
	return system_uuid
