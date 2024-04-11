# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
system.subprocess
"""

import os
import subprocess
from os import PathLike, pathsep
from typing import IO, Any, Callable, Collection, Iterable, Mapping, Sequence

from opsicommon.system.info import SYSTEM, is_posix, is_windows

if is_windows():
	import win32profile  # type: ignore[import]

	from opsicommon.system.windows.subprocess import get_process, get_process_user_token, patch_create_process

if is_posix():
	from opsicommon.system.posix.subprocess import get_subprocess_environment

PopenOrig = subprocess.Popen


class Popen(PopenOrig):
	def __init__(
		self,
		args: str | bytes | PathLike[str] | PathLike[bytes] | Sequence[str | bytes | PathLike[str] | PathLike[bytes]],
		bufsize: int = -1,
		executable: str | bytes | PathLike[str] | PathLike[bytes] | None = None,
		stdin: int | IO[Any] | None = None,
		stdout: int | IO[Any] | None = None,
		stderr: int | IO[Any] | None = None,
		preexec_fn: Callable[[], Any] | None = None,
		close_fds: bool = True,
		shell: bool = False,
		cwd: str | bytes | PathLike[str] | PathLike[bytes] | None = None,
		env: Mapping[str, str] | None = None,
		universal_newlines: bool | None = None,
		startupinfo: Any | None = None,
		creationflags: int = 0,
		restore_signals: bool = True,
		start_new_session: bool = False,
		pass_fds: Collection[int] = (),
		*,
		text: bool | None = None,
		encoding: str | None = None,
		errors: str | None = None,
		user: str | int | None = None,
		group: str | int | None = None,
		extra_groups: Iterable[str | int] | None = None,
		umask: int = -1,
		pipesize: int = -1,
		process_group: int | None = None,
		session_id: str | int | None = None,
		session_env: bool | None = None,
		session_elevated: bool | None = None,
		session_desktop: str | None = None,
	) -> None:
		if (not is_windows()) and session_id is not None:
			raise NotImplementedError(f"Parameter 'session_id' not supported on {SYSTEM!r}")
		if session_env is not None and session_id is None:
			raise ValueError("Parameter 'session_env' requires 'session_id' to be set")
		if session_elevated is not None and session_id is None:
			raise ValueError("Parameter 'session_elevated' requires 'session_id' to be set")
		if session_desktop is not None and session_id is None:
			raise ValueError("Parameter 'session_desktop' requires 'session_id' to be set")

		if is_windows() and session_id and (session_env or session_env is None):
			proc = get_process("explorer.exe", session_id=int(session_id))
			if not proc:
				raise RuntimeError(f"Failed to find 'explorer.exe' in session {session_id}")
			# senv = proc.environ()
			senv = win32profile.CreateEnvironmentBlock(get_process_user_token(proc.pid), False)
			if env:
				senv.update(env)
			env = senv

		env = dict(env or os.environ.copy())
		if is_posix():
			env = get_subprocess_environment(env)

		for key in list(env.keys()):
			if key.startswith("_opsi_popen_"):
				del env[key]

		path = env.get("PATH")
		if path:
			# Cleanup PATH variable
			# Remove empty values and values containing "pywin32_system32" and "opsi"
			values = list(dict.fromkeys(v for v in path.split(pathsep) if v and not ("pywin32_system32" in v and "opsi" in v)))
			env["PATH"] = pathsep.join(values)

		if session_id and is_windows():
			env["_opsi_popen_session_id"] = str(session_id)
			env["_opsi_popen_session_elevated"] = str(int(bool(session_elevated)))
			if session_desktop:
				env["_opsi_popen_session_desktop"] = str(session_desktop)

		PopenOrig.__init__(  # type: ignore
			self,
			args=args,
			bufsize=bufsize,
			executable=executable,
			stdin=stdin,
			stdout=stdout,
			stderr=stderr,
			preexec_fn=preexec_fn,
			close_fds=close_fds,
			shell=shell,
			cwd=cwd,
			env=env,
			universal_newlines=universal_newlines,
			startupinfo=startupinfo,
			creationflags=creationflags,
			restore_signals=restore_signals,
			start_new_session=start_new_session,
			pass_fds=pass_fds,
			user=user,
			group=group,
			extra_groups=extra_groups,
			encoding=encoding,
			errors=errors,
			text=text,
			umask=umask,
			pipesize=pipesize,
			process_group=process_group,
		)


def patch_popen() -> None:
	subprocess.Popen = Popen  # type: ignore
	if is_windows():
		patch_create_process()
