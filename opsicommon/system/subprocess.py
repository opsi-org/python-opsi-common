# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
system.subprocess
"""

import platform
import subprocess
from os import PathLike, environ
from typing import IO, Any, Callable, Collection, Iterable, Mapping, Sequence

SYSTEM = platform.system().lower()

if SYSTEM == "windows":
	from opsicommon.system.windows.subprocess import patch_create_process

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
	) -> None:
		env = dict(env or environ.copy())
		lp_orig = env.get("LD_LIBRARY_PATH_ORIG")
		if lp_orig is not None:
			# Restore the original, unmodified value
			env["LD_LIBRARY_PATH"] = lp_orig
		else:
			# This happens when LD_LIBRARY_PATH was not set.
			# Remove the env var as a last resort
			env.pop("LD_LIBRARY_PATH", None)

		if SYSTEM == "windows" and user:
			# Original Popen does not support 'user' parameter
			env["_create_process_as_user"] = str(user)
			user = None
		PopenOrig.__init__(  # type: ignore  # pylint: disable=non-parent-init-called
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
	if SYSTEM == "windows":
		patch_create_process()
