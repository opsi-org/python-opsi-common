# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
system.windows.subprocess
"""

from typing import Any

import _winapi
import ntsecuritycon  # type: ignore[import]
import psutil
import win32api  # type: ignore[import]
import win32con  # type: ignore[import]
import win32process  # type: ignore[import]
import win32profile  # type: ignore[import]
import win32security  # type: ignore[import]
import win32ts  # type: ignore[import]


def get_process(process_name: str, session_id: int) -> psutil.Process | None:
	process_name = process_name.lower()
	session_id = int(session_id)
	for proc in psutil.process_iter():
		try:
			if proc.name() == process_name and win32ts.ProcessIdToSessionId(proc.pid) == session_id:
				return proc
		except psutil.AccessDenied:
			pass
	return None


def get_process_user_token(process_id: int, duplicate: bool = False) -> int:
	proc_handle = win32api.OpenProcess(win32con.MAXIMUM_ALLOWED, False, process_id)
	proc_token = win32security.OpenProcessToken(proc_handle, win32con.MAXIMUM_ALLOWED)
	if not duplicate:
		return proc_token
	proc_token_dup = win32security.DuplicateTokenEx(
		ExistingToken=proc_token,
		# To request the same access rights as the existing token, specify zero.
		DesiredAccess=0,
		# https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-security_impersonation_level
		# SecurityDelegation: The server process can impersonate the client's security context on remote systems.
		ImpersonationLevel=win32security.SecurityDelegation,
		# The new token is a primary token that you can use in the CreateProcessAsUser function.
		TokenType=ntsecuritycon.TokenPrimary,
	)
	return proc_token_dup


CreateProcessOrig = _winapi.CreateProcess  # type: ignore[attr-defined]


def CreateProcess(
	__application_name: str | None,
	__command_line: str | None,
	__proc_attrs: Any,
	__thread_attrs: Any,
	__inherit_handles: bool,
	__creation_flags: int,
	__env_mapping: dict[str, str],
	__current_directory: str | None,
	__startup_info: Any,
) -> tuple[int, int, int, int]:
	if not __env_mapping or not __env_mapping.get("_opsi_popen_session_id"):
		return CreateProcessOrig(
			__application_name,
			__command_line,
			__proc_attrs,
			__thread_attrs,
			__inherit_handles,
			__creation_flags,
			__env_mapping,
			__current_directory,
			__startup_info,
		)

	session_id = int(__env_mapping.pop("_opsi_popen_session_id"))
	session_elevated = bool(int(__env_mapping.pop("_opsi_popen_session_elevated", "0")))
	session_desktop = __env_mapping.pop("_opsi_popen_session_desktop", "")
	process_name = "winlogon.exe" if session_elevated else "explorer.exe"
	proc = get_process(process_name=process_name, session_id=session_id)
	if not proc:
		raise RuntimeError(f"Failed to find '{process_name}' in session {session_id}")

	user_token = get_process_user_token(proc.pid, duplicate=True)
	startup_info = win32process.STARTUPINFO()
	for attr, val in __startup_info.__dict__.items():
		if attr != "lpAttributeList" and val is not None:
			setattr(startup_info, attr, val)

	if session_desktop:
		if r"\\" not in session_desktop:
			session_desktop = f"WinSta0\\{session_desktop}"
		if session_desktop.split("\\")[-1].lower() not in ("default", "winlogon"):
			raise ValueError(f"Invalid desktop '{session_desktop}'")
		startup_info.lpDesktop = session_desktop

	__env_mapping = win32profile.CreateEnvironmentBlock(user_token, False)
	(process_handle, thread_handle, process_id, thread_id) = win32process.CreateProcessAsUser(
		user_token,
		__application_name,
		__command_line,
		__proc_attrs,
		__thread_attrs,
		__inherit_handles,
		__creation_flags,
		__env_mapping,
		__current_directory,
		startup_info,
	)
	return (process_handle.Detach(), thread_handle.Detach(), process_id, thread_id)


def patch_create_process() -> None:
	_winapi.CreateProcess = CreateProcess  # type: ignore[attr-defined]
