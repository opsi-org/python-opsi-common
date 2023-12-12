import subprocess
from typing import Any

import _winapi
import ntsecuritycon  # type: ignore[import]
import psutil
import win32api  # type: ignore[import]
import win32con  # type: ignore[import]
import win32process  # type: ignore[import]
import win32profile  # type: ignore[import]
import win32security  # type: ignore[import]


def get_process_user_token(user: str) -> int:
	user = user.lower()
	pid = -1
	for proc in psutil.process_iter():
		try:
			if proc.username().split("\\")[-1].lower() == user and proc.name() == "explorer.exe":
				pid = proc.pid
				break
		except psutil.AccessDenied:
			pass

	if pid == -1:
		raise RuntimeError(f"explorer.exe of user {user} not found")

	proc_handle = win32api.OpenProcess(win32con.MAXIMUM_ALLOWED, False, pid)
	proc_token = win32security.OpenProcessToken(proc_handle, win32con.MAXIMUM_ALLOWED)
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
	__startup_info: subprocess.STARTUPINFO,
) -> tuple[int, int, int, int]:
	if not __env_mapping or not __env_mapping.get("_create_process_as_user"):
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

	user_token = get_process_user_token(__env_mapping.pop("_create_process_as_user"))
	startup_info = win32process.STARTUPINFO()
	for attr, val in __startup_info.__dict__.items():
		if attr != "lpAttributeList" and val is not None:
			setattr(startup_info, attr, val)

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
