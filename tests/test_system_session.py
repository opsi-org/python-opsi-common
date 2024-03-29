# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
test_system_session
"""

import subprocess

import pytest


@pytest.mark.windows
def test_get_sessions() -> None:
	from opsicommon.system.windows.session import get_windows_sessions

	sessions = get_windows_sessions()
	assert sessions
	session_ids = [s.session_id for s in sessions]
	assert 0 in session_ids


@pytest.mark.windows
def test_popen_session() -> None:
	from opsicommon.system.subprocess import patch_popen
	from opsicommon.system.windows.session import get_windows_sessions

	patch_popen()
	user_sessions = [s for s in get_windows_sessions() if s.username]
	if not user_sessions:
		pytest.skip("No user sessions found")

	proc = subprocess.run(  # type: ignore[call-overload]
		["powershell.exe", "-Command", "Write-Host $Env:USERNAME"],
		check=True,
		capture_output=True,
		text=True,
		session_id=user_sessions[0].session_id,
		session_env=True,
		session_elevated=False,
	)
	assert proc.stdout.strip() == user_sessions[0].username
