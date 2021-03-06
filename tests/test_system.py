# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import getpass
import os
import shutil
import subprocess
import time
from unittest import mock

import pytest

from opsicommon.system import ensure_not_already_running


@pytest.mark.linux
@pytest.mark.not_in_docker
def test_get_user_sessions_linux():
	from opsicommon.system import (  # pylint: disable=import-outside-toplevel
		get_user_sessions,
	)

	username = os.environ.get("SUDO_USER", getpass.getuser())
	usernames = [sess.username for sess in get_user_sessions()]
	assert username in usernames


@pytest.mark.linux
def test_get_user_sessions_linux_mock():
	import psutil  # type: ignore[import]  # pylint: disable=import-outside-toplevel

	from opsicommon.system import (  # pylint: disable=import-outside-toplevel
		get_user_sessions,
	)

	with mock.patch(
		"psutil.users",
		lambda: [
			psutil._common.suser(  # pylint: disable=protected-access
				name="mockuser", terminal="tty3", host="", started=time.time(), pid=os.getpid()
			)  # pylint: disable=protected-access
		],
	):
		assert "mockuser" in [sess.username for sess in get_user_sessions()]


@pytest.mark.linux
@pytest.mark.not_in_docker
def test_run_process_in_session_linux():
	from opsicommon.system import (  # pylint: disable=import-outside-toplevel
		get_user_sessions,
		run_process_in_session,
	)

	username = getpass.getuser()
	for session in get_user_sessions():
		if username in (session.username, "root"):
			proc = run_process_in_session(command=["whoami"], session_id=session.id, impersonate=False)
			out = proc.stdout.read().decode()
			assert f"{username}\n" == out  # pylint: disable=loop-invariant-statement
			proc.wait()

			proc = run_process_in_session(command=["whoami"], session_id=session.id, impersonate=True)
			out = proc.stdout.read().decode()
			assert f"{session.username}\n" == out  # pylint: disable=loop-invariant-statement
			proc.wait()


@pytest.mark.linux
def test_ensure_not_already_running_linux(tmpdir):
	test_system_sleep = tmpdir.join("test_system_sleep")
	shutil.copy("/bin/sleep", test_system_sleep)
	with subprocess.Popen([f"{test_system_sleep} 3 </dev/null &>/dev/null &"], shell=True):
		with pytest.raises(RuntimeError):
			ensure_not_already_running("test_system_sleep")


@pytest.mark.linux
def test_ensure_not_already_running_child_process_linux(tmpdir):
	test_system_sleep = tmpdir.join("test_system_sleep_child")
	shutil.copy("/bin/sleep", test_system_sleep)
	with subprocess.Popen([test_system_sleep, "3"]):
		# test_system_sleep_child is our child => no Exception should be raised
		ensure_not_already_running("test_system_sleep_child")


@pytest.mark.linux
@pytest.mark.admin_permissions
def test_drop_privileges():
	from opsicommon.system.linux import (  # pylint: disable=import-outside-toplevel
		drop_privileges,
	)

	username = getpass.getuser()
	drop_privileges(username)
