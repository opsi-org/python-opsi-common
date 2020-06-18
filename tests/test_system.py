# -*- coding: utf-8 -*-
"""
:copyright: uib GmbH <info@uib.de>
This file is part of opsi - https://www.opsi.org

:license: GNU Affero General Public License version 3
"""

import os
import pytest
import shutil
import getpass
import subprocess

from opsicommon.system import (
	get_user_sessions,
	run_process_in_session,
	ensure_not_already_running
)

running_in_docker = False
with open("/proc/self/cgroup") as f:
	running_in_docker = f.readline().split(':')[2].startswith("/docker/")

@pytest.mark.skipif(running_in_docker, reason="Running in docker.")
def test_get_user_sessions():
	username = getpass.getuser()
	usernames = []
	for sess in get_user_sessions():
		usernames.append(sess.username)
	assert username in usernames

@pytest.mark.skipif(running_in_docker, reason="Running in docker.")
def test_run_process_in_session():
	username = getpass.getuser()
	for session in get_user_sessions():
		if session.username == username or username == "root":
			proc = run_process_in_session(command=["whoami"], session_id=session.id, impersonate=False)
			out = proc.stdout.read().decode()
			assert f"{username}\n" == out
			proc.wait()

			proc = run_process_in_session(command=["whoami"], session_id=session.id, impersonate=True)
			out = proc.stdout.read().decode()
			assert f"{session.username}\n" == out
			proc.wait()

def test_ensure_not_already_running(tmpdir):
	test_system_sleep = tmpdir.join("test_system_sleep")
	shutil.copy("/bin/sleep", test_system_sleep)
	subprocess.Popen([f"{test_system_sleep} 3 </dev/null &>/dev/null &"], shell=True)
	with pytest.raises(RuntimeError) as exc:
		ensure_not_already_running("test_system_sleep")

def test_ensure_not_already_running_child_process(tmpdir):
	test_system_sleep = tmpdir.join("test_system_sleep_child")
	shutil.copy("/bin/sleep", test_system_sleep)
	subprocess.Popen([test_system_sleep, "3"])
	# test_system_sleep_child is our child => no Exception should be raised 
	ensure_not_already_running("test_system_sleep_child")
