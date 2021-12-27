# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import os
import shutil
import getpass
import subprocess

import pytest

from opsicommon.system import (
	get_user_sessions,
	run_process_in_session,
	ensure_not_already_running
)

running_in_docker = False # pylint: disable=invalid-name
with open("/proc/self/cgroup", encoding="utf-8") as file: # pylint: disable=invalid-name
	for line in file.readlines():
		if line.split(':')[2].startswith("/docker/"):
			running_in_docker = True # pylint: disable=invalid-name
			break

@pytest.mark.skipif(running_in_docker, reason="Running in docker.")
def test_get_user_sessions():
	username = os.environ.get("SUDO_USER", getpass.getuser())
	usernames = []
	for sess in get_user_sessions():
		usernames.append(sess.username)
	assert username in usernames

@pytest.mark.skipif(running_in_docker, reason="Running in docker.")
def test_run_process_in_session():
	username = getpass.getuser()
	for session in get_user_sessions():
		if username in (session.username, "root"):
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
	with subprocess.Popen([f"{test_system_sleep} 3 </dev/null &>/dev/null &"], shell=True):
		with pytest.raises(RuntimeError):
			ensure_not_already_running("test_system_sleep")

def test_ensure_not_already_running_child_process(tmpdir):
	test_system_sleep = tmpdir.join("test_system_sleep_child")
	shutil.copy("/bin/sleep", test_system_sleep)
	with subprocess.Popen([test_system_sleep, "3"]):
		# test_system_sleep_child is our child => no Exception should be raised
		ensure_not_already_running("test_system_sleep_child")
