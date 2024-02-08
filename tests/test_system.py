# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import getpass
import multiprocessing
import os
import queue
import shutil
import subprocess
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock
from uuid import UUID

import pytest

from opsicommon.system import (
	ensure_not_already_running,
	get_system_uuid,
	lock_file,
	set_system_datetime,
)


@pytest.mark.linux
@pytest.mark.not_in_docker
def test_get_user_sessions_linux() -> None:
	from opsicommon.system import (
		get_user_sessions,
	)

	username = os.environ.get("SUDO_USER", getpass.getuser())
	usernames = [sess.username for sess in get_user_sessions()]
	assert username in usernames


@pytest.mark.linux
def test_get_user_sessions_linux_mock() -> None:
	import psutil  # type: ignore[import]

	from opsicommon.system import (
		get_user_sessions,
	)

	with mock.patch(
		"psutil.users",
		lambda: [psutil._common.suser(name="mockuser", terminal="tty3", host="", started=time.time(), pid=str(os.getpid()))],
	):
		assert "mockuser" in [sess.username for sess in get_user_sessions()]


@pytest.mark.linux
@pytest.mark.not_in_docker
def test_run_process_in_session_linux() -> None:
	from opsicommon.system import (
		get_user_sessions,
		run_process_in_session,
	)

	username = getpass.getuser()
	for session in get_user_sessions():
		if username in (session.username, "root"):
			proc = run_process_in_session(command=["whoami"], session_id=session.id, impersonate=False)
			out = proc.stdout.read().decode()  # type: ignore[union-attr]
			assert f"{username}\n" == out
			proc.wait()

			proc = run_process_in_session(command=["whoami"], session_id=session.id, impersonate=True)
			out = proc.stdout.read().decode()  # type: ignore[union-attr]
			assert f"{session.username}\n" == out
			proc.wait()


@pytest.mark.linux
def test_ensure_not_already_running_linux(tmpdir: Path) -> None:
	test_system_sleep = tmpdir / "test_system_sleep"
	shutil.copy("/bin/sleep", test_system_sleep)
	with subprocess.Popen([f"{test_system_sleep} 5 </dev/null &>/dev/null &"], shell=True):
		time.sleep(1)
		with pytest.raises(RuntimeError):
			ensure_not_already_running("test_system_sleep")


@pytest.mark.linux
def test_ensure_not_already_running_child_process_linux(tmpdir: Path) -> None:
	test_system_sleep = tmpdir / "test_system_sleep_child"
	shutil.copy("/bin/sleep", test_system_sleep)
	with subprocess.Popen([test_system_sleep, "5"]):
		time.sleep(1)
		# test_system_sleep_child is our child => no Exception should be raised
		ensure_not_already_running("test_system_sleep_child")


@pytest.mark.linux
@pytest.mark.admin_permissions
def test_drop_privileges() -> None:
	from opsicommon.system.linux import (
		drop_privileges,
	)

	username = getpass.getuser()
	drop_privileges(username)


@pytest.mark.not_in_docker
@pytest.mark.admin_permissions
def test_set_system_datetime() -> None:
	now = datetime.utcnow()
	try:
		new_time = now - timedelta(seconds=10)
		set_system_datetime(new_time)
		cur = datetime.utcnow()
		assert abs((new_time - cur).total_seconds()) <= 1
	finally:
		set_system_datetime(now)


@pytest.mark.linux
def test_get_kernel_params(tmpdir: Path) -> None:
	cmdline_path = tmpdir / "cmdline"
	cmdline_path.write_text("root=/root rw quiet splash apparmor=1 security=apparmor", encoding="utf-8")

	from opsicommon.system.linux import get_kernel_params

	with mock.patch("opsicommon.system.linux.CMDLINE_PATH", str(cmdline_path)):
		assert get_kernel_params() == {"root": "/root", "rw": "", "quiet": "", "splash": "", "apparmor": "1", "security": "apparmor"}


@pytest.mark.admin_permissions
def test_get_system_uuid() -> None:
	system_uuid = get_system_uuid()
	assert UUID(system_uuid)


class Task:  # type: ignore
	def __init__(self, task_id: int, file: Path, res_queue: queue.Queue, exclusive: bool, timeout: float, wait: float) -> None:
		self.task_id = task_id
		self.file = file
		self.exclusive = exclusive
		self.timeout = timeout
		self.wait = wait
		self.res_queue = res_queue

	def run(self) -> None:
		start = time.time()
		result: str | Exception | None = None
		try:
			with open(self.file, "a+", encoding="utf8") as test_fh:
				with lock_file(test_fh, exclusive=self.exclusive, timeout=self.timeout):
					test_fh.seek(0)
					data = test_fh.read()
					if self.exclusive:
						test_fh.seek(0)
						test_fh.write(",".join([str(self.task_id)] * 10))
						test_fh.truncate()
					result = data
					time.sleep(self.wait)
		except Exception as err:
			result = err
		self.res_queue.put((result, time.time() - start))


class ThreadTask(threading.Thread):
	def __init__(self, task_id: int, file: Path, res_queue: queue.Queue, exclusive: bool, timeout: float, wait: float) -> None:
		threading.Thread.__init__(self)
		self.task = Task(task_id, file, res_queue, exclusive, timeout, wait)

	def run(self) -> None:
		self.task.run()


class MultiprocessTask(multiprocessing.Process):
	def __init__(self, task_id: int, file: Path, res_queue: queue.Queue, exclusive: bool, timeout: float, wait: float) -> None:
		multiprocessing.Process.__init__(self)
		self.task = Task(task_id, file, res_queue, exclusive, timeout, wait)

	def run(self) -> None:
		self.task.run()


@pytest.mark.parametrize(
	"task_type",
	(ThreadTask, MultiprocessTask),
)
def test_lock_file(tmp_path: Path, task_type: type) -> None:
	test_file = tmp_path / "test.bin"
	res_queue: queue.Queue | multiprocessing.Queue = queue.Queue() if task_type == ThreadTask else multiprocessing.Queue()

	# Exclusive lock / write lock
	num_tasks = 10
	tasks = [
		task_type(task_id=task_id, file=test_file, res_queue=res_queue, exclusive=True, timeout=1.0, wait=3.0)
		for task_id in range(num_tasks)
	]
	for task in tasks:
		task.start()
	for task in tasks:
		task.join()

	results = [res_queue.get(timeout=5.0) for _ in range(num_tasks)]
	err_results = [r for r in results if isinstance(r[0], Exception)]
	assert len(err_results) == num_tasks - 1
	for res in err_results:
		assert 1.0 < res[1] < 2.0

	task_ids = test_file.read_text(encoding="utf-8").split(",")
	assert len(task_ids) == 10
	for task_id in task_ids:
		assert task_id == task_ids[0]

	file_data = "opsi" * 10
	test_file.write_text(file_data)

	# Shared lock / read lock
	num_tasks = 10
	tasks = [
		task_type(task_id=task_id, file=test_file, res_queue=res_queue, exclusive=False, timeout=1.0, wait=3.0)
		for task_id in range(num_tasks)
	]
	for task in tasks:
		task.start()
	for task in tasks:
		task.join()

	results = [res_queue.get(timeout=5.0) for _ in range(num_tasks)]
	success_results = [r for r in results if not isinstance(r[0], Exception)]
	assert len(success_results) == num_tasks
	for res in success_results:
		assert res[0] == file_data
