# opsicommon is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2025 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0-only

"""
This file is part of opsi - https://www.opsi.org
"""

import asyncio
import logging
import os
import random
import re
import tempfile
import threading
import time
import warnings
from multiprocessing import Process
from pathlib import Path
from typing import Any

import pytest
import requests
from _pytest.capture import CaptureFixture

from opsicommon.logging import (
	ContextSecretFormatter,
	ObservableHandler,
	context_filter,
	get_all_handlers,
	get_logger,
	handle_log_exception,
	init_warnings_capture,
	log_context,
	logging_config,
	observable_handler,
	print_logger_info,
	secret_filter,
	set_context,
	set_filter,
	set_filter_from_string,
	set_format,
	use_logging_config,
)
from opsicommon.logging.constants import INFO, LOG_DEBUG, LOG_ERROR, LOG_INFO, LOG_NOTSET, LOG_SECRET, LOG_TRACE, LOG_WARNING
from opsicommon.logging.logging import get_logger_levels, remove_all_handlers, reset_logging
from opsicommon.logging.sqlite import SQLiteHandler
from opsicommon.utils import unix_timestamp

from .helpers import log_stream

MY_FORMAT = "%(log_color)s[%(opsilevel)d] [%(asctime)s.%(msecs)03d]%(reset)s [%(contextstring)s] %(message)s"
OTHER_FORMAT = "[%(opsilevel)d] [%(asctime)s.%(msecs)03d] [%(contextstring)s] %(message)s   (%(filename)s:%(lineno)d)"

logger = get_logger()


@pytest.fixture(autouse=True)
def _reset_logging() -> None:
	reset_logging()


def test_levels() -> None:
	with log_stream(LOG_SECRET, format="%(message)s") as stream:
		expected = ""
		for level in ("secret", "confidential", "trace", "debug2", "debug", "info", "notice", "warning", "error", "critical", "comment"):
			func = getattr(logger, level)
			msg = f"logline {level}"
			func(msg)
			expected += f"{msg}\n"

		stream.seek(0)
		assert expected in stream.read()


def test_caller_filename() -> None:
	with log_stream(LOG_SECRET, format="%(levelname)s %(filename)s") as stream:
		for level in ("secret", "trace", "debug", "info", "notice", "warning", "error", "critical", "essential"):
			func = getattr(logger, level)
			func("")
		stream.seek(0)
		for line in stream.read().strip().split("\n"):
			assert line.split()[-1] == "test_logging.py"


def test_log_file(tmp_path: Path) -> None:
	log_file1 = tmp_path / "log1"
	log_file2 = tmp_path / "log2"
	log_file3 = tmp_path / "log3"
	logger.addHandler(logging.FileHandler(log_file1))
	logging_config(log_file=log_file2, file_level=logging.INFO, file_format="%(message)s", remove_handlers=False)
	logger.warning("message")
	with open(log_file1, encoding="utf-8") as file:
		assert file.read().strip() == "message"
	with open(log_file2, encoding="utf-8") as file:
		assert file.read().strip() == "message"

	logger.addHandler(logging.FileHandler(log_file3))
	logging_config(log_file=log_file2, file_level=logging.INFO, file_format="%(message)s", remove_handlers=True)
	logger.warning("message2")
	assert not os.path.exists(log_file3) or os.path.getsize(log_file3) == 0
	with open(log_file2, encoding="utf-8") as file:
		assert "message2" in file.read()

	logging_config(log_file=None, remove_handlers=True)


def test_log_exception_handler() -> None:
	log_record = logging.LogRecord(name="", level=logging.ERROR, pathname="", lineno=1, msg="t", args=None, exc_info=None)

	filename = os.path.join(tempfile.gettempdir(), f"log_exception_{os.getpid()}.txt")
	if os.path.exists(filename):
		os.remove(filename)
	try:
		raise Exception("TESTäöüß")
	except Exception as err:
		handle_log_exception(exc=err, record=log_record, log=True, temp_file=True, stderr=True)
		with open(filename, "r", encoding="utf-8") as file:
			data = file.read()
			assert "TESTäöüß" in data
			assert "'levelname': 'ERROR'" in data


@pytest.mark.linux
def test_permission_error_log_exception_handler(capsys: CaptureFixture[str]) -> None:
	pid = os.getpid()
	uid = os.getegid()
	gid = os.getegid()
	log_record = logging.LogRecord(name="", level=logging.ERROR, pathname="", lineno=1, msg="t", args=None, exc_info=None)
	test_file = f"/proc/{pid}/stat"
	try:
		os.remove(test_file)
	except PermissionError as err:
		handle_log_exception(exc=err, record=log_record, log=False, temp_file=False, stderr=True)
		lines = capsys.readouterr().err.strip().split("\n")
		assert lines[0] == "Logging error:"
		assert lines[1].startswith("File permissions: 100444, owner: ")
		assert lines[2] == f"Process uid: {uid}, gid: {gid}"
		assert lines[3] == "Traceback (most recent call last):"


def test_secret_formatter_attr() -> None:
	log_record = logging.LogRecord(name="", level=logging.ERROR, pathname="", lineno=1, msg="t", args=None, exc_info=None)
	csf = ContextSecretFormatter(logging.Formatter())
	csf.format(log_record)


def test_secret_filter() -> None:
	secret_filter.set_min_length(7)
	secret_filter.add_secrets("PASSWORD", "2SHORT", "SECRETSTRING")

	with log_stream(LOG_TRACE, format="[%(asctime)s.%(msecs)03d] %(message)s") as stream:
		print_logger_info()
		logger.info("line 1")
		logger.info("line 2 PASSWORD")
		logger.info("line 3 2SHORT")
		logger.secret("line 4 SECRETSTRING")
		stream.seek(0)
		log = stream.read()
		assert "line 1\n" in log
		assert "line 2 PASSWORD\n" not in log
		assert "line 3 2SHORT\n" in log
		assert "line 4 SECRETSTRING\n" not in log

	with log_stream(LOG_SECRET, format="[%(asctime)s.%(msecs)03d] %(message)s") as stream:
		print_logger_info()
		logger.info("line 5 PASSWORD")
		logger.secret("line 6 SECRETSTRING")
		stream.seek(0)
		log = stream.read()
		assert "line 5 PASSWORD\n" in log
		assert "line 6 SECRETSTRING\n" in log

		secret_filter.clear_secrets()
		logger.info("line 7 PASSWORD")

		secret_filter.clear_secrets()
		logger.info("line 7 PASSWORD")
		stream.seek(0)
		log = stream.read()
		assert "line 7 PASSWORD\n" in log

	secret_filter.add_secrets("SECRETSTRING1", "SECRETSTRING2", "SECRETSTRING3")
	secret_filter.remove_secrets("SECRETSTRING2")
	with log_stream(LOG_INFO) as stream:
		logger.info("SECRETSTRING1 SECRETSTRING2 SECRETSTRING3")
		stream.seek(0)
		log = stream.read()
		assert "SECRETSTRING1" not in log
		assert "SECRETSTRING2" in log
		assert "SECRETSTRING3" not in log

	# If log level is secret, log all secrets in all log levels (disable filter)
	secret_filter.clear_secrets()
	secret_filter.add_secrets("VISIBLE_SECRETSTRING")
	with log_stream(LOG_SECRET) as stream:
		logger.trace("VISIBLE_SECRETSTRING")
		logger.secret("VISIBLE_SECRETSTRING")
		stream.seek(0)
		log = stream.read()
		assert log.count("VISIBLE_SECRETSTRING") == 2


def test_context_base() -> None:
	with log_stream(LOG_SECRET) as stream:
		set_format(
			stderr_format=(
				"%(log_color)s[%(opsilevel)d] [%(asctime)s.%(msecs)03d]%(reset)s "
				"[%(contextstring)s] %(message)s   (%(filename)s:%(lineno)d)"
			)
		)

		logger.info("before setting context")
		with log_context({"whoami": "first-context"}):
			logger.warning("message-1")
			assert context_filter.get_context() == {
				"logger": "root",
				"whoami": "first-context",
			}

		with log_context({"whoami": "second-context", "remote_addr": "1.2.3.4", "extra": "value"}):
			logger.error("message-2")
			assert context_filter.get_context() == {
				"logger": "root",
				"whoami": "second-context",
				"remote_addr": "1.2.3.4",
				"extra": "value",
			}

			with log_context({"whoami": "second-context", "extra": "new-value", "additional": "info"}, replace=True):
				logger.error("message-3")
				assert context_filter.get_context() == {
					"logger": "root",
					"whoami": "second-context",
					"extra": "new-value",
					"additional": "info",
				}

			with log_context({"extra": "new-value-2", "additional": "info"}, replace=False):
				logger.error("message-4")
				assert context_filter.get_context() == {
					"logger": "root",
					"whoami": "second-context",
					"remote_addr": "1.2.3.4",
					"extra": "new-value-2",
					"additional": "info",
				}

			logger.error("message-5")
			assert context_filter.get_context() == {
				"logger": "root",
				"whoami": "second-context",
				"remote_addr": "1.2.3.4",
				"extra": "value",
			}

		stream.seek(0)
		log = stream.read()
		assert "[first-context] message-1 " in log
		assert "[second-context,1.2.3.4,value] message-2 " in log
		assert "[second-context,new-value,info] message-3 " in log
		assert "[second-context,1.2.3.4,new-value-2,info] message-4 " in log
		assert "[second-context,1.2.3.4,value] message-5 " in log


def test_context_threads() -> None:
	def common_work() -> None:
		time.sleep(0.2)
		logger.info("common_work")
		time.sleep(0.2)

	class Main:
		def run(self) -> None:
			AsyncMain().start()
			for _ in range(5):  # perform 5 iterations
				threads = []
				for i in range(2):
					_thread = MyModule(client=f"Client-{i}")
					threads.append(_thread)
					_thread.start()
				for _thread in threads:
					_thread.join()
				time.sleep(1)

	class AsyncMain(threading.Thread):
		def __init__(self) -> None:
			super().__init__()
			self._should_stop = False

		def stop(self) -> None:
			self._should_stop = True

		def run(self) -> None:
			loop = asyncio.new_event_loop()
			loop.run_until_complete(self.arun())
			loop.close()

		async def handle_client(self, client: str) -> None:
			with log_context({"whoami": "handler for " + str(client)}):
				logger.essential("handling client %s", client)
				seconds = random.random() * 1
				await asyncio.sleep(seconds)
				logger.essential("client %s handled after %0.3f seconds", client, seconds)

		async def arun(self) -> None:
			while not self._should_stop:
				tasks = []
				for i in range(2):
					tasks.append(self.handle_client(client=f"Client-{i}"))
				await asyncio.gather(*tasks)
				await asyncio.sleep(1)

	class MyModule(threading.Thread):
		def __init__(self, client: str):
			super().__init__()
			self.client = client
			logger.essential("initializing client: %s", client)

		def run(self) -> None:
			with log_context({"whoami": "module " + str(self.client)}):
				logger.essential("MyModule.run")
				common_work()

	with log_context({"whoami": "MAIN"}):
		with log_stream(LOG_INFO, format="%(contextstring)s %(message)s") as stream:
			main = Main()
			try:
				main.run()
			except KeyboardInterrupt:
				pass
			for _thread in threading.enumerate():
				if hasattr(_thread, "stop"):
					_thread.stop()  # type: ignore[attr-defined]
					_thread.join()

			stream.seek(0)
			log = stream.read()
			assert re.search(r"module Client-1.*MyModule.run", log) is not None
			# to check for corrent handling of async contexti when eventloop is not running in main thread
			assert re.search(r"handler for client Client-0.*handling client Client-1", log) is None


def test_observable_handler() -> None:
	class LogObserver:
		def __init__(self) -> None:
			self.messages: list[str] = []

		def messageChanged(self, handler: logging.Handler, message: Any) -> None:
			self.messages.append(message)

	assert not get_all_handlers(ObservableHandler)

	with log_stream(LOG_SECRET):
		log_observer = LogObserver()
		observable_handler.attach_observer(log_observer)
		assert get_all_handlers(ObservableHandler)
		observable_handler.attach_observer(log_observer)

		logger.error("error")
		logger.warning("warning")
		logger.info("in%s%s", "f", "o")
		assert log_observer.messages == ["error", "warning", "info"]

		observable_handler.detach_observer(log_observer)
		observable_handler.detach_observer(log_observer)
		logger.error("error2")
		assert log_observer.messages == ["error", "warning", "info"]

	assert not get_all_handlers(ObservableHandler)


def test_simple_colored() -> None:
	with log_stream(LOG_WARNING, format=MY_FORMAT) as stream:
		with log_context({"firstcontext": "asdf", "secondcontext": "jkl"}):
			logger.error("test message")
		stream.seek(0)
		log = stream.read()
		assert "asdf" in log and "jkl" in log


def test_simple_plain() -> None:
	with log_stream(LOG_WARNING, format=OTHER_FORMAT) as stream:
		with log_context({"firstcontext": "asdf", "secondcontext": "jkl"}):
			logger.error("test message")
		stream.seek(0)
		log = stream.read()
		assert "asdf" in log and "jkl" in log


def test_set_context() -> None:
	with log_stream(LOG_WARNING, format=MY_FORMAT) as stream:
		set_context({"firstcontext": "asdf", "secondcontext": "jkl"})
		logger.error("test message")
		stream.seek(0)
		log = stream.read()
		assert "asdf" in log and "jkl" in log
		stream.seek(0)
		stream.truncate()

		set_context({"firstcontext": "asdf"})
		logger.error("test message")
		stream.seek(0)
		log = stream.read()
		assert "asdf" in log and "jkl" not in log

		stream.seek(0)
		stream.truncate()
		set_context({})
		logger.error("test message")
		stream.seek(0)
		log = stream.read()
		assert "asdf" not in log

		stream.seek(0)
		stream.truncate()
		with pytest.raises(ValueError):
			set_context("suddenly a string")  # type: ignore[arg-type]
		logger.error("test message")
		stream.seek(0)
		log = stream.read()
		assert "suddenly a string" not in log  # must be given as dictionary

		set_context(None)


def test_foreign_logs() -> None:
	with log_stream(LOG_DEBUG, format="%(message)s") as stream:
		logger.error("message before request")

		requests.get("http://www.uib.de", timeout=10)

		logger.error("message after request")
		stream.seek(0)
		log = stream.read()
		assert "www.uib.de" in log


def test_filter() -> None:
	with log_stream(LOG_WARNING, format="%(message)s") as stream:
		set_filter({"testkey": ["t1", "t3"]})
		with log_context({"testkey": "t1"}):
			logger.warning("test that should appear")
		with log_context({"testkey": "t2"}):
			logger.warning("test that should not appear")
		set_filter({"testkey2": "t1"})
		with log_context({"testkey2": "t1"}):
			logger.warning("test2 that should appear")
		with log_context({"testkey2": "t2"}):
			logger.warning("test2 that should not appear")
		stream.seek(0)
		log = stream.read()
		assert "test that should appear" in log
		assert "test that should not appear" not in log
		assert "test2 that should appear" in log
		assert "test2 that should not appear" not in log

		with pytest.raises(ValueError):
			set_filter("invalid")  # type: ignore[arg-type]


def test_filter_from_string() -> None:
	with log_stream(LOG_WARNING, format="%(message)s") as stream:
		# as one string (like --log-filter "")
		set_filter_from_string("testkey = t1 , t3 ; alsotest = a1")
		with log_context({"testkey": "t1", "alsotest": "a1"}):
			logger.warning("test that should appear")
		with log_context({"testkey": "t2", "alsotest": "a1"}):
			logger.warning("test that should not appear")
		with log_context({"testkey": "t3", "alsotest": "a2"}):
			logger.warning("test that should not appear")

		# as list of strings (like --log-filter "" --log-filter "")
		set_filter_from_string(["testkey = t1 , t3", "alsotest = a1"])
		with log_context({"testkey": "t1", "alsotest": "a1"}):
			logger.warning("test that should also appear")
		with log_context({"testkey": "t2", "alsotest": "a1"}):
			logger.warning("test that should not appear")
		with log_context({"testkey": "t3", "alsotest": "a2"}):
			logger.warning("test that should not appear")

		set_filter_from_string(None)
		with log_context({"testkey": "t3", "alsotest": "a2"}):
			logger.warning("test that should appear after filter reset")

		stream.seek(0)
		log = stream.read()
		assert "test that should appear" in log
		assert "test that should also appear" in log
		assert "test that should not appear" not in log
		assert "test that should appear after filter reset" in log

		with pytest.raises(ValueError):
			set_filter_from_string({"testkey": ["t1", "t3"]})  # type: ignore[arg-type]


def test_log_devel() -> None:
	with log_stream(LOG_ERROR) as stream:
		logger.warning("warning")
		logger.devel("devel")
		logger.debug("debug")

		stream.seek(0)
		log = stream.read()
		assert "devel" in log
		assert "warning" not in log
		assert "debug" not in log


def test_multi_call_logging_config(tmp_path: Path) -> None:
	log_file = tmp_path / "opsi.log"
	logging_config(stderr_level=logging.INFO, log_file=log_file, file_level=logging.INFO, file_format="%(message)s")
	print_logger_info()
	logger.info("LINE1")
	logging_config(stderr_level=logging.INFO, log_file=log_file, file_level=logging.INFO, file_format="%(message)s")
	logger.info("LINE2")
	logging_config(stderr_level=logging.INFO, log_file=log_file, file_level=logging.ERROR, file_format="%(message)s")
	logger.info("LINE3")
	logging_config(stderr_level=logging.NONE, file_level=logging.INFO)  # type: ignore[attr-defined]
	logger.info("LINE4")
	assert log_file.read_text(encoding="utf-8") == "LINE1\nLINE2\nLINE4\n"


def test_log_warnings() -> None:
	init_warnings_capture()
	with log_stream(LOG_WARNING) as stream:
		warnings.showwarning("test warning should be logged", DeprecationWarning, "test.py", 1)
		stream.seek(0)
		log = stream.read()
		print(log)
		assert "test warning should be logged" in log


def test_sub_logger() -> None:
	sub_logger = get_logger("sub")

	with log_stream(LOG_WARNING, format="%(message)s") as stream:
		logger.warning("root_logger_1")
		sub_logger.warning("sub_logger_1")

		set_filter({"logger": ["root"]})

		logger.warning("root_logger_2")
		sub_logger.warning("sub_logger_2")

		set_filter({"logger": ["root", "sub"]})

		logger.warning("root_logger_3")
		sub_logger.warning("sub_logger_3")

		logging_config(logger_levels={"sub": LOG_ERROR})

		sub_logger.error("sub_logger_4")
		sub_logger.warning("sub_logger_5")

		levels = get_logger_levels(opsi_level=True)
		assert levels["root"] == LOG_WARNING
		assert levels["sub"] == LOG_ERROR
		for key in levels:
			if key not in ("root", "sub"):
				assert levels[key] == LOG_NOTSET

		logging_config(logger_levels={"s.*": LOG_WARNING})

		sub_logger.warning("sub_logger_6")

		stream.seek(0)
		log = stream.read()
		assert "root_logger_1" in log
		assert "sub_logger_1" in log
		assert "root_logger_2" in log
		assert "sub_logger_2" not in log
		assert "root_logger_3" in log
		assert "sub_logger_4" in log
		assert "sub_logger_5" not in log
		assert "sub_logger_6" in log

		levels = get_logger_levels(opsi_level=True)
		assert levels["root"] == LOG_WARNING
		assert levels["sub"] == LOG_WARNING
		for key in levels:
			if key not in ("root", "sub"):
				assert levels[key] == LOG_NOTSET

		levels = get_logger_levels(opsi_level=False)
		assert levels["root"] == logging.WARNING
		assert levels["sub"] == logging.WARNING
		for key in levels:
			if key not in ("root", "sub"):
				assert levels[key] == logging.NOTSET


def test_logger_name_in_context() -> None:
	sub1_logger = get_logger("sub.sub1")
	sub2_logger = get_logger("sub.sub2")
	sub3_logger = get_logger("sub.sub3")
	sub1_logger.context_name = "sub.sub1"
	sub2_logger.context_name = "Logger Sub2"
	with log_stream(LOG_WARNING, format="[%(contextstring)s] %(message)s") as stream:
		logger.warning("root_logger_1")
		sub1_logger.warning("sub_logger_1")
		sub2_logger.warning("sub_logger_2")
		sub3_logger.warning("sub_logger_3")

		stream.seek(0)
		log_lines = stream.read().strip().split("\n")
		assert log_lines == [
			"[] root_logger_1",
			"[sub.sub1] sub_logger_1",
			"[Logger Sub2] sub_logger_2",
			"[] sub_logger_3",
		]


def test_use_logging_config() -> None:
	with log_stream(LOG_WARNING, format="%(message)s") as stream:
		logger.warning("warning1")
		logger.info("info1")
		with use_logging_config(stderr_level=LOG_INFO):
			logger.warning("warning2")
			logger.info("info2")
		logger.warning("warning3")
		logger.info("info3")

		stream.seek(0)
		log = stream.read()

		assert "warning1" in log
		assert "info1" not in log
		assert "warning2" in log
		assert "info2" in log
		assert "warning3" in log
		assert "info3" not in log


def test_sqlite_handler_base(tmp_path: Path) -> None:
	log_db = Path(tmp_path) / "logs.db"
	sqlite_handler = SQLiteHandler(db_path=log_db)

	remove_all_handlers()

	logger.addHandler(sqlite_handler)
	logger.setLevel(LOG_TRACE)

	now_ms = unix_timestamp(millis=True)
	with log_context({"ctx1": "val1", "ctx2": "val2"}):
		logger.info("info message: %s %d", "arg1", 1)
	time.sleep(0.1)
	logger.debug("debug message")

	records = list(sqlite_handler.get_records())
	assert len(records) == 2

	assert now_ms <= records[0].created * 1000 <= now_ms + 1000
	assert records[0].levelno == logging.INFO
	assert getattr(records[0], "opsilevel") == LOG_INFO
	assert records[0].getMessage() == "info message: arg1 1"
	assert getattr(records[0], "context") == {"ctx1": "val1", "ctx2": "val2", "logger": "root"}

	assert now_ms <= records[1].created * 1000 <= now_ms + 1000
	assert records[1].created > records[0].created
	assert records[1].levelno == logging.DEBUG
	assert getattr(records[1], "opsilevel") == LOG_DEBUG
	assert records[1].getMessage() == "debug message"
	assert getattr(records[1], "context") == {"logger": "root"}

	sqlite_handler.delete_records(end_time=now_ms / 1000 - 10)  # delete records older than 10 seconds ago
	assert len(list(sqlite_handler.get_records())) == 2

	sqlite_handler.delete_records(end_time=now_ms / 1000 + 10)  # delete records older than 10 seconds in the future
	records = list(sqlite_handler.get_records())
	assert len(records) == 0

	# Test performance
	start_time = time.perf_counter()
	log_level = 0
	num_records = 0
	for context in ({"ctx1": "val1"}, {"ctx2": "val2"}, {"ctx1": "val1", "ctx2": "val2"}):
		with log_context(context):
			for num in range(9_000):
				log_level += 10
				if log_level > 90:
					log_level = 10
				logger.log(log_level, "trace message %d", num)
				num_records += 1

	end_time = time.perf_counter()
	duration = end_time - start_time
	print(f"Logged {num_records} trace messages in {duration:.2f} seconds ({num_records / duration:.2f} messages/second)")
	assert duration < 30.0

	start_time = time.perf_counter()
	records = list(sqlite_handler.get_records())
	end_time = time.perf_counter()
	duration = end_time - start_time
	print(f"Read {len(records)} records in {duration:.2f} seconds ({len(records) / duration:.2f} records/second)")
	assert duration < 10.0

	# Test filtering
	records = list(sqlite_handler.get_records(max_level=LOG_WARNING))
	assert len(records) == 4_000 * 3
	for record in records:
		assert getattr(record, "opsilevel") <= LOG_WARNING

	records = list(sqlite_handler.get_records(max_level=INFO))
	assert len(records) == 6_000 * 3
	for record in records:
		assert getattr(record, "opsilevel") <= LOG_INFO

	records = list(sqlite_handler.get_records(max_level=LOG_WARNING))
	assert len(records) == 4_000 * 3
	for record in records:
		assert getattr(record, "opsilevel") <= LOG_WARNING

	records = list(sqlite_handler.get_records(context={"ctx1": "val1"}))
	assert len(records) == 18_000
	expected_first_record = records[-5000]
	expected_last_record = records[-1]

	records = list(sqlite_handler.get_records(context={"ctx1": "val1"}, max_records=5_000))
	assert len(records) == 5_000
	assert records[0].getMessage() == expected_first_record.getMessage()
	assert records[-1].getMessage() == expected_last_record.getMessage()

	records = list(sqlite_handler.get_records(context={"ctx1": "val1", "ctx2": "val2"}))
	assert len(records) == 9_000
	expected_first_record = records[-5000]
	expected_last_record = records[-1]

	time.sleep(1)
	now_ms = unix_timestamp(millis=True)
	logger.info("New record")

	start_time = time.perf_counter()
	records = list(sqlite_handler.get_records(start_time=now_ms / 1000))
	end_time = time.perf_counter()
	duration = end_time - start_time
	print(f"Read {len(records)} new records in {duration:.2f} seconds")
	assert len(records) == 1

	start_time = time.perf_counter()
	records = list(sqlite_handler.get_records(start_time=now_ms / 1000, end_time=now_ms / 1000 + 1))
	end_time = time.perf_counter()
	duration = end_time - start_time
	print(f"Read {len(records)} new records in {duration:.2f} seconds")
	assert len(records) == 1

	line_regex = re.compile(r"^\[\d] \[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}\] \[.*\] .*")
	for colored in (True, False):
		for line in sqlite_handler.get_lines(colored=colored, max_records=10):
			assert ("\x1b[" in line) == colored
			if not colored:
				assert line_regex.match(line)

	sqlite_handler.delete_records(keep_number=1_000)
	records = list(sqlite_handler.get_records())
	assert len(records) == 1_000

	sqlite_handler.delete_records()
	records = list(sqlite_handler.get_records())
	assert len(records) == 0

	sqlite_handler.close()


def test_sqlite_handler_max_records(tmp_path: Path) -> None:
	log_db = Path(tmp_path) / "logs_max_records.db"
	sqlite_handler = SQLiteHandler(db_path=log_db, max_records=50, truncate_interval=1.0)

	remove_all_handlers()

	logger.addHandler(sqlite_handler)
	logger.setLevel(LOG_TRACE)

	for i in range(100):
		logger.info("info message: %d", i)

	time.sleep(2)  # Wait for truncate to happen
	records = list(sqlite_handler.get_records())
	assert len(records) == 50
	assert records[0].getMessage() == "info message: 50"
	assert records[-1].getMessage() == "info message: 99"

	sqlite_handler.close()


def test_sqlite_handler_threaded(tmp_path: Path) -> None:
	log_db = Path(tmp_path) / "logs_threaded.db"
	sqlite_handler = SQLiteHandler(db_path=log_db)

	remove_all_handlers()

	logger.addHandler(sqlite_handler)
	logger.setLevel(LOG_TRACE)

	num_threads = 10

	def log_messages(thread_id: int) -> None:
		with log_context({"thread_id": str(thread_id)}):
			for i in range(1000):
				logger.info("info message from thread %d: %d", thread_id, i)
			if i % 100 == 0:
				sqlite_handler.get_records(max_records=50)
				time.sleep(0.001)

	threads = []
	for thread_id in range(num_threads):
		thread = threading.Thread(target=log_messages, args=(thread_id,))
		threads.append(thread)

	for thread in threads:
		thread.start()

	for thread in threads:
		thread.join()

	records = list(sqlite_handler.get_records())
	assert len(records) == num_threads * 1000

	thread_message_counts = {str(i): 0 for i in range(num_threads)}
	for record in records:
		context = getattr(record, "context", {})
		thread_id = context.get("thread_id")
		if thread_id in thread_message_counts:
			thread_message_counts[thread_id] += 1

	for count in thread_message_counts.values():
		assert count == 1000

	sqlite_handler.close()


@pytest.mark.linux
def test_sqlite_handler_multiprocess(tmp_path: Path) -> None:
	log_db = Path(tmp_path) / "logs_multiprocess.db"

	sqlite_handler = SQLiteHandler(db_path=log_db)

	def log_messages(process_id: int) -> None:
		sqlite_handler = SQLiteHandler(db_path=log_db)
		with log_context({"process_id": str(process_id)}):
			for i in range(1000):
				sqlite_handler.emit(
					logger.makeRecord(
						name="root",
						level=logging.INFO,
						fn="",
						lno=0,
						msg="Info message from process %d: %d",
						args=(process_id, i),
						exc_info=None,
					)
				)
				time.sleep(0.001)
		sqlite_handler.close()

	processes = []
	num_processes = 5
	for process_id in range(num_processes):
		process = Process(target=log_messages, args=(process_id,))
		processes.append(process)
	for process in processes:
		with warnings.catch_warnings():
			warnings.simplefilter("ignore", DeprecationWarning)
			process.start()
	for process in processes:
		process.join()
	records = list(sqlite_handler.get_records())
	assert len(records) == num_processes * 1000
	sqlite_handler.close()


@pytest.mark.parametrize("max_level", [None, LOG_ERROR])
def test_sqlite_handler_follow(tmp_path: Path, max_level: int | None) -> None:
	log_db = Path(tmp_path) / "logs_follow.db"
	sqlite_handler = SQLiteHandler(db_path=log_db)

	remove_all_handlers()

	logger.addHandler(sqlite_handler)
	logger.setLevel(LOG_TRACE)
	for num in range(1, 20):
		logger.info("Info message %d", num)
		logger.error("Error message %d", num)

	def log_writer() -> None:
		for num in range(20, 40):
			logger.info("Info message %d", num)
			logger.error("Error message %d", num)
			time.sleep(0.05)

	records = []
	for record in sqlite_handler.get_records(max_records=10, max_level=max_level, follow=True):
		records.append(record)
		if record.getMessage() == "Error message 19":
			threading.Thread(target=log_writer).start()
		elif record.getMessage() == "Error message 39":
			break

	if max_level is None:
		assert len(records) == 50
	else:
		assert len(records) == 30
		for idx, record in enumerate(records):
			assert record.getMessage() == f"Error message {idx + 10}"

	sqlite_handler.close()


def test_logging_config_log_db(tmp_path: Path) -> None:
	log_db = tmp_path / "logs.db"
	logging_config(log_db=log_db, db_level=logging.INFO)
	logger.info("message")
	time.sleep(1.0)  # Wait for flush
	sqlite_handler = get_all_handlers(SQLiteHandler)[0]
	records = list(sqlite_handler.get_records())  # type: ignore[unresolved-attribute]
	assert len(records) == 1
	assert records[0].getMessage() == "message"
	sqlite_handler.close()
