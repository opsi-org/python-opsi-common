# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
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
	init_logging,
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
from opsicommon.logging.constants import LOG_DEBUG, LOG_ERROR, LOG_INFO, LOG_NOTSET, LOG_SECRET, LOG_TRACE, LOG_WARNING
from opsicommon.logging.logging import get_logger_levels, reset_logging

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


def test_log_file(tmpdir: str) -> None:
	log_file1 = tmpdir + "/log1"
	log_file2 = tmpdir + "/log2"
	log_file3 = tmpdir + "/log3"
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
		captured = capsys.readouterr()
		assert captured.err.startswith(
			"Logging error:\n"
			f"File permissions: 100444, owner: 0, group: 0\n"
			f"Process uid: {uid}, gid: {gid}\n"
			"Traceback (most recent call last):\n"
		)


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


def test_context() -> None:
	with log_stream(LOG_SECRET) as stream:
		set_format(
			stderr_format=(
				"%(log_color)s[%(opsilevel)d] [%(asctime)s.%(msecs)03d]%(reset)s "
				"[%(contextstring)s] %(message)s   (%(filename)s:%(lineno)d)"
			)
		)

		logger.info("before setting context")
		with log_context({"whoami": "first-context"}):
			logger.warning("lorem ipsum")
		with log_context({"whoami": "second-context"}):
			logger.error("dolor sit amet")
			assert context_filter.get_context() == {"logger": "root", "whoami": "second-context"}
		stream.seek(0)
		log = stream.read()
		assert "first-context" in log
		assert "second-context" in log


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
		set_context("suddenly a string")  # type: ignore[arg-type]
		logger.error("test message")
		stream.seek(0)
		log = stream.read()
		assert "suddenly a string" not in log  # must be given as dictionary

		set_context(None)  # type: ignore[arg-type]


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


def test_multi_call_init_logging(tmpdir: str) -> None:
	log_file = tmpdir.join("opsi.log")
	init_logging(stderr_level=logging.INFO, log_file=log_file, file_level=logging.INFO, file_format="%(message)s")
	print_logger_info()
	logger.info("LINE1")
	init_logging(stderr_level=logging.INFO, log_file=log_file, file_level=logging.INFO, file_format="%(message)s")
	logger.info("LINE2")
	init_logging(stderr_level=logging.INFO, log_file=log_file, file_level=logging.ERROR, file_format="%(message)s")
	logger.info("LINE3")
	init_logging(stderr_level=logging.NONE, file_level=logging.INFO)  # type: ignore[attr-defined]
	logger.info("LINE4")

	with open(log_file, encoding="utf-8") as file:
		data = file.read()
		assert data == "LINE1\nLINE2\nLINE4\n"


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
