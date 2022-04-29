# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import asyncio
import codecs
import logging
import os
import random
import re
import tempfile
import threading
import time
import warnings

import pytest
import requests

from opsicommon.logging import (
	ContextSecretFormatter,
	context_filter,
	get_logger,
	handle_log_exception,
	init_logging,
	init_warnings_capture,
	log_context,
	logger,
	logging_config,
	observable_handler,
	print_logger_info,
	secret_filter,
	set_context,
	set_filter,
	set_filter_from_string,
	set_format,
)
from opsicommon.logging.constants import (
	LOG_DEBUG,
	LOG_ERROR,
	LOG_INFO,
	LOG_SECRET,
	LOG_TRACE,
	LOG_WARNING,
)

from .helpers import log_stream

MY_FORMAT = "%(log_color)s[%(opsilevel)d] [%(asctime)s.%(msecs)03d]%(reset)s [%(contextstring)s] %(message)s"
OTHER_FORMAT = "[%(opsilevel)d] [%(asctime)s.%(msecs)03d] [%(contextstring)s] %(message)s   (%(filename)s:%(lineno)d)"


def test_levels():  # pylint: disable=redefined-outer-name
	with log_stream(LOG_SECRET, format="%(message)s") as stream:
		expected = ""
		print_logger_info()
		for level in ("secret", "confidential", "trace", "debug2", "debug", "info", "notice", "warning", "error", "critical", "comment"):
			func = getattr(logger, level)
			msg = f"logline {level}"
			func(msg)
			expected += f"{msg}\n"

		stream.seek(0)
		assert expected in stream.read()


def test_log_file(tmpdir):
	log_file1 = tmpdir + "/log1"
	log_file2 = tmpdir + "/log2"
	log_file3 = tmpdir + "/log3"
	logger.addHandler(logging.FileHandler(log_file1))
	logging_config(log_file=log_file2, file_level=logging.INFO, file_format="%(message)s", remove_handlers=False)
	logger.warning("message")
	with open(log_file1, "r", encoding="utf-8") as file:
		assert file.read().strip() == "message"
	with open(log_file2, "r", encoding="utf-8") as file:
		assert file.read().strip() == "message"

	logger.addHandler(logging.FileHandler(log_file3))
	logging_config(log_file=log_file2, file_level=logging.INFO, file_format="%(message)s", remove_handlers=True)
	logger.warning("message2")
	assert not os.path.exists(log_file3) or os.path.getsize(log_file3) == 0
	with open(log_file2, "r", encoding="utf-8") as file:
		assert "message2" in file.read()

	logging_config(log_file=None, remove_handlers=True)


def test_log_exception_handler():
	log_record = logging.LogRecord(name=None, level=logging.ERROR, pathname=None, lineno=1, msg="t", args=None, exc_info=None)

	filename = os.path.join(tempfile.gettempdir(), f"log_exception_{os.getpid()}.txt")
	if os.path.exists(filename):
		os.remove(filename)
	try:
		raise Exception("TESTäöüß")
	except Exception as err:  # pylint: disable=broad-except
		handle_log_exception(exc=err, record=log_record, log=True, temp_file=True, stderr=True)
		with codecs.open(filename, "r", "utf-8") as file:
			data = file.read()
			assert "TESTäöüß" in data
			assert "'levelname': 'ERROR'" in data


def test_secret_formatter_attr():
	log_record = logging.LogRecord(name=None, level=logging.ERROR, pathname=None, lineno=1, msg="t", args=None, exc_info=None)
	csf = ContextSecretFormatter(logging.Formatter())
	csf.format(log_record)


def test_secret_filter():  # pylint: disable=redefined-outer-name
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

	secret_filter.clear_secrets()
	secret_filter.add_secrets("SECRETSTRING1")
	with log_stream(LOG_SECRET) as stream:
		logger.info("SECRETSTRING1")
		stream.seek(0)
		log = stream.read()
		assert "SECRETSTRING1" in log


def test_context():  # pylint: disable=redefined-outer-name
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


def test_context_threads():  # pylint: disable=redefined-outer-name
	def common_work():
		time.sleep(0.2)
		logger.info("common_work")
		time.sleep(0.2)

	class Main:  # pylint: disable=too-few-public-methods
		def run(self):  # pylint: disable=no-self-use
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
		def __init__(self):
			super().__init__()
			self._should_stop = False

		def stop(self):
			self._should_stop = True

		def run(self):
			loop = asyncio.new_event_loop()
			loop.run_until_complete(self.arun())
			loop.close()

		async def handle_client(self, client: str):  # pylint: disable=no-self-use
			with log_context({"whoami": "handler for " + str(client)}):
				logger.essential("handling client %s", client)
				seconds = random.random() * 1
				await asyncio.sleep(seconds)
				logger.essential("client %s handled after %0.3f seconds", client, seconds)

		async def arun(self):
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

		def run(self):
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
					_thread.stop()
					_thread.join()

			stream.seek(0)
			log = stream.read()
			assert re.search(r"module Client-1.*MyModule.run", log) is not None
			# to check for corrent handling of async contexti when eventloop is not running in main thread
			assert re.search(r"handler for client Client-0.*handling client Client-1", log) is None


def test_observable_handler():  # pylint: disable=redefined-outer-name
	class LogObserver:  # pylint: disable=too-few-public-methods
		def __init__(self):
			self.messages = []

		def messageChanged(self, handler, message):  # pylint: disable=unused-argument,invalid-name
			self.messages.append(message)

	with log_stream(LOG_SECRET):
		log_observer = LogObserver()
		observable_handler.attach_observer(log_observer)
		observable_handler.attach_observer(log_observer)
		logger.error("error")
		logger.warning("warning")
		logger.info("in%s%s", "f", "o")
		assert log_observer.messages == ["error", "warning", "info"]

		observable_handler.detach_observer(log_observer)
		observable_handler.detach_observer(log_observer)
		logger.error("error2")
		assert log_observer.messages == ["error", "warning", "info"]


def test_simple_colored():  # pylint: disable=redefined-outer-name
	with log_stream(LOG_WARNING, format=MY_FORMAT) as stream:
		with log_context({"firstcontext": "asdf", "secondcontext": "jkl"}):
			logger.error("test message")
		stream.seek(0)
		log = stream.read()
		assert "asdf" in log and "jkl" in log


def test_simple_plain():  # pylint: disable=redefined-outer-name
	with log_stream(LOG_WARNING, format=OTHER_FORMAT) as stream:
		with log_context({"firstcontext": "asdf", "secondcontext": "jkl"}):
			logger.error("test message")
		stream.seek(0)
		log = stream.read()
		assert "asdf" in log and "jkl" in log


def test_set_context():  # pylint: disable=redefined-outer-name
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
		set_context("suddenly a string")
		logger.error("test message")
		stream.seek(0)
		log = stream.read()
		assert "suddenly a string" not in log  # must be given as dictionary

		set_context(None)


def test_foreign_logs():  # pylint: disable=redefined-outer-name
	with log_stream(LOG_DEBUG, format="%(message)s") as stream:
		logger.error("message before request")

		requests.get("http://www.uib.de")

		logger.error("message after request")
		stream.seek(0)
		log = stream.read()
		assert "www.uib.de" in log


def test_filter():  # pylint: disable=redefined-outer-name
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
			set_filter("invalid")


def test_filter_from_string():  # pylint: disable=redefined-outer-name
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
			set_filter_from_string({"testkey": ["t1", "t3"]})


def test_log_devel():  # pylint: disable=redefined-outer-name
	with log_stream(LOG_ERROR) as stream:
		logger.warning("warning")
		logger.devel("devel")
		logger.debug("debug")

		stream.seek(0)
		log = stream.read()
		assert "devel" in log
		assert "warning" not in log
		assert "debug" not in log


def test_multi_call_init_logging(tmpdir):
	log_file = tmpdir.join("opsi.log")
	init_logging(stderr_level=logging.INFO, log_file=log_file, file_level=logging.INFO, file_format="%(message)s")
	print_logger_info()
	logger.info("LINE1")
	init_logging(stderr_level=logging.INFO, log_file=log_file, file_level=logging.INFO, file_format="%(message)s")
	logger.info("LINE2")
	init_logging(stderr_level=logging.INFO, log_file=log_file, file_level=logging.ERROR, file_format="%(message)s")
	logger.info("LINE3")
	init_logging(stderr_level=logging.NONE, file_level=logging.INFO)
	logger.info("LINE4")

	with open(log_file, encoding="utf-8") as file:
		data = file.read()
		assert data == "LINE1\nLINE2\nLINE4\n"


def test_log_warnings():
	init_warnings_capture()
	with log_stream(LOG_WARNING) as stream:
		warnings.showwarning("test warning should be logged", DeprecationWarning, "test.py", 1)
		stream.seek(0)
		log = stream.read()
		print(log)
		assert "test warning should be logged" in log


def test_sub_logger():  # pylint: disable=redefined-outer-name
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

		stream.seek(0)
		log = stream.read()
		assert "root_logger_1" in log
		assert "sub_logger_1" in log
		assert "root_logger_2" in log
		assert "sub_logger_2" not in log
		assert "root_logger_3" in log
		assert "sub_logger_4" in log
		assert "sub_logger_5" not in log
