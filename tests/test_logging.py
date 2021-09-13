# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import os
import io
import re
import time
import codecs
import logging
import threading
import asyncio
import random
import requests
from contextlib import contextmanager
import pytest
import tempfile

from opsicommon.logging import (
	logger, handle_log_exception, secret_filter, observable_handler,
	ContextSecretFormatter, log_context, set_format,
	init_logging, print_logger_info, set_filter, set_context,
	set_filter_from_string, logging_config

)
from opsicommon.logging.constants import (
	LOG_SECRET, LOG_WARNING, LOG_ERROR, LOG_DEBUG, LOG_TRACE, LOG_INFO,
	OPSI_LEVEL_TO_LEVEL
)

try:
	from OPSI.Logger import Logger as LegacyLogger
except ImportError:
	LegacyLogger = None

MY_FORMAT = "%(log_color)s[%(opsilevel)d] [%(asctime)s.%(msecs)03d]%(reset)s [%(contextstring)s] %(message)s"
OTHER_FORMAT = "[%(opsilevel)d] [%(asctime)s.%(msecs)03d] [%(contextstring)s] %(message)s   (%(filename)s:%(lineno)d)"


class Utils:
	@staticmethod
	@contextmanager
	def log_stream(new_level, format=None):
		stream = io.StringIO()
		logging_config(stderr_level=new_level, stderr_format=format, stderr_file=stream)
		try:
			yield stream
		finally:
			pass	#somehow revert to previous values? Impossible as logging_config deletes all stream handlers

@pytest.fixture
def utils():
	return Utils

def test_levels(utils):
	with utils.log_stream(LOG_SECRET, format="%(message)s") as stream:
		expected = ""
		print_logger_info()
		for level in (
			"secret", "confidential", "trace", "debug2", "debug",
			"info", "notice", "warning", "error", "critical", "comment"
		):
			func = getattr(logger, level)
			msg = f"logline {level}"
			func(msg)
			expected += f"{msg}\n"

		stream.seek(0)
		assert expected in stream.read()

def test_log_exception_handler():
	log_record = logging.LogRecord(name=None, level=logging.ERROR, pathname=None, lineno=1, msg="t", args=None, exc_info=None)

	filename = os.path.join(tempfile.gettempdir(), f"log_exception_{os.getpid()}.txt")
	if os.path.exists(filename):
		os.remove(filename)
	try:
		raise Exception("TESTäöüß")
	except Exception as err:
		handle_log_exception(exc=err, record=log_record, log=True, temp_file=True, stderr=True)
		with codecs.open(filename, "r", "utf-8") as file:
			data = file.read()
			assert "TESTäöüß" in data
			assert "'levelname': 'ERROR'" in data

def test_secret_formatter_attr():
	log_record = logging.LogRecord(name=None, level=logging.ERROR, pathname=None, lineno=1, msg="t", args=None, exc_info=None)
	sf = ContextSecretFormatter(logging.Formatter())
	sf.format(log_record)

def test_secret_filter(utils):
	secret_filter.set_min_length(7)
	secret_filter.add_secrets("PASSWORD", "2SHORT", "SECRETSTRING")

	with utils.log_stream(LOG_TRACE, format="[%(asctime)s.%(msecs)03d] %(message)s") as stream:
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

	with utils.log_stream(LOG_SECRET, format="[%(asctime)s.%(msecs)03d] %(message)s") as stream:
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
	with utils.log_stream(LOG_INFO) as stream:
		logger.info("SECRETSTRING1 SECRETSTRING2 SECRETSTRING3")

		stream.seek(0)
		log = stream.read()
		assert "SECRETSTRING1" not in log
		assert "SECRETSTRING2" in log
		assert "SECRETSTRING3" not in log


@pytest.mark.skipif(not LegacyLogger, reason="OPSI.Logger not available.")
def test_legacy_logger_file(utils):
	with utils.log_stream(LOG_SECRET) as stream:
		legacy_logger = LegacyLogger("/tmp/test.log")
		assert legacy_logger == logger
		legacy_logger.info("test should appear")

		stream.seek(0)
		log = stream.read()
		assert "test should appear" in log

	with open("/tmp/test.log") as logfile:
		content = logfile.read()
		assert "test should appear" in content

def test_context(utils):
	with utils.log_stream(LOG_SECRET) as stream:
		set_format(stderr_format="%(log_color)s[%(opsilevel)d] [%(asctime)s.%(msecs)03d]%(reset)s [%(contextstring)s] %(message)s   (%(filename)s:%(lineno)d)")

		logger.info("before setting context")
		with log_context({'whoami' : "first-context"}):
			logger.warning("lorem ipsum")
		with log_context({'whoami' : "second-context"}):
			logger.error("dolor sit amet")
		stream.seek(0)
		log = stream.read()
		assert "first-context" in log
		assert "second-context" in log


def test_context_threads(utils):
	def common_work():
		time.sleep(0.2)
		logger.info("common_work")
		time.sleep(0.2)

	class Main():
		def run(self):
			AsyncMain().start()
			for _ in range(5):		#perform 5 iterations
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

		async def handle_client(self, client: str):
			with log_context({'whoami' : "handler for " + str(client)}):
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
			with log_context({'whoami' : "module " + str(self.client)}):
				logger.essential("MyModule.run")
				common_work()

	with log_context({'whoami' : "MAIN"}):
		with utils.log_stream(LOG_INFO, format="%(contextstring)s %(message)s") as stream:
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

def test_observable_handler(utils):
	class LogObserver():
		def __init__(self):
			self.messages = []

		def messageChanged(self, handler, message):
			self.messages.append(message)

	with utils.log_stream(LOG_SECRET):
		lo = LogObserver()
		observable_handler.attach_observer(lo)
		logger.error("error")
		logger.warning("warning")
		logger.info("in%s%s", "f", "o")
		assert lo.messages == ["error", "warning", "info"]


@pytest.mark.skipif(not LegacyLogger, reason="OPSI.Logger not available.")
def test_legacy_logger(utils):
	with utils.log_stream(LOG_TRACE) as stream:
		legacy_logger = LegacyLogger()
		assert legacy_logger == logger
		#init_logging(file_level=logging.SECRET)
		#legacy_logger.setLogFile("/tmp/test.log")
		# This method does nothing
		legacy_logger.setLogFormat("xy")

		secret_filter.set_min_length(7)
		legacy_logger.setConfidentialStrings(["SECRETSTRING1", "SECRETSTRING2"])
		legacy_logger.addConfidentialString("SECRETSTRING3")
		legacy_logger.info("SECRETSTRING1 SECRETSTRING2 SECRETSTRING3")

		stream.seek(0)
		log = stream.read()
		assert "SECRETSTRING1" not in log
		assert "SECRETSTRING2" not in log
		assert "SECRETSTRING3" not in log

		legacy_logger.logException(Exception("LOG_EXCEPTION"), logLevel=logging.CRITICAL)
		stream.seek(0)
		log = stream.read()
		assert "LOG_EXCEPTION" in log

@pytest.mark.skipif(not LegacyLogger, reason="OPSI.Logger not available.")
def test_legacy_logger_calls(utils):
	legacy_logger = LegacyLogger()
	assert legacy_logger == logger
	legacy_logger.getStderr()
	legacy_logger.getStdout()
	legacy_logger.setConfidentialStrings(["topsecret"])
	legacy_logger.addConfidentialString("evenmoresecret")
	legacy_logger.setLogFormat("%s some format %s", currentThread=False, object=None)
	legacy_logger.setConsoleFormat("%s some format %s", currentThread=False, object=None)
	legacy_logger.setComponentName("name", currentThread=False, object=None)
	legacy_logger.logToStdout(None)
	legacy_logger.setSyslogFormat("%s some format %s", currentThread=False, object=None)
	legacy_logger.setFileFormat("%s some format %s", currentThread=False, object=None)
	legacy_logger.setUniventionFormat("%s some format %s", currentThread=False, object=None)
	legacy_logger.setMessageSubjectFormat("%s some format %s", currentThread=False, object=None)
	legacy_logger.setUniventionLogger(None)
	legacy_logger.setUniventionClass(None)
	legacy_logger.getMessageSubject()
	legacy_logger.setColor(True)
	legacy_logger.setConsoleColor(True)
	legacy_logger.setSyslogLevel(0)
	legacy_logger.setMessageSubjectLevel(0)
	legacy_logger.setConsoleLevel(0)
	legacy_logger.getConsoleLevel()
	legacy_logger.getFileLevel()
	legacy_logger.getLogFile(currentThread=False, object=None)
	legacy_logger.setLogFile("logfile.log", currentThread=False, object=None)
	legacy_logger.linkLogFile("logfile", currentThread=False, object=None)
	legacy_logger.setFileLevel(0)
	legacy_logger.exit(object=None)
	legacy_logger._setThreadConfig(None, None)
	legacy_logger._getThreadConfig(key=None)
	legacy_logger._setObjectConfig(None, None, None)
	legacy_logger._getObjectConfig(None, key=None)
	legacy_logger.logException(None)
	legacy_logger.logFailure(None)
	legacy_logger.logTraceback(None)
	legacy_logger.logWarnings()
	legacy_logger.startTwistedLogging()
	legacy_logger.setConsoleLevel(9)

	with utils.log_stream(LOG_SECRET) as stream:
		legacy_logger.confidential("mymessage %s", "fill-value")
		legacy_logger.debug3("mymessage %s", "fill-value")
		legacy_logger.debug2("mymessage %s", "fill-value")
		legacy_logger.debug("mymessage %s", "fill-value")
		legacy_logger.info("mymessage %s", "fill-value")
		legacy_logger.msg("mymessage %s", "fill-value")
		legacy_logger.notice("mymessage %s", "fill-value")
		legacy_logger.warning("mymessage %s", "fill-value")
		legacy_logger.error("mymessage %s", "fill-value")
		legacy_logger.err("mymessage %s", "fill-value")
		legacy_logger.critical("mymessage %s", "fill-value")
		legacy_logger.essential("mymessage %s", "fill-value")
		legacy_logger.comment("mymessage %s", "fill-value")
		# calling log still fails as method signature has changed with opsi 4.2
		#legacy_logger.log(3, "text %s", raiseException=False, formatArgs=["some format arg"], formatKwargs={})
		stream.seek(0)
		log = stream.read()
		assert log.count("fill-value") == 13


def test_simple_colored(utils):
	with utils.log_stream(LOG_WARNING, format=MY_FORMAT) as stream:
		with log_context({'firstcontext' : 'asdf', 'secondcontext' : 'jkl'}):
			logger.error("test message")
		stream.seek(0)
		log = stream.read()
		assert "asdf" in log and "jkl" in log

def test_simple_plain(utils):
	with utils.log_stream(LOG_WARNING, format=OTHER_FORMAT) as stream:
		with log_context({'firstcontext' : 'asdf', 'secondcontext' : 'jkl'}):
			logger.error("test message")
		stream.seek(0)
		log = stream.read()
		assert "asdf" in log and "jkl" in log

def test_set_context(utils):
	with utils.log_stream(LOG_WARNING, format=MY_FORMAT) as stream:
		set_context({'firstcontext' : 'asdf', 'secondcontext' : 'jkl'})
		logger.error("test message")
		stream.seek(0)
		log = stream.read()
		assert "asdf" in log and "jkl" in log
		stream.seek(0)
		stream.truncate()

		set_context({'firstcontext' : 'asdf'})
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
		assert "suddenly a string" not in log	# must be given as dictionary

def test_foreign_logs(utils):
	with utils.log_stream(LOG_DEBUG, format="%(message)s") as stream:
		logger.error("message before request")

		requests.get("http://www.uib.de")

		logger.error("message after request")
		stream.seek(0)
		log = stream.read()
		assert "www.uib.de" in log

def test_filter(utils):
	with utils.log_stream(LOG_WARNING, format="%(message)s") as stream:
		set_filter({"testkey" : ["t1", "t3"]})
		with log_context({"testkey" : "t1"}):
			logger.warning("test that should appear")
		with log_context({"testkey" : "t2"}):
			logger.warning("test that should not appear")
		stream.seek(0)
		log = stream.read()
		assert "test that should appear" in log
		assert "test that should not appear" not in log

def test_filter_from_string(utils):
	with utils.log_stream(LOG_WARNING, format="%(message)s") as stream:
		# as one string (like --log-filter "")
		set_filter_from_string("testkey = t1 , t3 ; alsotest = a1")
		with log_context({"testkey" : "t1", "alsotest" : "a1"}):
			logger.warning("test that should appear")
		with log_context({"testkey" : "t2", "alsotest" : "a1"}):
			logger.warning("test that should not appear")
		with log_context({"testkey" : "t3", "alsotest" : "a2"}):
			logger.warning("test that should not appear")

		# as list of strings (like --log-filter "" --log-filter "")
		set_filter_from_string(["testkey = t1 , t3", "alsotest = a1"])
		with log_context({"testkey" : "t1", "alsotest" : "a1"}):
			logger.warning("test that should also appear")
		with log_context({"testkey" : "t2", "alsotest" : "a1"}):
			logger.warning("test that should not appear")
		with log_context({"testkey" : "t3", "alsotest" : "a2"}):
			logger.warning("test that should not appear")

		stream.seek(0)
		log = stream.read()
		set_filter(None)
		assert "test that should appear" in log
		assert "test that should also appear" in log
		assert "test that should not appear" not in log

def test_log_devel(utils):
	with utils.log_stream(LOG_ERROR) as stream:
		logger.warning("warning")
		logger.devel("devel")
		logger.debug("debug")

		stream.seek(0)
		log = stream.read()
		assert "devel" in log
		assert "warning" not in log
		assert "debug" not in log

def test_multi_call_init_logging(tmpdir, utils):
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

	with open(log_file) as f:
		data = f.read()
		assert data == "LINE1\nLINE2\nLINE4\n"
