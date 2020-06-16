# -*- coding: utf-8 -*-
"""
:copyright: uib GmbH <info@uib.de>
This file is part of opsi - https://www.opsi.org

:license: GNU Affero General Public License version 3
"""

import io
import pytest
import logging

from opsicommon.logging import logger, handle_log_exception, secret_filter, SecretFormatter

try:
	from OPSI.Logger import Logger as LegacyLogger
except ImportError:
	LegacyLogger = None

@pytest.fixture
def log_stream_handler():
	stream = io.StringIO()
	handler = logging.StreamHandler(stream)
	return (handler, stream)

def test_levels(log_stream_handler):
	(handler, stream) = log_stream_handler
	logger.addHandler(handler)
	handler.setLevel(logging.SECRET)
	logger.setLevel(logging.SECRET)
	expected = ""
	for level in (
		"secret", "confidential", "trace", "debug2", "debug",
		"info", "notice", "warning", "error", "critical", "comment"
	):
		func = getattr(logger, level)
		msg = f"logline {level}"
		func(msg)
		expected += f"{msg}\n"
	
	stream.seek(0)
	assert stream.read() == expected

def test_log_exception_handler():
	log_record = logging.LogRecord(name=None, level=logging.ERROR, pathname=None, lineno=1, msg="t", args=None, exc_info=None)
	handle_log_exception(exc=Exception(), record=log_record, log=True)
	handle_log_exception(exc=Exception(), record=None, log=False)

def test_secret_formatter_attr():
	log_record = logging.LogRecord(name=None, level=logging.ERROR, pathname=None, lineno=1, msg="t", args=None, exc_info=None)
	sf = SecretFormatter(logging.Formatter())
	sf.format(log_record)

def test_secret_filter(log_stream_handler):
	(handler, stream) = log_stream_handler
	logger.addHandler(handler)
	handler.setLevel(logging.SECRET)
	logger.setLevel(logging.SECRET)

	secret_filter.set_min_length(7)	
	secret_filter.add_secrets("PASSWORD", "2SHORT", "SECRETSTRING")
	logger.info("line 1")
	logger.info("line 2 PASSWORD")
	logger.info("line 3 2SHORT")
	logger.secret("line 4 SECRETSTRING")
	stream.seek(0)
	log = stream.read()
	assert "line 1\n" in log
	assert "line 2 PASSWORD\n" not in log
	assert "line 3 2SHORT\n" in log
	assert "line 4 SECRETSTRING\n" in log

	secret_filter.clear_secrets()
	logger.info("line 5 PASSWORD")
	stream.seek(0)
	log = stream.read()
	assert "line 5 PASSWORD\n" in log

	stream.seek(0)
	stream.truncate()
	secret_filter.add_secrets("SECRETSTRING1", "SECRETSTRING2", "SECRETSTRING3")
	secret_filter.remove_secrets("SECRETSTRING2")
	logger.info("SECRETSTRING1 SECRETSTRING2 SECRETSTRING3")
	stream.seek(0)
	log = stream.read()
	assert "SECRETSTRING1" not in log
	assert "SECRETSTRING2" in log
	assert "SECRETSTRING3" not in log



@pytest.mark.skipif(not LegacyLogger, reason="OPSI.Logger not available.")
def test_legacy_logger(log_stream_handler):
	(handler, stream) = log_stream_handler
	logger.addHandler(handler)
	handler.setLevel(logging.SECRET)
	logger.setLevel(logging.SECRET)

	legacy_logger = LegacyLogger()
	assert legacy_logger == logger
	# This method does nothing
	legacy_logger.setLogFile("/tmp/test.log")
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
