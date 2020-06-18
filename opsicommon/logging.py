# -*- coding: utf-8 -*-
"""
:copyright: uib GmbH <info@uib.de>
This file is part of opsi - https://www.opsi.org

:license: GNU Affero General Public License version 3
"""

import traceback
import time
import sys
import os
import logging
import colorlog

from logging import LogRecord, Formatter, StreamHandler, Filter
from logging.handlers import WatchedFileHandler, RotatingFileHandler

from .utils import Singleton

DEFAULT_FORMAT = "%(log_color)s[%(opsilevel)d] [%(asctime)s.%(msecs)03d]%(reset)s %(message)s   (%(filename)s:%(lineno)d)"
DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"
SECRET_REPLACEMENT_STRING = '***secret***'

logger = logging.getLogger()

logging.NONE = 0
logging.NOTSET = logging.NONE
logging.SECRET = 10
logging.CONFIDENTIAL = logging.SECRET
logging.TRACE = 20
logging.DEBUG2 = logging.TRACE
logging.DEBUG = 30
logging.INFO = 40
logging.NOTICE = 50
logging.WARNING = 60
logging.WARN = logging.WARNING
logging.ERROR = 70
logging.CRITICAL = 80
logging.ESSENTIAL = 90
logging.COMMENT = logging.ESSENTIAL

logging._levelToName = {
	logging.SECRET: 'SECRET',
	logging.TRACE: 'TRACE',
	logging.DEBUG: 'DEBUG',
	logging.INFO: 'INFO',
	logging.NOTICE: 'NOTICE',
	logging.WARNING: 'WARNING',
	logging.ERROR: 'ERROR',
	logging.CRITICAL: 'CRITICAL',
	logging.ESSENTIAL: 'ESSENTIAL',
	logging.NONE: 'NONE'
}

logging._nameToLevel = {
	'SECRET': logging.SECRET,
	'TRACE': logging.TRACE,
	'DEBUG': logging.DEBUG,
	'INFO': logging.INFO,
	'NOTICE': logging.NOTICE,
	'WARNING': logging.WARNING,
	'ERROR': logging.ERROR,
	'CRITICAL': logging.CRITICAL,
	'ESSENTIAL': logging.ESSENTIAL,
	'NONE': logging.NONE
}

logging._levelToOpsiLevel = {
	logging.SECRET: 9,
	logging.TRACE: 8,
	logging.DEBUG: 7,
	logging.INFO: 6,
	logging.NOTICE: 5,
	logging.WARNING: 4,
	logging.ERROR: 3,
	logging.CRITICAL: 2,
	logging.ESSENTIAL: 1,
	logging.NONE: 0
}

logging._opsiLevelToLevel = {
	9: logging.SECRET,
	8: logging.TRACE,
	7: logging.DEBUG,
	6: logging.INFO,
	5: logging.NOTICE,
	4: logging.WARNING,
	3: logging.ERROR,
	2: logging.CRITICAL,
	1: logging.ESSENTIAL,
	0: logging.NONE
}

LOG_COLORS = {
	'SECRET': 'thin_yellow',
	'TRACE': 'thin_white',
	'DEBUG': 'white',
	'INFO': 'bold_white',
	'NOTICE': 'bold_green',
	'WARNING': 'bold_yellow',
	'ERROR': 'red',
	'CRITICAL': 'bold_red',
	'ESSENTIAL': 'bold_cyan'
}

def secret(self, msg, *args, **kwargs):
	if self.isEnabledFor(logging.SECRET):
		self._log(logging.SECRET, msg, args, **kwargs)
logging.Logger.secret = secret
logging.Logger.confidential = secret

def trace(self, msg, *args, **kwargs):
	if self.isEnabledFor(logging.TRACE):
		self._log(logging.TRACE, msg, args, **kwargs)
logging.Logger.trace = trace
logging.Logger.debug2 = trace

def notice(self, msg, *args, **kwargs):
	if self.isEnabledFor(logging.NOTICE):
		self._log(logging.NOTICE, msg, args, **kwargs)
logging.Logger.notice = notice

def essential(self, msg, *args, **kwargs):
	if self.isEnabledFor(logging.ESSENTIAL):
		self._log(logging.ESSENTIAL, msg, args, **kwargs)
logging.Logger.essential = essential
logging.Logger.comment = essential

def logrecord_init(self, name, level, pathname, lineno, msg, args, exc_info, func=None, sinfo=None, **kwargs):
	self.__init_orig__(name, level, pathname, lineno, msg, args, exc_info, func=func, sinfo=sinfo, **kwargs)
	self.opsilevel = logging._levelToOpsiLevel.get(level, level)

LogRecord.__init_orig__ = LogRecord.__init__
LogRecord.__init__ = logrecord_init

try:
	# Replace OPSI Logger
	import OPSI.Logger
	def opsi_logger_factory():
		return logger
	OPSI.Logger.Logger = opsi_logger_factory

	def setLogFile(logFile, currentThread=False, object=None):
		pass
	logger.setLogFile = setLogFile

	def setLogFormat(logFormat):
		pass
	logger.setLogFormat = setLogFormat

	def setConfidentialStrings(strings):
		secret_filter.clear_secrets()
		secret_filter.add_secrets(*strings)
	logger.setConfidentialStrings = setConfidentialStrings

	def addConfidentialString(string):
		secret_filter.add_secrets(string)
	logger.addConfidentialString = addConfidentialString

	def logException(e, logLevel=logging.CRITICAL):
		logger.log(level=logLevel, msg=e, exc_info=True)
	logger.logException = logException
except ImportError:
	pass


def handle_log_exception(exc: Exception, record: logging.LogRecord = None, log: bool = True):
	print("Logging error:", file=sys.stderr)
	traceback.print_exc(file=sys.stderr)
	if not log:
		return
	try:
		logger.error(f"Logging error: {exc}", exc_info=True)
		if record:
			logger.error(record.__dict__)
			#logger.error(f"{record.msg} - {record.args}")
	except:
		pass


class SecretFormatter(object):
	def __init__(self, orig_formatter: Formatter):
		if orig_formatter is None:
			orig_formatter = Formatter()
		self.orig_formatter = orig_formatter
	
	def format(self, record: LogRecord):
		msg = self.orig_formatter.format(record)
		if record.levelno != logging.SECRET:
			for secret in secret_filter.secrets:
				msg = msg.replace(secret, SECRET_REPLACEMENT_STRING)
		return msg
	
	def __getattr__(self, attr):
		return getattr(self.orig_formatter, attr)

class SecretFilter(metaclass=Singleton):
	def __init__(self, min_length: int = 6):
		self._min_length = min_length
		self.secrets = []

	def _initialize_handlers(self):
		for handler in logging.root.handlers:
			if not isinstance(handler.formatter, SecretFormatter):
				handler.formatter = SecretFormatter(handler.formatter)
	
	def set_min_length(self, min_length: int):
		self._min_length = min_length
	
	def clear_secrets(self):
		self.secrets = []
	
	def add_secrets(self, *secrets: str):
		self._initialize_handlers()
		for secret in secrets:
			if secret and len(secret) >= self._min_length and not secret in self.secrets:
				self.secrets.append(secret)
	
	def remove_secrets(self, *secrets: str):
		for secret in secrets:
			if secret in self.secrets:
				self.secrets.remove(secret)

secret_filter = SecretFilter()
