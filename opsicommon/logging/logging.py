# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
logging
"""

from __future__ import annotations

import codecs
import contextvars
import logging
import os
import re
import sys
import tempfile
import warnings
from contextlib import contextmanager
from logging import (
	NOTSET,
	FileHandler,
	Formatter,
	Handler,
	LogRecord,
	NullHandler,
	PlaceHolder,
	StreamHandler,
)
from logging.handlers import RotatingFileHandler
from traceback import format_stack, format_tb
from typing import IO, Any, Generator
from urllib.parse import quote

from colorlog import ColoredFormatter
from rich.console import Console

from .constants import (
	DATETIME_FORMAT,
	DEFAULT_COLORED_FORMAT,
	DEFAULT_FORMAT,
	ESSENTIAL,
	LOG_COLORS,
	NONE,
	NOTICE,
	OPSI_LEVEL_TO_LEVEL,
	SECRET,
	SECRET_REPLACEMENT_STRING,
	TRACE,
)

context: contextvars.ContextVar[dict[str, Any]] = contextvars.ContextVar("context", default={})


class OPSILogger(logging.Logger):
	def __init__(self, name: str, level: int | str = NOTSET) -> None:  # pylint: disable=useless-super-delegation
		super().__init__(name, level)

	def secret(self, msg: Any, *args: Any, **kwargs: Any) -> None:
		"""
		Logging with level SECRET.

		This method calls a log with level SECRET.

		:param msg: Message to log (may contain %-style placeholders).
		:param *args: Arguments to fill %-style placeholders with.
		:param **kwargs: Additional keyword-arguments.
		"""
		if self.isEnabledFor(SECRET):
			self._log(SECRET, msg, args, **kwargs)

	confidential = secret

	def trace(self, msg: Any, *args: Any, **kwargs: Any) -> None:
		"""
		Logging with level TRACE.

		This method calls a log with level TRACE.

		:param msg: Message to log (may contain %-style placeholders).
		:param *args: Arguments to fill %-style placeholders with.
		:param **kwargs: Additional keyword-arguments.
		"""
		if self.isEnabledFor(TRACE):
			self._log(TRACE, msg, args, **kwargs)

	debug2 = trace

	def notice(self, msg: Any, *args: Any, **kwargs: Any) -> None:
		"""
		Logging with level NOTICE.

		This method calls a log with level NOTICE.

		:param msg: Message to log (may contain %-style placeholders).
		:param *args: Arguments to fill %-style placeholders with.
		:param **kwargs: Additional keyword-arguments.
		"""
		if self.isEnabledFor(NOTICE):
			self._log(NOTICE, msg, args, **kwargs)

	def essential(self, msg: Any, *args: Any, **kwargs: Any) -> None:
		"""
		Logging with level ESSENTIAL.

		This method calls a log with level ESSENTIAL.

		:param msg: Message to log (may contain %-style placeholders).
		:param *args: Arguments to fill %-style placeholders with.
		:param **kwargs: Additional keyword-arguments.
		"""
		if self.isEnabledFor(ESSENTIAL):
			self._log(ESSENTIAL, msg, args, **kwargs)

	comment = essential
	devel = essential

	def findCaller(  # pylint: disable=invalid-name
		self, stack_info: bool = False, stacklevel: int = 1  # pylint: disable=unused-argument
	) -> tuple[str, int, str, None]:
		"""
		Find the stack frame of the caller so that we can note the source
		file name, line number and function name.
		"""
		frame = sys._getframe(1)  # pylint: disable=protected-access
		try:
			while frame:
				if frame.f_code.co_name == "_log":
					caller = frame.f_back.f_back  # type: ignore[union-attr]
					code = caller.f_code  # type: ignore[union-attr]
					return code.co_filename, caller.f_lineno, code.co_name, None  # type: ignore[union-attr]
				frame = frame.f_back  # type: ignore[assignment]
		except AttributeError:
			pass
		raise ValueError("Failed to find caller")


logging.Logger.secret = OPSILogger.secret  # type: ignore[attr-defined]
logging.Logger.confidential = OPSILogger.confidential  # type: ignore[attr-defined]
logging.Logger.trace = OPSILogger.trace  # type: ignore[attr-defined]
logging.Logger.debug2 = OPSILogger.debug2  # type: ignore[attr-defined]
logging.Logger.notice = OPSILogger.notice  # type: ignore[attr-defined]
logging.Logger.essential = OPSILogger.essential  # type: ignore[attr-defined]
logging.Logger.comment = OPSILogger.comment  # type: ignore[attr-defined]
logging.Logger.devel = OPSILogger.devel  # type: ignore[attr-defined]
logging.Logger.findCaller = OPSILogger.findCaller  # type: ignore[assignment]


logging.setLoggerClass(OPSILogger)
orig_getLogger = logging.getLogger
logger = orig_getLogger()


def logrecord_init(  # pylint: disable=too-many-arguments
	self: LogRecord,
	name: str,
	level: int,
	pathname: str,
	lineno: int,
	msg: str,
	args: Any,
	exc_info: Any,
	func: str | None = None,
	sinfo: Any = None,
	**kwargs: Any,
) -> None:
	"""
	New Constructor for LogRecord.

	This overloads the LogRecord constructor to also include the OpsiLogLevel.
	The reason is to have backwards compatibility.

	:param name: Name of the logger to feed.
	:param level: Log level of the message.
	:param pathname: Path of the running module.
	:param lineno: Line number of the call.
	:param msg: Message to log (may contain %-style placeholders).
	:param args: Arguments to fill %-style placeholders with.
	:param exc_info: Traceback information in case of exceptions.
	:param func: Name of the calling function.
	:param sinfo: Call stack information.
	:param **kwargs: Additional keyword-arguments.
	"""
	self.__init_orig__(name, level, pathname, lineno, msg, args, exc_info, func=func, sinfo=sinfo, **kwargs)  # type: ignore[attr-defined]
	self.opsilevel = logging.level_to_opsi_level.get(level, level)  # type: ignore[attr-defined]
	self.context = {}
	self.contextstring = ""


logging.LogRecord.__init_orig__ = logging.LogRecord.__init__  # type: ignore[attr-defined]
logging.LogRecord.__init__ = logrecord_init  # type: ignore[assignment]


def handle_log_exception(
	exc: Exception, record: logging.LogRecord | None = None, stderr: bool = True, temp_file: bool = False, log: bool = False
) -> None:
	"""
	Handles an exception in logging process.

	This method prints an Exception message and traceback to stderr.

	:param exc: Exception to be logged.
	:type exc: Exception
	:param record: Log record where the exception occured.
	:type record: logging.LogRecord.
	:param stderr: If true, the Exception is printed to srderr. (default: True)
	:type stderr: bool
	:param temp_file: If true, the Exception is written to a temp file. (default: False)
	:type temp_file: bool
	:param log: If true, the Exception is output by the logger. (default: False)
	:type log: bool
	"""
	try:

		text = "Logging error:\nTraceback (most recent call last):\n"
		text += "".join(format_tb(exc.__traceback__))
		text += f"{exc.__class__.__name__}: {exc}\n"

		if record:
			text += f"record: {record.__dict__}\n"

		if stderr:
			sys.stderr.write(text)

		if temp_file:
			filename = os.path.join(tempfile.gettempdir(), f"log_exception_{os.getpid()}.txt")
			with codecs.open(filename, "a", "utf-8") as file:
				file.write(text)

		if log:
			logger.error(text)

	except Exception:  # pylint: disable=broad-except
		pass


class Singleton(type):
	_instances: dict[type, type] = {}

	def __call__(cls: Singleton, *args: Any, **kwargs: Any) -> type:
		if cls not in cls._instances:
			cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
		return cls._instances[cls]


class ContextFilter(logging.Filter, metaclass=Singleton):
	"""
	class ContextFilter

	This class implements a filter which modifies allows to store context
	for a single thread/task.
	"""

	def __init__(self, filter_dict: dict[str, Any] | None = None):
		"""
		ContextFilter Constructor

		This constructor initializes a ContextFilter instance with an
		empty dictionary as context.

		:param filter_dict: Dictionary that must be present in record context
			in order to accept the LogRecord.
		:type filter_dict: Dict
		"""
		super().__init__()
		self.filter_dict: dict[str, Any] = {}
		self.set_filter(filter_dict)

	def get_context(self) -> dict[str, Any]:
		"""
		Returns context of current thread/task.

		This method requests the thread/task identifier,
		looks up the context stored for it and returns it.

		:returns: Context for currently active thread/task.
		:rtype: Dict
		"""
		return context.get()

	def set_filter(self, filter_dict: dict[str, Any] | None = None) -> None:
		"""
		Sets a new filter dictionary.

		This method expectes a filter dictionary.
		Records are only allowed to pass if their context has a matching
		key-value entry. None means, every record can pass.

		:param filter_dict: Value that must be present in record context
			in order to accept the LogRecord.
		:type filter_dict: Dict
		"""
		if filter_dict is None:
			self.filter_dict = {}
			return
		if not isinstance(filter_dict, dict):
			raise ValueError("filter_dict must be a python dictionary")

		self.filter_dict = {}
		for (key, value) in filter_dict.items():
			if isinstance(value, list):
				self.filter_dict[key] = value
			else:
				self.filter_dict[key] = [value]

	def filter(self, record: logging.LogRecord) -> bool:
		"""
		Adds context to a LogRecord.

		This method is called by Logger._log and modifies LogRecords.
		It adds the context stored for the current thread/task to the namespace.
		If the records context conforms to the filter, it is passed on.

		:param record: LogRecord to add context to and to filter.
		:type record: LogRecord

		:returns: True, if the record conforms to the filter rules.
		:rtype: bool
		"""
		if not getattr(record, "context", None):
			record.context = context.get()  # type: ignore[attr-defined]
			record.context["logger"] = record.name  # type: ignore[attr-defined]
		for (filter_key, filter_values) in self.filter_dict.items():
			record_value = record.context.get(filter_key)  # type: ignore[attr-defined]
			# Filter out record if key not present or value not in filter values
			if record_value in (None, "") or record_value not in filter_values:
				return False
		return True


class ContextSecretFormatter(Formatter):
	"""
	class ContextSecretFormatter

	This class fulfills two formatting tasks:
	1. It alters the LogRecord to also include a string representation of
		a context dictionary, which can be logged by specifying a log
		format which includes %(contextstring)s
	2. It can replace secret strings specified to a SecretFilter by a
		replacement string, thus censor passwords etc.
	"""

	logger_name_in_context_string = False

	def __init__(self, orig_formatter: Formatter) -> None:  # pylint: disable=super-init-not-called
		"""
		ContextSecretFormatter constructor

		This constructor initializes the encapsulated Formatter with
		either one given as parameter or a newly created default one.

		:param orig_formatter: Formatter to encapsulate (my be None).
		:type orig_formatter: Formatter
		"""
		if orig_formatter is None:
			orig_formatter = Formatter()
		self.orig_formatter = orig_formatter
		self.secret_filter_enabled = True

	def disable_filter(self) -> None:
		"""
		Disable the Secret Filter

		This method sets secret_filter_enabled to False such that on evaluating LogRecords,
		the List if secrets is disregarded on formatting.
		"""
		self.secret_filter_enabled = False

	def enable_filter(self) -> None:
		"""
		Enable the Secret Filter

		This method sets secret_filter_enabled to True such that on evaluating LogRecords,
		the List if secrets is consulted on formatting.
		"""
		self.secret_filter_enabled = True

	def format(self, record: logging.LogRecord) -> str:
		"""
		Formats a LogRecord.

		This method takes a LogRecord and formats it to produce
		an output string. If context is specified in the LogRecord
		it is used to produce a contextstring which is included in
		the log string if %(contextstring)s is specified in the format.

		:param record: LogRecord to format.
		:type record: logging.LogRecord

		:returns: The formatted log string.
		:rytpe: str
		"""

		context_ = getattr(record, "context", None)
		if context_:
			record.contextstring = ",".join(
				[str(v) for k, v in context_.items() if self.logger_name_in_context_string or k != "logger"]  # type: ignore[attr-defined]
			)

		msg = self.orig_formatter.format(record)
		if not self.secret_filter_enabled:
			return msg

		_secret_filter = secret_filter
		for _secret in _secret_filter.secrets:
			msg = msg.replace(_secret, SECRET_REPLACEMENT_STRING)
		return msg

	def __getattr__(self, attr: str) -> Any:
		"""
		Retrieves attribute from original formatter.

		This method expects an attribute and returns the valuefor this
		attribute being part of the original formatters namespace.

		:param attr: Any attribute requested from the original formatter.
		:type attr: str

		:returns: Current value of the attribute.
		:rtype: Any
		"""
		return getattr(self.orig_formatter, attr)


class SecretFilter(metaclass=Singleton):
	"""
	class SecretFilter

	This class implements functionality of maintaining a collection
	of secrets which can be used by the ContextSecretFormatter.
	"""

	def __init__(self, min_length: int = 6):
		"""
		SecretFilter constructor.

		This constructor initializes the minimal length of secrets.
		If no value is provided, the default is 6 (characters long).

		:param min_length: Minimal length of a secret string (Default: 6).
		:type min_length: int
		"""
		self._min_length = min_length
		self.secrets: set[str] = set()

	def _initialize_handlers(self) -> None:
		"""
		Assign ContextSecretFormatter to Handlers.

		This method iterates of all Handlers of the root logger.
		Each Handler is assigned a ContextSecretFormatter to ensure that
		no secret string is printed into a Log stream.
		"""
		root_logger = logging.root
		for handler in root_logger.handlers:
			if handler.formatter and not isinstance(handler.formatter, ContextSecretFormatter):
				handler.formatter = ContextSecretFormatter(handler.formatter)

	def set_min_length(self, min_length: int) -> None:
		"""
		Sets minimal secret length.

		This method assigns a new value to the minimal secret length.
		Any new secret string can only be added, if it has more characters.

		:param min_length: Minimal length of a secret string.
		:type min_length: int
		"""
		self._min_length = min_length

	def clear_secrets(self) -> None:
		"""
		Delete all secret strings.

		This method clears the list of secret strings.
		"""
		self.secrets = set()

	def add_secrets(self, *secrets: str) -> None:
		"""
		Inserts new secret strings.

		This method expects any number of secret strings and adds them to the list.

		:param *secrets: Any number of strings (as individual arguments) to add.
		:type *secrets: str
		"""
		self._initialize_handlers()
		for _secret in secrets:
			if _secret and len(_secret) >= self._min_length:
				self.secrets.add(_secret)
				self.secrets.add(quote(_secret))

	def remove_secrets(self, *secrets: str) -> None:
		"""
		Removes secret strings.

		This method expects any number of secret strings and removes them from the list.

		:param *secrets: Any number of strings (as individual arguments) to remove.
		:type *secrets: str
		"""
		for _secret in secrets:
			try:
				self.secrets.remove(_secret)
			except KeyError:
				pass


class RichConsoleHandler(Handler):
	def __init__(self, console: Console) -> None:
		super().__init__()
		self._console = console
		self._styles: dict[str, tuple[str, str]] = {}
		for level, color in LOG_COLORS.items():
			if "thin" in color:
				if color == "thin_white":
					color = "rgb(48,48,48)"
				elif color == "thin_yellow":
					color = "rgb(128,128,0)"
				else:
					color = color.replace("thin_", "")
				self._styles[level] = (f"[not bold][{color}]", f"[/{color}][/not bold]")
			elif "bold" in color:
				color = color.replace("bold_", "bright_")
				self._styles[level] = (f"[bold][{color}]", f"[/{color}][/bold]")
			else:
				self._styles[level] = (f"[not bold][{color}]", f"[/{color}][/not bold]")

	def emit(self, record: LogRecord) -> None:
		try:
			record.log_color, record.reset = self._styles[record.levelname]
			msg = self.format(record)
			self._console.print(msg)
		except Exception:  # pylint: disable=broad-except
			self.handleError(record)


class ObservableHandler(Handler, metaclass=Singleton):
	def __init__(self) -> None:
		Handler.__init__(self)
		self._observers: list[Any] = []

	def attach_observer(self, observer: Any) -> None:
		if observer not in self._observers:
			self._observers.append(observer)

	attachObserver = attach_observer

	def detach_observer(self, observer: Any) -> None:
		if observer in self._observers:
			self._observers.remove(observer)

	detachObserver = detach_observer

	def emit(self, record: LogRecord) -> None:
		if self._observers:
			message = self.format(record)
			for observer in self._observers:
				try:
					observer.messageChanged(self, message)
				except Exception as err:  # pylint: disable=broad-except
					handle_log_exception(err)


last_stderr_format = None  # pylint: disable=invalid-name
last_file_format = None  # pylint: disable=invalid-name


def logging_config(  # pylint: disable=too-many-arguments,too-many-branches,too-many-locals,too-many-statements
	*,
	stderr_level: int | None = None,
	stderr_format: str | None = None,
	log_file: str | None = None,
	file_level: int | None = None,
	file_format: str | None = None,
	file_rotate_max_bytes: int = 0,
	file_rotate_backup_count: int = 0,
	remove_handlers: bool = False,
	stderr_file: IO | Console = sys.stderr,
	logger_levels: dict | None = None,
) -> None:
	"""
	Initialize logging.

	This method initializes the logger according to given parameters.
	Log levels and format for stderr and file output can be set individually.
	:param stderr_level: Loglevel to set for the stderr logging stream.
	:type stderr_level: int
	:param stderr_format: Format to set for the stderr logging stream.
	:type stderr_format: str
	:param stderr_file: File handle for stderr stream.
	:type stderr_file: IO
	:param log_file: Name of the file to write logging stream to.
	:type log_file: str
	:param file_level: Loglevel to set for the file logging stream.
	:type file_level: int
	:param file_format: Format to set for the file logging stream.
	:type file_format: str
	:param file_rotate_max_bytes: Rotate log file if size exceeds file_rotate_max_bytes
	:type file_rotate_max_bytes: int
	:param file_rotate_backup_count: Keep this number of backups when rotating
	:type file_rotate_backup_count: int
	:param remove_handlers: Remove all current handlers
	:type remove_handlers: bool
	"""
	add_context_filter_to_loggers()

	global last_stderr_format  # pylint: disable=global-statement,invalid-name
	if stderr_format is None:
		stderr_format = last_stderr_format or DEFAULT_FORMAT
	else:
		last_stderr_format = stderr_format

	global last_file_format  # pylint: disable=global-statement,invalid-name
	if file_format is None:
		file_format = last_file_format or DEFAULT_FORMAT
	else:
		last_file_format = file_format

	if stderr_level is not None and stderr_level < 10:
		stderr_level = OPSI_LEVEL_TO_LEVEL[stderr_level]
	if file_level is not None and file_level < 10:
		file_level = OPSI_LEVEL_TO_LEVEL[file_level]

	if log_file:
		if remove_handlers:
			remove_all_handlers(handler_type=FileHandler)
			remove_all_handlers(handler_type=RotatingFileHandler)
		else:
			remove_all_handlers(handler_name="opsi_file_handler")

		handler: FileHandler
		if file_rotate_max_bytes and file_rotate_max_bytes > 0:
			handler = RotatingFileHandler(log_file, encoding="utf-8", maxBytes=file_rotate_max_bytes, backupCount=file_rotate_backup_count)
		else:
			handler = FileHandler(log_file, encoding="utf-8")
		handler.name = "opsi_file_handler"
		logging.root.addHandler(handler)

	if file_level is not None:
		for hdlr in get_all_handlers(FileHandler) + get_all_handlers(RotatingFileHandler):
			hdlr.setLevel(file_level)

	if stderr_level is not None:
		if remove_handlers:
			remove_all_handlers(handler_type=StreamHandler)
		else:
			remove_all_handlers(handler_name="opsi_stderr_handler")
		if stderr_level != 0:
			shandler: Handler
			if isinstance(stderr_file, Console):
				shandler = RichConsoleHandler(console=stderr_file)
			else:
				shandler = StreamHandler(stream=stderr_file)
			shandler.name = "opsi_stderr_handler"
			logging.root.addHandler(shandler)
		for hdlr in get_all_handlers((StreamHandler, RichConsoleHandler)):
			hdlr.setLevel(stderr_level)

	if observable_handler not in get_all_handlers(ObservableHandler):
		logging.root.addHandler(observable_handler)

	min_value = NONE
	for hdlr in get_all_handlers():
		if hdlr.level != NOTSET and hdlr.level < min_value:
			min_value = hdlr.level
	logging.root.setLevel(min_value)

	if logger_levels:
		loggers = {
			logger_.name: logger_
			for logger_ in list(logging.Logger.manager.loggerDict.values())  # type: ignore[union-attr]
			if hasattr(logger_, "name")
		}
		re_compile = re.compile
		for logger_re, level in logger_levels.items():
			logger_re = re_compile(logger_re)
			if level is None:
				continue
			for logger_name, logger_ in loggers.items():
				if logger_re.match(logger_name):
					if level < 10:
						level = OPSI_LEVEL_TO_LEVEL[level]
					logger_.setLevel(level)  # type: ignore[union-attr]

	if (
		stderr_format
		and "(log_color)" in stderr_format
		and stderr_file
		and not isinstance(stderr_file, Console)
		and not stderr_file.isatty()
	):
		stderr_format = stderr_format.replace("%(log_color)s", "").replace("%(reset)s", "")
	set_format(file_format=file_format, stderr_format=stderr_format)


def init_logging(
	*,
	stderr_level: int | None = None,
	stderr_format: str | None = None,
	log_file: str | None = None,
	file_level: int | None = None,
	file_format: str | None = None,
) -> None:
	logging_config(
		stderr_level=stderr_level,
		stderr_format=stderr_format,
		log_file=log_file,
		file_level=file_level,
		file_format=file_format,
		remove_handlers=True,
	)


def set_format(
	*,
	file_format: str = DEFAULT_FORMAT,
	stderr_format: str = DEFAULT_COLORED_FORMAT,
	datefmt: str = DATETIME_FORMAT,
	log_colors: dict[str, str] | None = None,
) -> None:
	"""
	Assigns ContextSecretFormatter to all Handlers.

	This method takes optional arguments for format, dateformat and log colors
	and creates ContextSecretFormatters considering those.
	Every Handler is assigned such a ContextSecretFormatter.

	:param file_format: Format to set for the file logging stream.
	:type file_format: str
	:param stderr_format: Format to set for the stderr logging stream.
	:type stderr_format: str
	:param datefmt: Date format for logging. If omitted, a default dateformat is used.
	:type datefmt: str
	:param log_colors: Dictionary of colors for different log levels.
		If omitted, a default Color dictionary is used.
	:type log_colors: Dict
	"""
	for handler_type in (StreamHandler, FileHandler, RotatingFileHandler, RichConsoleHandler):
		fmt = stderr_format if handler_type is StreamHandler or handler_type is RichConsoleHandler else file_format
		for handler in get_all_handlers(handler_type):
			formatter: Formatter
			if handler_type != RichConsoleHandler and fmt.find("(log_color)") >= 0:
				formatter = ColoredFormatter(fmt, datefmt=datefmt, log_colors=log_colors or LOG_COLORS)
			else:
				formatter = Formatter(fmt, datefmt=datefmt)
			csformatter = ContextSecretFormatter(formatter)
			if handler.level == SECRET:
				csformatter.disable_filter()
			else:
				csformatter.enable_filter()
			handler.setFormatter(csformatter)


@contextmanager
def log_context(new_context: dict[str, Any]) -> Generator[None, None, None]:
	"""
	Contextmanager to set a context.

	This contextmanager sets context to the given one on entering
	and resets to the previous dictionary when leaving.

	Example: with log_context({"instance": "context-name"}): ...
	:param new_context: new context to set for the section.
	:type new_context: dict
	"""
	token = None
	try:
		token = set_context(new_context)
		yield
	finally:
		if token is not None:
			context.reset(token)


def set_context(new_context: dict[str, Any]) -> contextvars.Token:
	"""
	Sets a context.

	This method sets context to the given one and returns a reset-token.

	:param new_context: new context to set.
	:type new_context: dict

	:returns: reset-token for the context (stores previous value).
	:rtype: contextvars.Token
	"""
	if isinstance(new_context, dict):
		return context.set(new_context)
	return None


def add_context_filter_to_logger(_logger: logging.Logger) -> None:
	if not isinstance(_logger, PlaceHolder) and context_filter not in _logger.filters:
		_logger.addFilter(context_filter)


def add_context_filter_to_loggers() -> None:
	for _logger in get_all_loggers():
		add_context_filter_to_logger(_logger)


def set_filter(filter_dict: dict[str, Any] | None) -> None:
	"""
	Sets a new filter dictionary.

	This method expectes a filter dictionary.
	Records are only allowed to pass if their context contains
	this specific dictionary. None means, every record can pass.

	:param filter_dict: Dictionary that must be present in record
		context in order to accept the LogRecord.
	:type filter_dict: Dict
	"""
	add_context_filter_to_loggers()
	context_filter.set_filter(filter_dict)


def set_filter_from_string(filter_string: str | list[str] | None) -> None:
	"""
	Parses string and sets filter dictionary.

	This method expects a string (e.g. from user input).
	It is parsed to create a dictionary which is set as filter dictionary.
	The parsing rules are:
		*	Entries are separated by ';'.
		*	One entry consists of exactly two strings separated by '='.
		*	The first one is interpreted as key, the second as value(s).
		*	Values of the same key are separated by ','.

	:param filter_string: String to parse for a filter statement.
	:type filter_string: str
	"""
	filter_dict: dict[str, Any] = {}
	if filter_string is None:
		set_filter(None)
		return

	if isinstance(filter_string, str):
		filter_string = filter_string.split(";")
	elif not isinstance(filter_string, list):
		raise ValueError("filter_string must be either string or list")

	for part in filter_string:
		entry = part.split("=")
		if len(entry) == 2:
			key = entry[0].strip()
			values = entry[1].split(",")
			filter_dict[key] = [v.strip() for v in values]
	set_filter(filter_dict)


def get_all_loggers() -> list[logging.Logger | logging.RootLogger]:
	"""
		Gets list of all loggers.

		This method requests all Logger instances registered at
		logging.Logger.manager.loggerDict and returns them as a list.
	not
		:returns: List containing all loggers (including root)
		:rtype: List
	"""
	return [logging.root] + [lg for lg in logging.Logger.manager.loggerDict.values() if not isinstance(lg, PlaceHolder)]


def get_all_handlers(handler_type: type | tuple[type, ...] | None = None, handler_name: str | None = None) -> list[logging.Handler]:
	"""
	Gets list of all handlers.

	This method iterates over all registered loggers. All handlers
	(optional: of a certain type) are collected and returned as list.

	:param handler_type: If not None, return only handlers of specified type.
	:type handler_type: class

	:returns: List containing all handlers (of specified type) of all loggers.
	:rtype: List
	"""
	handlers = []
	if handler_type and not isinstance(handler_type, tuple):
		handler_type = (handler_type,)
	for _logger in get_all_loggers():
		if not isinstance(_logger, PlaceHolder):
			for _handler in _logger.handlers:
				if (
					(not isinstance(_handler, NullHandler))
					and (
						not isinstance(handler_type, tuple)
						or type(_handler) in handler_type  # exact type needed, not subclass pylint: disable=unidiomatic-typecheck
					)
					and (not handler_name or _handler.name == handler_name)
				):
					handlers.append(_handler)
	return handlers


def remove_all_handlers(handler_type: type | None = None, handler_name: str | None = None) -> None:
	"""
	Removes all handlers (of a certain type).

	This method iterates over all loggers. All assigned handlers
	(of a given type or all) are removed.

	:param handler_type: Type of handlers that should be removed.
	:type handler_type: class
	"""
	for _logger in get_all_loggers():
		if not isinstance(_logger, PlaceHolder):
			for _handler in _logger.handlers:
				if (
					not handler_type
					or type(_handler) == handler_type  # exact type needed, not subclass pylint: disable=unidiomatic-typecheck
				) and (not handler_name or _handler.name == handler_name):
					_logger.removeHandler(_handler)


def print_logger_info() -> None:
	"""
	Debug output logger status.

	This method prints all loggers with their respective
	handlers and formatters to stderr.
	"""
	stderr = sys.stderr
	for _logger in get_all_loggers():
		print(f"- Logger: {_logger}", file=stderr)
		if not isinstance(_logger, PlaceHolder):
			for _filter in _logger.filters:
				print(f"  - Filter: {_filter} ", file=stderr)
			for _handler in _logger.handlers:
				name = str(_handler)
				if _handler.name:
					tmp = name.split(" ")
					tmp.insert(1, f'"{_handler.name}"')
					name = " ".join(tmp)
				print(f"  - Handler: {name} ", file=stderr)
				print(f"    - Formatter: {_handler.formatter}", file=stderr)


def init_warnings_capture(traceback_log_level: int = logging.INFO) -> None:
	def _log_warning(  # pylint: disable=too-many-arguments
		message: str, category: Any, filename: str, lineno: int, line: Any = None, file: Any = None  # pylint: disable=unused-argument
	) -> None:
		log = logger.log
		logger.warning("Warning '%s' in file '%s', line %s", message, filename, lineno)
		for entry in format_stack():
			for _line in entry.split("\n"):
				log(traceback_log_level, _line)

	warnings.showwarning = _log_warning  # type: ignore[assignment]
	# warn filter: https://docs.python.org/3/library/warnings.html#the-warnings-filter
	warnings.simplefilter("default")
	# Warning 'The distutils package is deprecated and slated for removal in Python 3.12.
	# Use setuptools or check PEP 632 for potential alternatives' in file 'PyInstaller/loader/pyimod03_importers.py'
	warnings.filterwarnings("ignore", message="The distutils package is deprecated")


init_warnings_capture()
observable_handler = ObservableHandler()
secret_filter = SecretFilter()
context_filter = ContextFilter()


def get_logger(name: str | None = None) -> OPSILogger:
	_logger = orig_getLogger(name)
	add_context_filter_to_logger(_logger)
	return _logger  # type: ignore[return-value]


logging.getLogger = get_logger
logging_config(stderr_level=logging.WARNING)
