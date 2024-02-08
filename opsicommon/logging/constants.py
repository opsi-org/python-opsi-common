# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import logging

DEFAULT_COLORED_FORMAT = (
	"%(log_color)s[%(opsilevel)d] [%(asctime)s.%(msecs)03d]%(reset)s [%(contextstring)-15s] %(message)s   (%(filename)s:%(lineno)d)"
)
DEFAULT_FORMAT = "[%(opsilevel)d] [%(asctime)s.%(msecs)03d] [%(contextstring)-15s] %(message)s   (%(filename)s:%(lineno)d)"
DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"

LOG_COLORS = {
	"SECRET": "thin_yellow",
	"TRACE": "thin_white",
	"DEBUG": "white",
	"INFO": "bold_white",
	"NOTICE": "bold_green",
	"WARNING": "bold_yellow",
	"ERROR": "red",
	"CRITICAL": "bold_red",
	"ESSENTIAL": "bold_cyan",
}
SECRET_REPLACEMENT_STRING = "***secret***"

LOG_SECRET = 9
LOG_CONFIDENTIAL = 9
LOG_TRACE = 8
LOG_DEBUG2 = 7
LOG_DEBUG = 7
LOG_INFO = 6
LOG_NOTICE = 5
LOG_WARNING = 4
LOG_WARN = 4
LOG_ERROR = 3
LOG_CRITICAL = 2
LOG_ESSENTIAL = 1
LOG_COMMENT = 1
LOG_NONE = 0
LOG_NOTSET = 0

logging.NOTSET = 0
SECRET = 10
logging.SECRET = SECRET  # type: ignore[attr-defined]
logging.CONFIDENTIAL = SECRET  # type: ignore[attr-defined]
TRACE = 20
logging.TRACE = TRACE  # type: ignore[attr-defined]
logging.DEBUG2 = TRACE  # type: ignore[attr-defined]
logging.DEBUG = 30
logging.INFO = 40
NOTICE = 50
logging.NOTICE = NOTICE  # type: ignore[attr-defined]
logging.WARNING = 60
logging.WARN = logging.WARNING
logging.ERROR = 70
logging.CRITICAL = 80
ESSENTIAL = 90
logging.ESSENTIAL = ESSENTIAL  # type: ignore[attr-defined]
logging.COMMENT = ESSENTIAL  # type: ignore[attr-defined]
NONE = 100
logging.NONE = NONE  # type: ignore[attr-defined]

LEVEL_TO_NAME = {
	logging.SECRET: "SECRET",  # type: ignore[attr-defined]
	logging.TRACE: "TRACE",  # type: ignore[attr-defined]
	logging.DEBUG: "DEBUG",
	logging.INFO: "INFO",
	logging.NOTICE: "NOTICE",  # type: ignore[attr-defined]
	logging.WARNING: "WARNING",
	logging.ERROR: "ERROR",
	logging.CRITICAL: "CRITICAL",
	logging.ESSENTIAL: "ESSENTIAL",  # type: ignore[attr-defined]
	logging.NONE: "NONE",  # type: ignore[attr-defined]
}
logging._levelToName = logging.level_to_name = LEVEL_TO_NAME  # type: ignore[attr-defined]

NAME_TO_LEVEL = {
	"SECRET": logging.SECRET,  # type: ignore[attr-defined]
	"TRACE": logging.TRACE,  # type: ignore[attr-defined]
	"DEBUG": logging.DEBUG,
	"INFO": logging.INFO,
	"NOTICE": logging.NOTICE,  # type: ignore[attr-defined]
	"WARNING": logging.WARNING,
	"ERROR": logging.ERROR,
	"CRITICAL": logging.CRITICAL,
	"ESSENTIAL": logging.ESSENTIAL,  # type: ignore[attr-defined]
	"NONE": logging.NONE,  # type: ignore[attr-defined]
}
logging._nameToLevel = logging.name_to_level = NAME_TO_LEVEL  # type: ignore[attr-defined]

LEVEL_TO_OPSI_LEVEL = {
	logging.SECRET: LOG_SECRET,  # type: ignore[attr-defined]
	logging.TRACE: LOG_TRACE,  # type: ignore[attr-defined]
	logging.DEBUG: LOG_DEBUG,
	logging.INFO: LOG_INFO,
	logging.NOTICE: LOG_NOTICE,  # type: ignore[attr-defined]
	logging.WARNING: LOG_WARNING,
	logging.ERROR: LOG_ERROR,
	logging.CRITICAL: LOG_CRITICAL,
	logging.ESSENTIAL: LOG_ESSENTIAL,  # type: ignore[attr-defined]
	logging.NONE: LOG_NONE,  # type: ignore[attr-defined]
}
logging.level_to_opsi_level = LEVEL_TO_OPSI_LEVEL  # type: ignore[attr-defined]
logging._levelToOpsiLevel = LEVEL_TO_OPSI_LEVEL  # type: ignore[attr-defined]

OPSI_LEVEL_TO_LEVEL = {
	LOG_SECRET: logging.SECRET,  # type: ignore[attr-defined]
	LOG_TRACE: logging.TRACE,  # type: ignore[attr-defined]
	LOG_DEBUG: logging.DEBUG,
	LOG_INFO: logging.INFO,
	LOG_NOTICE: logging.NOTICE,  # type: ignore[attr-defined]
	LOG_WARNING: logging.WARNING,
	LOG_ERROR: logging.ERROR,
	LOG_CRITICAL: logging.CRITICAL,
	LOG_ESSENTIAL: logging.ESSENTIAL,  # type: ignore[attr-defined]
	LOG_NONE: logging.NONE,  # type: ignore[attr-defined]
}
logging.opsi_level_to_level = OPSI_LEVEL_TO_LEVEL  # type: ignore[attr-defined]
logging._opsiLevelToLevel = OPSI_LEVEL_TO_LEVEL  # type: ignore[attr-defined]
