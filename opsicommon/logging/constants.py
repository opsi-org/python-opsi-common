# opsicommon is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2025 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0-only

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

LOG_SECRET = LOG_CONFIDENTIAL = 9
LOG_TRACE = LOG_DEBUG2 = 8
LOG_DEBUG = 7
LOG_INFO = 6
LOG_NOTICE = 5
LOG_WARNING = LOG_WARN = 4
LOG_ERROR = 3
LOG_CRITICAL = 2
LOG_ESSENTIAL = LOG_DEVEL = LOG_COMMENT = 1
LOG_NONE = LOG_NOTSET = 0

NOTSET = logging.NOTSET = 0  # type: ignore
SECRET = CONFIDENTIAL = logging.SECRET = logging.CONFIDENTIAL = 10  # type: ignore
TRACE = DEBUG2 = logging.TRACE = logging.DEBUG2 = 20  # type: ignore
DEBUG = logging.DEBUG = 30  # type: ignore
INFO = logging.INFO = 40  # type: ignore
NOTICE = logging.NOTICE = 50  # type: ignore
WARNING = WARN = logging.WARN = logging.WARNING = 60  # type: ignore
ERROR = logging.ERROR = 70  # type: ignore
CRITICAL = logging.CRITICAL = 80  # type: ignore
ESSENTIAL = DEVEL = COMMENT = logging.ESSENTIAL = logging.DEVEL = logging.COMMENT = 90  # type: ignore
NONE = logging.NONE = 100  # type: ignore

LEVEL_TO_NAME = {
	SECRET: "SECRET",
	TRACE: "TRACE",
	DEBUG: "DEBUG",
	INFO: "INFO",
	NOTICE: "NOTICE",
	WARNING: "WARNING",
	ERROR: "ERROR",
	CRITICAL: "CRITICAL",
	ESSENTIAL: "ESSENTIAL",
	NONE: "NONE",
}
logging._levelToName = logging.level_to_name = LEVEL_TO_NAME  # type: ignore[attr-defined]

NAME_TO_LEVEL = {
	"SECRET": SECRET,  # type: ignore[attr-defined]
	"TRACE": TRACE,  # type: ignore[attr-defined]
	"DEBUG": DEBUG,
	"INFO": INFO,
	"NOTICE": NOTICE,  # type: ignore[attr-defined]
	"WARNING": WARNING,
	"ERROR": ERROR,
	"CRITICAL": CRITICAL,
	"ESSENTIAL": ESSENTIAL,  # type: ignore[attr-defined]
	"NONE": NONE,  # type: ignore[attr-defined]
}
logging._nameToLevel = logging.name_to_level = NAME_TO_LEVEL  # type: ignore[attr-defined]

LEVEL_TO_OPSI_LEVEL = {
	SECRET: LOG_SECRET,
	TRACE: LOG_TRACE,
	DEBUG: LOG_DEBUG,
	INFO: LOG_INFO,
	NOTICE: LOG_NOTICE,
	WARNING: LOG_WARNING,
	ERROR: LOG_ERROR,
	CRITICAL: LOG_CRITICAL,
	ESSENTIAL: LOG_ESSENTIAL,
	NONE: LOG_NONE,
}
logging.level_to_opsi_level = LEVEL_TO_OPSI_LEVEL  # type: ignore[attr-defined]
logging._levelToOpsiLevel = LEVEL_TO_OPSI_LEVEL  # type: ignore[attr-defined]

OPSI_LEVEL_TO_LEVEL = {
	LOG_SECRET: SECRET,
	LOG_TRACE: TRACE,
	LOG_DEBUG: DEBUG,
	LOG_INFO: INFO,
	LOG_NOTICE: NOTICE,
	LOG_WARNING: WARNING,
	LOG_ERROR: ERROR,
	LOG_CRITICAL: CRITICAL,
	LOG_ESSENTIAL: ESSENTIAL,
	LOG_NONE: NONE,
}
logging.opsi_level_to_level = OPSI_LEVEL_TO_LEVEL  # type: ignore[attr-defined]
logging._opsiLevelToLevel = OPSI_LEVEL_TO_LEVEL  # type: ignore[attr-defined]
