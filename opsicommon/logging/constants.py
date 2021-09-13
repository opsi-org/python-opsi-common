# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import logging

DEFAULT_COLORED_FORMAT = "%(log_color)s[%(opsilevel)d] [%(asctime)s.%(msecs)03d]%(reset)s [%(contextstring)-15s] %(message)s   (%(filename)s:%(lineno)d)"  # pylint: disable=line-too-long
DEFAULT_FORMAT = "[%(opsilevel)d] [%(asctime)s.%(msecs)03d] [%(contextstring)-15s] %(message)s   (%(filename)s:%(lineno)d)"
DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"

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
SECRET_REPLACEMENT_STRING = '***secret***'

logging.NOTSET = 0
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
logging.NONE = 100

LEVEL_TO_NAME = {
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
logging.level_to_name = LEVEL_TO_NAME
logging._levelToName = LEVEL_TO_NAME  # pylint: disable=protected-access

NAME_TO_LEVEL = {
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
logging.name_to_level = NAME_TO_LEVEL
logging._nameToLevel = NAME_TO_LEVEL  # pylint: disable=protected-access

LEVEL_TO_OPSI_LEVEL = {
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
logging.level_to_opsi_level = LEVEL_TO_OPSI_LEVEL
logging._levelToOpsiLevel = LEVEL_TO_OPSI_LEVEL  # pylint: disable=protected-access

OPSI_LEVEL_TO_LEVEL = {
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
logging.opsi_level_to_level = OPSI_LEVEL_TO_LEVEL
logging._opsiLevelToLevel = OPSI_LEVEL_TO_LEVEL  # pylint: disable=protected-access

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
