# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

from datetime import datetime

import win32api  # type: ignore[import] # pylint: disable=import-error


def set_system_datetime(utc_datetime: datetime) -> None:
	win32api.SetSystemTime(
		utc_datetime.year,
		utc_datetime.month,
		utc_datetime.weekday(),
		utc_datetime.day,
		utc_datetime.hour,
		utc_datetime.minute,
		utc_datetime.second,
		0,
	)
