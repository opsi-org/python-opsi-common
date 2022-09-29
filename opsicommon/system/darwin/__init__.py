# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import subprocess
from datetime import datetime


def set_system_datetime(utc_datetime: datetime) -> None:
	subprocess.run(
		["date", "-f", "%Y-%m-%d %H:%M:%S %Z", "-u", utc_datetime.strftime("%Y-%m-%d %H:%M:%S UTC")], capture_output=True, check=True
	)
