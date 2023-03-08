# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import os
import re
import subprocess
from datetime import datetime


def set_system_datetime(utc_datetime: datetime) -> None:
	try:
		subprocess.run(
			["date", "-f", "%Y-%m-%d %H:%M:%S %Z", "-u", utc_datetime.strftime("%Y-%m-%d %H:%M:%S UTC")], capture_output=True, check=True
		)
	except subprocess.CalledProcessError as err:
		raise RuntimeError(
			f"Failed to set system time as uid {os.geteuid()}: {err.returncode} - {err.stderr.decode(errors='replace')}"
		) from err


def get_system_uuid() -> str:
	regex = re.compile(r'"IOPlatformUUID"\s*=\s*"([a-zA-Z0-9\-]+)"')
	out = subprocess.run(["ioreg", "-d", "2", "-c", "IOPlatformExpertDevice"], capture_output=True, check=True, encoding="utf-8").stdout
	for line in out.splitlines():
		if match := regex.search(line):
			return match.group(1).lower()
	raise RuntimeError(f"Failed to find IOPlatformUUID in ioreg output: {out}")
