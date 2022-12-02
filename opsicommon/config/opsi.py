# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import re
from pathlib import Path
from typing import Any

from tomlkit import dumps, loads

from ..logging import get_logger
from ..utils import Singleton

logger = get_logger("opsicommon.config")


class OpsiConfig(metaclass=Singleton):
	config_file = "/etc/opsi/opsi.conf"

	def __init__(self) -> None:
		self._config: dict[str, Any] = {}

	def update_config_file(self) -> None:
		file = Path(self.config_file)
		data = file.read_text(encoding="utf-8")
		key_val_regex = re.compile(r"([^=]+)=(\s*)(.+)")
		lines = data.split("\n")
		for idx, line in enumerate(lines):
			match = key_val_regex.search(line)
			if not match:
				continue
			val = match.group(3).strip()
			if val.lower() in ("true", "false"):
				line = f"{match.group(1)}={match.group(2)}{val.lower()}"
			elif not val.startswith('"'):
				line = f'{match.group(1)}={match.group(2)}"{match.group(3)}"'
			lines[idx] = line
		new_data = "\n".join(lines)
		if new_data != data:
			file.write_text(new_data, encoding="utf-8")

	def read_config_file(self) -> None:
		self.update_config_file()
		data = Path(self.config_file).read_text(encoding="utf-8")
		self._config = loads(data)

	def write_config_file(self) -> None:
		Path(self.config_file).write_text(dumps(self._config), encoding="utf-8")
