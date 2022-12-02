# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import re
from pathlib import Path
from threading import Lock
from typing import Any

from tomlkit import dumps, loads
from tomlkit.items import Item

from ..logging import get_logger
from ..utils import Singleton

logger = get_logger("opsicommon.config")


class OpsiConfig(metaclass=Singleton):
	file_lock = Lock()
	config_file = "/etc/opsi/opsi.conf"
	default_config = {
		"groups": {"fileadmingroup": "opsifileadmins", "admingroup": "opsiadmin"},
		"packages": {"use_pigz": True},
		"ldap_auth": {"ldap_url": "", "bind_user": ""},
	}

	def __init__(self) -> None:
		self._config_file_mtime = 0.0
		self._config: dict[str, Any] = self.default_config
		self._config_file_read = False

	@staticmethod
	def _merge_config(destination: dict[str, Any], source: dict[str, Any]) -> None:
		for key in source:
			if key not in destination:
				# Do not create new configs / categories
				continue
			if isinstance(source[key], dict):
				OpsiConfig._merge_config(destination[key], source[key])
			else:
				destination[key] = source[key]

	def _assert_config_read(self) -> None:
		if not self._config_file_read or Path(self.config_file).stat().st_mtime != self._config_file_mtime:
			self.read_config_file()

	def _assert_category_and_config(self, category: str, config: str) -> None:
		if category not in self._config:
			raise ValueError(f"Invalid category {category!r}")
		if config not in self._config[category]:
			raise ValueError(f"Invalid config {config!r} for category {category!r}", config, category)

	def get(self, category: str, config: str) -> Any:
		self._assert_config_read()
		self._assert_category_and_config(category, config)
		return self._config[category][config]

	def set(self, category: str, config: str, value: Any, persistent: bool = False) -> None:
		self._assert_config_read()
		self._assert_category_and_config(category, config)
		value = "" if value is None else value
		_type = type(self._config[category][config])
		if isinstance(self._config[category][config], Item):
			_type = type(self._config[category][config].unwrap())
		if not isinstance(value, _type):
			raise ValueError(f"Wrong type {type(value).__name__!r} for config {config!r} ({_type.__name__}) in category {category!r}")
		self._config[category][config] = value
		if persistent:
			self.write_config_file()

	def upgrade_config_file(self) -> None:
		# Convert ini (opsi < 4.3) to toml (opsi >= 4.3)
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
		with self.file_lock:
			self._config_file_read = False
			self.upgrade_config_file()
			file = Path(self.config_file)
			data = file.read_text(encoding="utf-8")
			self._merge_config(self._config, loads(data))
			self._config_file_read = True
			self._config_file_mtime = file.stat().st_mtime

	def write_config_file(self) -> None:
		with self.file_lock:
			file = Path(self.config_file)
			file.write_text(dumps(self._config), encoding="utf-8")
			self._config_file_mtime = file.stat().st_mtime
