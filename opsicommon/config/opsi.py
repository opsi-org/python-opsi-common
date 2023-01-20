# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import os
import re
import socket
from pathlib import Path
from shutil import chown
from subprocess import PIPE, Popen
from threading import Lock
from typing import Any
from urllib.parse import urlparse

from tomlkit import dumps, loads
from tomlkit.items import Item

from ..logging import get_logger
from ..types import forceFqdn
from ..utils import Singleton

logger = get_logger("opsicommon.config")


GLOBAL_CONF = "/etc/opsi/global.conf"
DISPATCH_CONF = "/etc/opsi/backendManager/dispatch.conf"
JSONRPC_CONF = "/etc/opsi/backends/jsonrpc.conf"
MYSQL_CONF = "/etc/opsi/backends/mysql.conf"

DEFAULT_ADMIN_GROUP = "opsiadmin"
DEFAULT_FILEADMIN_GROUP = "opsifileadmins"
DEFAULT_READONLY_GROUP = ""
DEFAULT_DEPOT_USER = "pcpatch"
DEFAULT_DEPOT_USER_HOME = "/var/lib/opsi"
DEFAULT_OPSICONFD_USER = "opsiconfd"


def read_backend_config_file(file: Path) -> dict[str, Any]:
	if not file.exists():
		return {}
	loc: dict[str, Any] = {}
	exec(compile(file.read_bytes(), "<string>", "exec"), None, loc)  # pylint: disable=exec-used
	return loc["config"]


def get_role() -> str:
	dipatch_conf = Path(DISPATCH_CONF)
	if dipatch_conf.exists():
		for line in dipatch_conf.read_text(encoding="utf-8").split("\n"):
			line = line.strip()
			if not line or line.startswith("#") or ":" not in line:
				continue
			if "jsonrpc" in line.split(":", 1)[1]:
				return "depotserver"
	return "configserver"


def get_host_id(server_role: str) -> str:
	if server_role == "depotserver":
		jsonrpc_conf = read_backend_config_file(Path(JSONRPC_CONF))
		if jsonrpc_conf and jsonrpc_conf.get("username"):
			return jsonrpc_conf["username"]
	else:
		global_conf = Path(GLOBAL_CONF)
		try:
			if global_conf.exists():
				regex = re.compile(r"^hostname\s*=\s*(\S+)")
				for line in global_conf.read_text(encoding="utf-8").split("\n"):
					match = regex.search(line.strip())
					if match:
						return forceFqdn(match.group(1))
		except Exception:  # pylint: disable=broad-except
			pass

		try:
			return forceFqdn(os.environ.get("OPSI_HOST_ID") or os.environ.get("OPSI_HOSTNAME"))
		except ValueError:
			pass

	return forceFqdn(socket.getfqdn())


def get_host_key(server_role: str) -> str:
	if server_role == "depotserver":
		jsonrpc_conf = read_backend_config_file(Path(JSONRPC_CONF))
		return jsonrpc_conf.get("password", "")

	mysql_conf = read_backend_config_file(Path(MYSQL_CONF))
	if not mysql_conf:
		return ""

	with Popen(
		[
			"mysql",
			"--defaults-file=/dev/stdin",
			"--skip-column-names",
			"-h",
			urlparse(mysql_conf["address"]).hostname or mysql_conf["address"],
			"-D",
			mysql_conf["database"],
			"-e",
			"SELECT opsiHostKey FROM HOST WHERE type='OpsiConfigserver';",
		],
		stdin=PIPE,
		stdout=PIPE,
		stderr=PIPE,
	) as proc:
		out = proc.communicate(input=f"[client]\nuser={mysql_conf['username']}\npassword={mysql_conf['password']}\n".encode())
		if proc.returncode != 0:
			return ""
		return out[0].decode().strip()


def get_service_url(server_role: str) -> str:
	if server_role == "depotserver":
		jsonrpc_conf = read_backend_config_file(Path(JSONRPC_CONF))
		addr = jsonrpc_conf.get("address", "")
		if not addr:
			return ""
		if "://" not in addr:
			addr = f"https://{addr}"
		url = urlparse(addr)
		return f"{url.scheme}://{url.hostname}:{url.port or 4447}"

	return "https://localhost:4447"


class OpsiConfig(metaclass=Singleton):
	file_lock = Lock()
	config_file = "/etc/opsi/opsi.conf"
	default_config = {
		"host": {"id": "", "key": "", "server-role": ""},
		"service": {"url": ""},
		"groups": {
			"fileadmingroup": DEFAULT_FILEADMIN_GROUP,
			"admingroup": DEFAULT_ADMIN_GROUP,
			"readonly": DEFAULT_READONLY_GROUP,
		},
		"depot_user": {"username": DEFAULT_DEPOT_USER, "home": DEFAULT_DEPOT_USER_HOME},
		"packages": {"use_pigz": True},
		"ldap_auth": {"ldap_url": "", "bind_user": ""},
	}

	def __init__(self, upgrade_config: bool = True) -> None:
		self._config_file_mtime = 0.0
		self._config: dict[str, Any] = self.default_config
		self._config_file_read = False
		self._upgrade_config = upgrade_config
		self._upgrade_done = False

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
		cf_path = Path(self.config_file)
		if not self._config_file_read or not cf_path.exists() or not cf_path.stat().st_mtime != self._config_file_mtime:
			self.read_config_file()

	def _assert_category_and_config(self, category: str, config: str | None = None) -> None:
		if category not in self._config:
			raise ValueError(f"Invalid category {category!r}")
		if config is not None and config not in self._config[category]:
			raise ValueError(f"Invalid config {config!r} for category {category!r}", config, category)

	def get(self, category: str, config: str | None = None) -> Any:
		self._assert_config_read()
		self._assert_category_and_config(category, config)
		if config is None:
			return dict(self._config[category])
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

	def upgrade_config_file(self) -> None:  # pylint: disable=too-many-branches
		if self._upgrade_done or not self._upgrade_config:
			return
		# Convert ini (opsi < 4.3) to toml (opsi >= 4.3)
		file = Path(self.config_file)
		if not file.exists():
			file.touch(mode=0o660)
			try:
				chown(file, group=DEFAULT_ADMIN_GROUP)
			except Exception:  # pylint: disable=broad-except
				pass
			try:
				chown(file, user=DEFAULT_OPSICONFD_USER)
			except Exception:  # pylint: disable=broad-except
				pass
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
		config = loads(new_data)
		if not config.get("host"):
			config["host"] = {}
		if not config["host"].get("server-role"):  # type: ignore[union-attr]
			config["host"]["server-role"] = get_role()  # type: ignore[union-attr,index]
		if not config["host"].get("id"):  # type: ignore[union-attr]
			config["host"]["id"] = get_host_id(str(config["host"]["server-role"]))  # type: ignore[union-attr,index]
		if not config["host"].get("key"):  # type: ignore[union-attr]
			config["host"]["key"] = get_host_key(str(config["host"]["server-role"]))  # type: ignore[union-attr,index]

		if not config.get("service"):
			config["service"] = {}
		if not config["service"].get("url"):  # type: ignore[union-attr]
			config["service"]["url"] = get_service_url(str(config["host"]["server-role"]))  # type: ignore[union-attr,index]

		new_data = dumps(config)
		if new_data != data:
			file.write_text(new_data, encoding="utf-8")

		self._upgrade_done = True

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
