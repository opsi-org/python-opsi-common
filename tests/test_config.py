# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

from pathlib import Path
from textwrap import dedent
from time import sleep
from unittest.mock import patch

import pytest
from opsicommon.config.opsi import OpsiConfig
from opsicommon.testing.helpers import environment  # type: ignore[import]


def test_upgrade_config_from_ini(tmp_path: Path) -> None:
	config_file = tmp_path / "opsi.conf"
	OpsiConfig._instances = {}  # pylint: disable=protected-access
	OpsiConfig.config_file = str(config_file)
	data = """
	[groups]
	fileadmingroup = opsifileadmins
	#fileadmingroup = commented

	[packages]
	use_pigz = True

	[ldap_auth]
	# Active Directory / Samba 4
	ldap_url = ldaps://ad.opsi.test/dc=ad,dc=opsi,dc=test
	"""
	data = dedent(data)
	config_file.write_text(data, encoding="utf-8")
	config = OpsiConfig()
	config.upgrade_config_file()
	new_data = config_file.read_text(encoding="utf-8")
	assert (
		dedent(
			"""
	[groups]
	fileadmingroup = "opsifileadmins"
	#fileadmingroup = "commented"

	[packages]
	use_pigz = true

	[ldap_auth]
	# Active Directory / Samba 4
	ldap_url = "ldaps://ad.opsi.test/dc=ad,dc=opsi,dc=test"
	"""
		).strip()
		in new_data
	)


def test_fill_from_legacy_config_depotserver(tmp_path: Path) -> None:
	config_file = tmp_path / "opsi.conf"
	dispatch_conf = tmp_path / "dispatch.conf"
	jsonrpc_conf = tmp_path / "jsonrpc.conf"

	OpsiConfig._instances = {}  # pylint: disable=protected-access
	OpsiConfig.config_file = str(config_file)
	config = OpsiConfig()

	dispatch_conf.write_text("# comment\n.* : jsonrpc\n", encoding="utf-8")
	jsonrpc_conf.write_text(
		dedent(
			"""
	module = 'JSONRPC'
	config = {
		"username" : "depot.opsi.test",
		"password" : "9a264fbe53fc58dd65030c1bd23983fa",
		"address" : "config.opsi.test"
	}
	"""
		),
		encoding="utf-8",
	)
	with (
		patch("opsicommon.config.opsi.DISPATCH_CONF", str(dispatch_conf)),
		patch("opsicommon.config.opsi.JSONRPC_CONF", str(jsonrpc_conf)),
	):
		assert config.get("host", "server-role") == "depotserver"
		assert config.get("host", "id") == "depot.opsi.test"
		assert config.get("host", "key") == "9a264fbe53fc58dd65030c1bd23983fa"
		assert config.get("service", "url") == "https://config.opsi.test:4447"


def test_fill_from_legacy_config_configserver(tmp_path: Path) -> None:
	config_file = tmp_path / "opsi.conf"
	dispatch_conf = tmp_path / "dispatch.conf"
	mysql_conf = Path("tests/data/opsi-config/backends/mysql.conf")
	global_conf = tmp_path / "global.conf"

	OpsiConfig._instances = {}  # pylint: disable=protected-access
	OpsiConfig.config_file = str(config_file)
	config = OpsiConfig()

	dispatch_conf.write_text(".* : mysql\n", encoding="utf-8")
	with (
		patch("opsicommon.config.opsi.DISPATCH_CONF", str(dispatch_conf)),
		patch("opsicommon.config.opsi.MYSQL_CONF", str(mysql_conf)),
		patch("opsicommon.config.opsi.GLOBAL_CONF", str(global_conf)),
	):
		assert config.get("host", "server-role") == "configserver"
		assert config.get("host", "id")
		assert config.get("service", "url") == "https://localhost:4447"

		config_file.write_bytes(b"")
		OpsiConfig._instances = {}  # pylint: disable=protected-access
		config = OpsiConfig()
		global_conf.write_text("\n\n hostname =  config.server.id \n\n", encoding="utf-8")
		assert config.get("host", "id") == "config.server.id"

		config_file.write_bytes(b"")
		OpsiConfig._instances = {}  # pylint: disable=protected-access
		config = OpsiConfig()
		global_conf.write_text("\n\n", encoding="utf-8")
		with environment({"OPSI_HOSTNAME": "env-config.server.id"}):
			assert config.get("host", "id") == "env-config.server.id"


def test_read_config_file(tmp_path: Path) -> None:
	config_file = tmp_path / "opsi.conf"
	OpsiConfig._instances = {}  # pylint: disable=protected-access
	OpsiConfig.config_file = str(config_file)
	data = """
	[ldap_auth]
	ldap_url = "ldaps://test"
	"""
	config_file.write_text(dedent(data), encoding="utf-8")
	config = OpsiConfig()
	assert config._config_file_mtime == 0.0  # pylint: disable=protected-access
	assert config.get("ldap_auth", "ldap_url") == "ldaps://test"
	mtime = config._config_file_mtime  # pylint: disable=protected-access
	assert mtime != 0.0

	sleep(0.1)
	# Assert that a changed file is reread
	data = """
	[ldap_auth]
	ldap_url = "ldaps://test2"
	"""
	config_file.write_text(dedent(data), encoding="utf-8")
	assert config.get("ldap_auth", "ldap_url") == "ldaps://test2"


def test_get_config(tmp_path: Path) -> None:
	config_file = tmp_path / "opsi.conf"
	OpsiConfig._instances = {}  # pylint: disable=protected-access
	OpsiConfig.config_file = str(config_file)
	data = """
	[groups]
	fileadmingroup = "fag"
	"""
	config_file.write_text(dedent(data), encoding="utf-8")
	config = OpsiConfig()
	assert type(config.get("groups", "fileadmingroup")) is str  # pylint: disable=unidiomatic-typecheck
	assert config.get("groups", "fileadmingroup") == "fag"
	conf_dict = config.get("groups")
	for key, val in conf_dict.items():
		assert type(key) is str  # pylint: disable=unidiomatic-typecheck
		assert type(val) is str  # pylint: disable=unidiomatic-typecheck
	assert conf_dict["fileadmingroup"] == "fag"


def test_set_config(tmp_path: Path) -> None:
	config_file = tmp_path / "opsi.conf"
	OpsiConfig._instances = {}  # pylint: disable=protected-access
	OpsiConfig.config_file = str(config_file)
	data = """
	[groups]
	fileadmingroup = "fag"
	admingroup = "ag"
	"""
	config_file.write_text(dedent(data), encoding="utf-8")
	config = OpsiConfig()
	config.set("groups", "fileadmingroup", "new", persistent=True)
	new_data = config_file.read_text(encoding="utf-8")
	assert (
		dedent(
			"""
	[groups]
	fileadmingroup = "new"
	admingroup = "ag"
	"""
		).strip()
		in new_data
	)


def test_set_config_type_check() -> None:
	config = OpsiConfig()
	with pytest.raises(ValueError, match=r"Wrong type 'str' for config 'use_pigz' \(bool\) in category 'packages'"):
		config.set("packages", "use_pigz", "yes")

	with pytest.raises(ValueError, match=r"Wrong type 'bool' for config 'fileadmingroup' \(str\) in category 'groups'"):
		config.set("groups", "fileadmingroup", True)

	with pytest.raises(ValueError, match=r"Wrong type 'int' for config 'ldap_url' \(str\) in category 'ldap_auth'"):
		config.set("ldap_auth", "ldap_url", 123)


def test_set_config_invalid_category_or_config() -> None:
	config = OpsiConfig()
	with pytest.raises(ValueError, match=r"Invalid config 'invalid' for category 'packages'"):
		config.set("packages", "invalid", True)

	with pytest.raises(ValueError, match=r"Invalid category 'invalid'"):
		config.set("invalid", "invalid", True)
