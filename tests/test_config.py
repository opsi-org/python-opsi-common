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

from opsicommon.config.opsi import (DEFAULT_OPSICONFD_USER, OPSICONFD_CONF,
                                    OpsiConfig, get_opsiconfd_user)
from opsicommon.testing.helpers import environment  # type: ignore[import]


def test_upgrade_config_from_ini(tmp_path: Path) -> None:
	config_file = tmp_path / "opsi.conf"
	OpsiConfig._instances = {}
	OpsiConfig.config_file = str(config_file)
	data = """
	[groups]
	fileadmingroup = opsifileadmins
	#fileadmingroup = DOMAIN\\\\commented
	admingroup = DOMAIN\\opsiadmin

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
	#fileadmingroup = "DOMAIN\\\\commented"
	admingroup = "DOMAIN\\\\opsiadmin"

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

	OpsiConfig._instances = {}
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

	OpsiConfig._instances = {}
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
		OpsiConfig._instances = {}
		config = OpsiConfig()
		global_conf.write_text("\n\n hostname =  config.server.id \n\n", encoding="utf-8")
		assert config.get("host", "id") == "config.server.id"

		config_file.write_bytes(b"")
		OpsiConfig._instances = {}
		config = OpsiConfig()
		global_conf.write_text("\n\n", encoding="utf-8")
		with environment({"OPSI_HOST_ID": "", "OPSI_HOSTNAME": "env-config.server.id"}):
			assert config.get("host", "id") == "env-config.server.id"

		config_file.write_bytes(b"")
		OpsiConfig._instances = {}
		config = OpsiConfig()
		with environment({"OPSI_HOST_ID": "env-config2.server.id", "OPSI_HOSTNAME": ""}):
			assert config.get("host", "id") == "env-config2.server.id"


def test_read_config_file(tmp_path: Path) -> None:
	config_file = tmp_path / "opsi.conf"
	OpsiConfig._instances = {}
	OpsiConfig.config_file = str(config_file)
	data = """
	[ldap_auth]
	ldap_url = "ldaps://test"
	"""
	config_file.write_text(dedent(data), encoding="utf-8")
	config = OpsiConfig()
	assert config._config_file_mtime == 0.0
	assert config.get("ldap_auth", "ldap_url") == "ldaps://test"
	mtime = config._config_file_mtime
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
	OpsiConfig._instances = {}
	OpsiConfig.config_file = str(config_file)
	data = """
	[groups]
	fileadmingroup = "FaG"
	"""
	config_file.write_text(dedent(data), encoding="utf-8")
	config = OpsiConfig()
	assert isinstance(config.get("groups", "fileadmingroup"), str)
	assert config.get("groups", "fileadmingroup") == "fag"
	conf_dict = config.get("groups")
	for key, val in conf_dict.items():
		assert isinstance(key, str)
		assert isinstance(val, str)
	assert conf_dict["fileadmingroup"] == "fag"


def test_set_config(tmp_path: Path) -> None:
	config_file = tmp_path / "opsi.conf"
	OpsiConfig._instances = {}
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


def test_default_user_when_config_file_not_exist() -> None:
	# Remove the opsiconfd configuration file if it exists
	if Path(OPSICONFD_CONF).exists():
		Path(OPSICONFD_CONF).unlink()
	get_opsiconfd_user.cache_clear()
	# Call the function and assert the return value is the default opsiconfd user
	assert get_opsiconfd_user() == DEFAULT_OPSICONFD_USER


def test_run_as_user_value_from_config_file(tmp_path: Path) -> None:
	confd_conf = tmp_path / "opsiconfd.conf"
	with patch("opsicommon.config.opsi.OPSICONFD_CONF", str(confd_conf)):
		get_opsiconfd_user.cache_clear()
		config_file = Path(confd_conf)
		config_file.write_text("run-as-user = test_user", encoding="utf-8")

		# Call the function and assert the return value is the run-as-user value from the config file
		assert get_opsiconfd_user() == "test_user"


def test_ignore_commented_and_invalid_lines_in_config_file(tmp_path: Path) -> None:
	confd_conf = tmp_path / "opsiconfd.conf"
	with patch("opsicommon.config.opsi.OPSICONFD_CONF", str(confd_conf)):
		get_opsiconfd_user.cache_clear()
		config_file = Path(confd_conf)
		config_file.write_text("# run-as-user = test_user\ninvalid_line\n", encoding="utf-8")

		# Call the function and assert the return value is the default opsiconfd user
		assert get_opsiconfd_user() == DEFAULT_OPSICONFD_USER


def test_config_file_with_run_as_user_line(tmp_path: Path) -> None:
	confd_conf = tmp_path / "opsiconfd.conf"
	with patch("opsicommon.config.opsi.OPSICONFD_CONF", str(confd_conf)):
		get_opsiconfd_user.cache_clear()
		config_file = Path(confd_conf)
		config_file.write_text(
			"""
# For available options see: opsiconfd --help
# config examples:
# log-level-file = 5
# networks = [192.168.0.0/16, 10.0.0.0/8, ::/0]
# update-ip = true
# skip-setup = [ssl, file_permissions]
run-as-user = opsiconfd-dev
grafana-internal-url = http://opsiconfd:aqmfgATF@localhost:3000
port = 443
		""",
			encoding="utf-8",
		)
		# Call the function and assert the return value is the default opsiconfd user
		assert get_opsiconfd_user() == "opsiconfd-dev"


def test_config_file_without_run_as_user_line(tmp_path: Path) -> None:
	confd_conf = tmp_path / "opsiconfd.conf"
	with patch("opsicommon.config.opsi.OPSICONFD_CONF", str(confd_conf)):
		get_opsiconfd_user.cache_clear()
	config_file = Path(confd_conf)
	config_file.write_text(
		"""
# For available options see: opsiconfd --help
# config examples:
# log-level-file = 5
# networks = [192.168.0.0/16, 10.0.0.0/8, ::/0]
# update-ip = true
# skip-setup = [ssl, file_permissions]
grafana-internal-url = http://opsiconfd:aqmfgATF@localhost:3000
port = 443
	""",
		encoding="utf-8",
	)
	# Call the function and assert the return value is the default opsiconfd user
	assert get_opsiconfd_user() == DEFAULT_OPSICONFD_USER


def test_read_config_file_with_invalid_groups(tmp_path: Path) -> None:
	config_file = tmp_path / "opsi.conf"
	opsi_config = OpsiConfig()
	opsi_config.config_file = str(config_file)
	data = """
	[groups]
	fileadmingroup = "opsifile admins"
	admingroup = "opsiadmin"
	readonly = ""
	"""
	config_file.write_text(dedent(data), encoding="utf-8")
	with pytest.raises(ValueError):
		opsi_config.read_config_file()
	opsi_config.config_file = "/etc/opsi/opsi.conf"

