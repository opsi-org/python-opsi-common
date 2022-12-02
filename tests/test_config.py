# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

from pathlib import Path
from textwrap import dedent

import pytest
from opsicommon.config import OpsiConfig


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
	assert new_data == dedent(
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
	)


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
	assert config.get("groups", "fileadmingroup") == "fag"


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
