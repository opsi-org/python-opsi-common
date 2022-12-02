# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

from pathlib import Path
from textwrap import dedent

from opsicommon.config import OpsiConfig


def test_update_config_from_ini(tmp_path: Path) -> None:
	config_file = tmp_path / "opsi.conf"
	OpsiConfig.config_file = config_file
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
	config.update_config_file()
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
