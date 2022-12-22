# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
test_system_network
"""

from opsicommon.system.network import (
	get_domain,
	get_fqdn,
	get_hostnames,
	get_ip_addresses,
)


def test_get_ip_addresses() -> None:
	addr = list(get_ip_addresses())
	assert addr


def test_get_fqdn() -> None:
	assert get_fqdn()


def test_get_domain() -> None:
	assert get_domain()


def test_get_hostnames() -> None:
	hostnames = get_hostnames()
	assert "localhost" in hostnames
