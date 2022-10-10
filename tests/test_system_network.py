# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
test_system_network
"""

from opsicommon.system.network import (
	get_ip_addresses, get_fqdn, get_domain, get_hostnames
)


def test_get_ip_addresses():
	addr = list(get_ip_addresses())
	assert addr


def test_get_fqdn():
	assert get_fqdn()


def test_get_domain():
	assert get_domain()


def test_get_hostnames():
	hostnames = get_hostnames()
	assert "localhost" in hostnames
