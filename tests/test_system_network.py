# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
test_system_network
"""

import socket
from unittest import mock

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
	fqdn = socket.getfqdn()
	if "." in fqdn:
		assert fqdn == socket.getfqdn()
	try:
		with mock.patch("socket.getfqdn", lambda x=None: "hostname"):
			assert "." in get_fqdn()
	except RuntimeError:
		pass


def test_get_domain() -> None:
	assert get_domain()


def test_get_hostnames() -> None:
	hostnames = get_hostnames()
	assert "localhost" in hostnames
