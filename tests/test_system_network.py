# opsicommon is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2025 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0-only

"""
test_system_network
"""

import socket
from unittest import mock

from opsicommon.system.network import _gethostbyaddr_with_timeout, get_domain, get_fqdn, get_hostnames, get_network_info


def test_get_network_info() -> None:
	network_info = get_network_info(include_link_local=True)
	assert network_info.interfaces
	assert network_info.routes
	assert any(route.is_default for route in network_info.routes)
	assert any(interface.is_link_local for interface in network_info.interfaces)
	assert any(not interface.is_link_local for interface in network_info.interfaces)


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


def test_gethostbyaddr_with_timeout() -> None:
	exc: Exception | None = None
	try:
		_gethostbyaddr_with_timeout("test.unavail.lan", 0.001)
	except (TimeoutError, socket.error) as err:
		exc = err
	assert exc
	assert _gethostbyaddr_with_timeout("127.0.0.1", 1.0)[0] in ("localhost", socket.gethostname())
