# opsicommon is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2025 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0-only

"""
test_system_network
"""

import socket
from unittest import mock

from opsicommon.system.network import _gethostbyaddr_with_timeout, get_domain, get_fqdn, get_hostnames, get_ip_addresses


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


def test_gethostbyaddr_with_timeout() -> None:
	exc: Exception | None = None
	try:
		_gethostbyaddr_with_timeout("test.unavail.lan", 0.001)
	except (TimeoutError, socket.error) as err:
		exc = err
	assert exc
	assert _gethostbyaddr_with_timeout("127.0.0.1", 1.0)[0] in ("localhost", socket.gethostname())
