# opsicommon is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2025 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0-only

"""
test_system_network
"""

import platform
import socket
from ipaddress import ip_network
from unittest import mock

from opsicommon.system.network import _gethostbyaddr_with_timeout, get_domain, get_fqdn, get_hostnames, get_network_info


def test_get_network_info() -> None:
	network_info = get_network_info(include_link_local=True)
	import pprint

	pprint.pprint(network_info)
	assert network_info.interfaces
	assert network_info.routes
	assert network_info.dns_nameservers
	assert network_info.search_domains
	default_routes = [route for route in network_info.routes if route.is_default]
	assert default_routes
	default_route_interfaces = [interface for interface in network_info.interfaces if interface.is_default_gateway]
	assert default_route_interfaces
	assert set(route.interface_name for route in default_routes) == set(interface.name for interface in default_route_interfaces)
	assert any(interface.is_loopback for interface in network_info.interfaces)
	assert any(not interface.is_loopback for interface in network_info.interfaces)
	for interface in network_info.interfaces:
		if interface.prefixlen and interface.broadcast:
			network = ip_network(f"{interface.address}/{interface.prefixlen}", strict=False)
			assert interface.broadcast == network.broadcast_address
	if platform.system() == "Linux":
		# TODO: Currently not working on Windows and macOS, needs further investigation
		assert all(interface.mac_address == "00:00:00:00:00:00" for interface in network_info.interfaces if interface.is_loopback)


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
	with mock.patch("socket.getfqdn", lambda x=None: "hostname.domain.org"):
		assert get_domain() == "domain.org"


def test_get_hostnames() -> None:
	hostnames = get_hostnames()
	print(hostnames)
	assert "localhost" in hostnames


def test_gethostbyaddr_with_timeout() -> None:
	exc: Exception | None = None
	try:
		_gethostbyaddr_with_timeout("test.unavail.lan", 0.001)
	except (TimeoutError, socket.error) as err:
		exc = err
	assert exc
	assert _gethostbyaddr_with_timeout("127.0.0.1", 1.0)[0] in ("localhost", socket.gethostname())
	assert _gethostbyaddr_with_timeout("127.0.0.1", 1.0)[0] in ("localhost", socket.gethostname())
