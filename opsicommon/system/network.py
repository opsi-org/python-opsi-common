# opsicommon is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2025 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0-only

"""
system.network
"""

import concurrent.futures
import ipaddress
import socket
from dataclasses import dataclass, field

import netifaces

from opsicommon.logging import get_logger
from opsicommon.types import forceFqdn

logger = get_logger("opsicommon.general")


@dataclass
class NetworkInterface:
	"""
	Network interface information.
	"""

	family: int
	name: str
	address: ipaddress.IPv4Address | ipaddress.IPv6Address
	netmask: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
	broadcast: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
	is_link_local: bool = False


@dataclass
class NetworkRoute:
	"""
	Network route information.
	"""

	family: int
	interface_name: str
	gateway: ipaddress.IPv4Address | ipaddress.IPv6Address
	destination: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
	is_default: bool = False


@dataclass
class NetworkInformation:
	"""
	Network information.
	"""

	interfaces: list[NetworkInterface] = field(default_factory=list)
	routes: list[NetworkRoute] = field(default_factory=list)


def get_network_info(*, include_link_local: bool = True) -> NetworkInformation:
	network_info = NetworkInformation()
	default_gw = netifaces.gateways().get("default")

	if default_gw:
		for family, info in default_gw.items():
			network_info.routes.append(
				NetworkRoute(
					family=family,
					interface_name=info[1],
					gateway=ipaddress.ip_address(info[0]),
					is_default=True,
				)
			)

	for iface_name in netifaces.interfaces():
		for family in (netifaces.AF_INET, netifaces.AF_INET6):
			for info in netifaces.ifaddresses(iface_name).get(family, []):
				try:
					address = ipaddress.ip_address(info["addr"].split("%")[0])
					if (not include_link_local) and address.is_link_local:
						continue
				except ValueError:
					continue

				network_info.interfaces.append(
					NetworkInterface(
						family=family,
						name=iface_name,
						address=address,
						netmask=ipaddress.ip_network(info["netmask"]) if "netmask" in info else None,
						broadcast=ipaddress.ip_address(info["broadcast"]) if "broadcast" in info else None,
						is_link_local=address.is_link_local,
					)
				)
	return network_info


def get_fqdn() -> str:
	fqdn = ""
	try:
		fqdn = socket.getfqdn()
		return forceFqdn(fqdn.lower())
	except Exception as err:
		logger.debug("Failed to get FQDN by socket.getfqdn(): %s - %s", fqdn, err)

	for hostname in get_hostnames():
		if "." in hostname:
			try:
				return forceFqdn(hostname.lower())
			except ValueError:
				continue

	raise RuntimeError("Failed to get FQDN")


def get_domain() -> str:
	return ".".join(get_fqdn().split(".")[1:])


def _gethostbyaddr_with_timeout(address: str, timeout: float) -> tuple[str, list[str], list[str]]:
	with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
		future = executor.submit(socket.gethostbyaddr, address)
		try:
			return future.result(timeout=timeout)
		except concurrent.futures.TimeoutError:
			raise TimeoutError(f"DNS lookup for {address} timed out after {timeout} seconds")


def get_hostnames() -> set[str]:
	names = {"localhost", "ip6-localhost", "ip6-loopback"}
	try:
		names.add(forceFqdn(socket.getfqdn()))
	except Exception as err:
		logger.info("Failed to get fqdn: %s", err)
	for interface in get_network_info(include_link_local=False).interfaces:
		try:
			addr = str(interface.address)
			(hostname, aliases, _addr) = _gethostbyaddr_with_timeout(addr, timeout=0.1)
			if hostname != addr:
				names.add(hostname)
				for alias in aliases:
					names.add(alias)
		except (socket.error, TimeoutError) as err:
			logger.info("No hostname for %s: %s", addr, err)
	return names
