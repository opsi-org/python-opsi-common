# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
system.network
"""

import ipaddress
import socket
from typing import Any, Generator

import psutil  # type: ignore[import]

from opsicommon.logging import get_logger
from opsicommon.types import forceFqdn

logger = get_logger("opsicommon.general")


def get_ip_addresses() -> Generator[dict[str, Any], None, None]:
	for interface, snics in psutil.net_if_addrs().items():
		for snic in snics:
			family = None
			if snic.family == socket.AF_INET:
				family = "ipv4"
			elif snic.family == socket.AF_INET6:
				family = "ipv6"
			else:
				continue

			ip_address = None
			try:
				ip_address = ipaddress.ip_address(snic.address.split("%")[0])
			except ValueError:
				logger.warning("Unrecognised ip address: %r", snic.address)
				continue

			yield {"family": family, "interface": interface, "address": snic.address, "ip_address": ip_address}


def get_fqdn() -> str:
	fqdn = socket.getfqdn()
	try:
		return forceFqdn(fqdn.lower())
	except ValueError:
		pass

	for addresses in psutil.net_if_addrs().values():
		for addr in addresses:
			if addr.family not in (socket.AF_INET, socket.AF_INET6) or addr.address in ("127.0.0.1", "::1"):
				continue
			try:
				fqdn = socket.getfqdn(addr.address)
				if fqdn != addr.address:
					return forceFqdn(fqdn.lower())
			except (socket.error, ValueError):
				pass

	raise RuntimeError("Failed to get fqdn")


def get_domain() -> str:
	return ".".join(get_fqdn().split(".")[1:])


def get_hostnames() -> set[str]:
	names = {"localhost", "ip6-localhost", "ip6-loopback"}
	try:
		names.add(get_fqdn())
	except RuntimeError as err:
		logger.info("Failed to get fqdn: %s", err)
	for addr in get_ip_addresses():
		try:
			(hostname, aliases, _addr) = socket.gethostbyaddr(addr["address"])
			names.add(hostname)
			for alias in aliases:
				names.add(alias)
		except socket.error as err:
			logger.info("No hostname for %s: %s", addr, err)
	return names
