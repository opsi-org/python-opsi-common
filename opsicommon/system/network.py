# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
system.network
"""

import ipaddress
import socket
from typing import Any, Dict, Generator, Set

import psutil  # type: ignore[import]

from opsicommon.logging import get_logger

logger = get_logger("opsicommon.general")


def get_ip_addresses() -> Generator[Dict[str, Any], None, None]:
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
	return socket.getfqdn().lower()


def get_domain() -> str:
	return ".".join(get_fqdn().split(".")[1:])


def get_hostnames() -> Set[str]:
	names = {"localhost"}
	names.add(get_fqdn())
	for addr in get_ip_addresses():
		try:
			(hostname, aliases, _addr) = socket.gethostbyaddr(addr["address"])
			names.add(hostname)
			for alias in aliases:
				names.add(alias)
		except socket.error as err:
			logger.info("No hostname for %s: %s", addr, err)
	return names
