# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
system.network
"""

import ipaddress
import socket

import psutil  # type: ignore[import]

from opsicommon.logging import get_logger

logger = get_logger("opsicommon.general")


def get_ip_addresses():
	for interface, snics in psutil.net_if_addrs().items():  # pylint: disable=dotted-import-in-loop
		for snic in snics:
			family = None
			if snic.family == socket.AF_INET:  # pylint: disable=dotted-import-in-loop
				family = "ipv4"
			elif snic.family == socket.AF_INET6:  # pylint: disable=dotted-import-in-loop
				family = "ipv6"
			else:
				continue

			ip_address = None
			try:  # pylint: disable=loop-try-except-usage
				ip_address = ipaddress.ip_address(snic.address.split("%")[0])  # pylint: disable=dotted-import-in-loop
			except ValueError:
				logger.warning("Unrecognised ip address: %r", snic.address)  # pylint: disable=loop-global-usage
				continue

			yield {"family": family, "interface": interface, "address": snic.address, "ip_address": ip_address}


def get_fqdn():
	return socket.getfqdn().lower()


def get_domain():
	return ".".join(get_fqdn().split(".")[1:])


def get_hostnames():
	names = {"localhost"}
	names.add(get_fqdn())
	for addr in get_ip_addresses():
		try:  # pylint: disable=loop-try-except-usage
			(hostname, aliases, _addr) = socket.gethostbyaddr(addr["address"])  # pylint: disable=dotted-import-in-loop
			names.add(hostname)
			for alias in aliases:
				names.add(alias)
		except socket.error as err:  # pylint: disable=dotted-import-in-loop
			logger.info("No hostname for %s: %s", addr, err)  # pylint: disable=loop-global-usage
	return names
