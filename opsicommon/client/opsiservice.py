# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import os
import re
import socket
import warnings
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path
from typing import Optional, Union
from urllib.parse import quote, unquote, urlparse

import requests
import urllib3.util.connection
from urllib3.exceptions import InsecureRequestWarning

from opsicommon import __version__
from opsicommon.logging import get_logger, secret_filter
from opsicommon.utils import prepare_proxy_environment

warnings.simplefilter("ignore", InsecureRequestWarning)

_DEFAULT_HTTPS_PORT = 4447

logger = get_logger("opsicommon.general")


class OPSIServiceClient:  # pylint: disable=too-many-instance-attributes
	rpc_timeouts = {
		"depot_installPackage": 3600,
		"depot_librsyncPatchFile": 24 * 3600,
		"depot_getMD5Sum": 3600,
	}
	no_proxy_addresses = ["localhost", "127.0.0.1", "ip6-localhost", "::1"]  # pylint: disable=use-tuple-over-list

	def __init__(  # pylint: disable=too-many-branches,too-many-statements,too-many-locals
		self,
		address: str,
		*,
		username: str = None,
		password: str = None,
		verify_server_cert: bool = True,
		ca_cert_file: Union[str, Path] = None,
		session_cookie: str = None,
		session_lifetime: int = 150,
		proxy_url: str = "system",
		ip_version: Union[str, int] = "auto",
		user_agent: str = f"opsi-service-client/{__version__}",
		connect_timeout: float = 10.0,
	) -> None:
		"""
		proxy_url:
			system = Use system proxy
			None = Do not use a proxy
		"""
		self.base_url = "https://localhost:4447"
		self.server_name = ""
		self.server_version = (0, 0, 0, 0)
		self._connected = False

		self._username = username
		self._password = password

		self._verify_server_cert = bool(verify_server_cert)
		self._ca_cert_file = str(ca_cert_file) if ca_cert_file else None

		if session_cookie and "=" not in session_cookie:
			raise ValueError("Invalid session cookie, <name>=<value> is needed")
		self._session_cookie = session_cookie or None

		self._session_lifetime = int(session_lifetime)
		self._proxy_url = str(proxy_url) if proxy_url else None

		ip_version = str(ip_version)
		if ip_version not in ("4", "6", "auto"):
			raise ValueError(f"Invalid IP version: {ip_version!r}")
		self._ip_version = ip_version

		self._user_agent = str(user_agent)
		self._connect_timeout = float(connect_timeout)

		self._set_address(address)

		ca_bundle = os.environ.get("REQUESTS_CA_BUNDLE", None)
		if ca_bundle:
			logger.warning("Environment variable REQUESTS_CA_BUNDLE is set to %r", ca_bundle)

		if self._password:
			secret_filter.add_secrets(self._password)

		self._session = requests.Session()
		if self._username or self._password:
			self._session.auth = (  # type: ignore # session.auth should be Tuple of str, but that is a problem with weird locales
				(self._username or "").encode("utf-8"),
				(self._password or "").encode("utf-8"),
			)
		self._session.headers.update(
			{
				"User-Agent": user_agent,
				"X-opsi-session-lifetime": str(self._session_lifetime),
			}
		)
		if self._session_cookie:
			logger.confidential("Using session cookie passed: %s", self._session_cookie)
			cookie_name, cookie_value = self._session_cookie.split("=", 1)
			self._session.cookies.set(cookie_name, quote(cookie_value))

		service_hostname = urlparse(self.base_url).hostname or ""
		self._session = prepare_proxy_environment(
			service_hostname,
			self._proxy_url,
			no_proxy_addresses=self.no_proxy_addresses,
			session=self._session,
		)

		if self._verify_server_cert:
			self._session.verify = self._ca_cert_file or True
		else:
			self._session.verify = False

		try:
			service_ip = ip_address(service_hostname)
			if isinstance(service_ip, IPv6Address) and self._ip_version != "6":
				logger.info("%s is an IPv6 address, forcing IPv6", service_ip.compressed)
				self._ip_version = "6"
			elif isinstance(service_ip, IPv4Address) and self._ip_version != "4":
				logger.info("%s is an IPv4 address, forcing IPv4", service_ip.compressed)
				self._ip_version = "4"
		except ValueError:
			pass

		setattr(urllib3.util.connection, "allowed_gai_family", self._allowed_gai_family)

	def _allowed_gai_family(self) -> int:
		"""This function is designed to work in the context of
		getaddrinfo, where family=socket.AF_UNSPEC is the default and
		will perform a DNS search for both IPv6 and IPv4 records."""
		# https://github.com/urllib3/urllib3/blob/main/src/urllib3/util/connection.py

		logger.debug("Using ip version %s", self._ip_version)
		if self._ip_version == "4":
			return socket.AF_INET
		if self._ip_version == "6":
			return socket.AF_INET6
		if urllib3.util.connection.HAS_IPV6:
			return socket.AF_UNSPEC
		return socket.AF_INET

	def _set_address(self, address: str) -> None:
		if "://" not in address:
			address = f"https://{address}"
		url = urlparse(address)
		if url.scheme != "https":
			raise ValueError(f"Protocol {url.scheme} not supported")

		hostname = str(url.hostname)
		if ":" in hostname:
			hostname = f"[{hostname}]"
		self.base_url = f"{url.scheme}://{hostname}:{url.port or _DEFAULT_HTTPS_PORT}"
		if url.username and not self._username:
			self._username = url.username
		if url.password and not self._password:
			self._password = url.password

	@property
	def session_coockie(self) -> Optional[str]:
		if not self._session.cookies or not self._session.cookies._cookies:  # type: ignore[attr-defined] # pylint: disable=protected-access
			return None
		for tmp1 in self._session.cookies._cookies.values():  # type: ignore[attr-defined] # pylint: disable=protected-access
			for tmp2 in tmp1.values():
				for cookie in tmp2.values():
					return f"{cookie.name}={unquote(cookie.value)}"
		return None

	def connect(self) -> None:
		self.disconnect()

		response = self._session.head(self.base_url, timeout=(self._connect_timeout, self._connect_timeout))
		if "server" in response.headers:
			self.server_name = response.headers["server"]
			match = re.search(r"^opsi\D+(\d+\.\d+\.\d+\.\d+)", self.server_name)
			if match:
				tuple(int(v) for v in match.group(1).split("."))

	def disconnect(self) -> None:
		if self._connected:
			try:
				# TODO: server version specific session deletion (backend_exit or /session/logout)
				self._session.close()
			except Exception:  # pylint: disable=broad-except
				pass
		self._connected = False
		self.server_version = (0, 0, 0, 0)
		self.server_name = ""
