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
from enum import Enum
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path
from typing import Dict, Optional, Tuple, Union
from urllib.parse import quote, unquote, urlparse

import urllib3.util.connection
from OpenSSL.crypto import (  # type: ignore[import]
	FILETYPE_PEM,
	dump_certificate,
	load_certificate,
)
from requests import Session
from requests.exceptions import SSLError, Timeout
from requests.structures import CaseInsensitiveDict
from urllib3.exceptions import InsecureRequestWarning

from opsicommon import __version__
from opsicommon.exceptions import (
	OpsiConnectionError,
	OpsiServiceError,
	OpsiServiceVerificationError,
	OpsiTimeoutError,
)
from opsicommon.logging import get_logger, secret_filter
from opsicommon.utils import prepare_proxy_environment

warnings.simplefilter("ignore", InsecureRequestWarning)

_DEFAULT_HTTPS_PORT = 4447

# It is possible to set multiple certificates as UIB_OPSI_CA
UIB_OPSI_CA = """-----BEGIN CERTIFICATE-----
MIIFvjCCA6agAwIBAgIWb3BzaS11aWItY2EtMjE1NzMwODcwNzANBgkqhkiG9w0B
AQsFADB+MQswCQYDVQQGEwJERTELMAkGA1UECAwCUlAxDjAMBgNVBAcMBU1haW56
MREwDwYDVQQKDAh1aWIgR21iSDENMAsGA1UECwwEb3BzaTEUMBIGA1UEAwwLdWli
IG9wc2kgQ0ExGjAYBgkqhkiG9w0BCQEWC2luZm9AdWliLmRlMB4XDTIxMDIyNjEy
NTMxNloXDTQ4MDcxNDEyNTMxNlowfjELMAkGA1UEBhMCREUxCzAJBgNVBAgMAlJQ
MQ4wDAYDVQQHDAVNYWluejERMA8GA1UECgwIdWliIEdtYkgxDTALBgNVBAsMBG9w
c2kxFDASBgNVBAMMC3VpYiBvcHNpIENBMRowGAYJKoZIhvcNAQkBFgtpbmZvQHVp
Yi5kZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALJn/XO2KV8Ax9I2
5PcaN13kat8Y7xB0MVrU64iwLtoYSjayQ62tcmcJNBQeo6x4COQdp3XQTvy7fCjS
y6O9WwySr920Wh2/etZkXNA6qgqqLBSx6hw8zCGXPLuxkT/INvFVr3zWaH4Irx2o
SB94cPvvM3mnp3vhhphBDJUKqIvm7uz2h5npMVD0UJCeLhcG9iBe7FcRT3xaUDmi
QDE5norGK2YS/kvMv1lGAxcoM8dJ3Dl0hAn6mFKJ7lIBzojxSuNQuBMZlx7OsCbS
p0u4dGR82LYTX2RZvZOJIQPEn+XzsyNG/2vHjlnVDLUikrdRs3IJ8pJQyIAOF1aq
tb5X4K/Syy8OIV71++hvnksEiI2JgBti6IdFgHVCb034hHhzblQdwZeRsQXy5b6X
ZibrRkhkoRXptHkLb3Qt3yvi1xtmvR5le5Jh7AczjTYVAx0EToEq2WLZFyhTgQgH
0PZthUeb0q9fBUZoqpppePBU+BnKvVga8hRpVapx4gy7Ms6SaHMZhKVR7aBAAbmb
IhCWJ3dQPbWa/De8JC5SaEQMWyg+UPD+6N8EZXIsAXczqjnSLfbfXBHlPrfxVVOD
YtvhNaSchyXjXEpCqXrTJtYrxQ3m7YGXfs8+P7Ncbl2py7bvYKBl1c7KeqJctUgK
vu6ym8XjsMWSK/YZABCNB4dL6mOTAgMBAAGjMjAwMB0GA1UdDgQWBBTpzwF8edXy
f1RBXkqReeeCTKvrpTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IC
AQCgLNQiM70eW7yc0Jrnklwm8euWh5s7iVr9hCaM8LaYXrk1LY04W4WpQPyk0CnW
jlwbsSfvksc65HwkK7W2M/CGo98Dc9bgLvhDRa90+18ktiF54TlTRy1DeGEfxcF0
CAEqWMcSTxkaMdWEI/DlWmwKlHmH+NyoajA/iJq+0yMr8TKIKmIoX0f7TuXiiPM+
roWG814e5dvapr3rYE5m6sf7kjVufaTEHWogo5oFHtXzTA04L51ZBvZl09isN+OK
eD0dL26/rdTiLOetGnta5BX0Rt1Ua4xUQPxgxVS70n9SN5gSo3LKEMAVRZvF56xz
mcDrJFQM6pEJ/uoH5cJe+EL0YMGndrKPeXFrIhdY64R4WY/iGNFXl0EOL2SX0M81
D+CAXzvO0SPjJLTrYIfpBqq0LaPAv6V5JlwpW27BL4jdmc9ADj9c4nPRzXU6d1Tb
6avQ4OyVgU/wUoUwq6AsO2BMVmfu5JS02Phl+WG7T+CR7HigNjr5nRJk2HayJ+z1
6HIb8KmSqzTt+5VuwSkMLDdUXVt2Dok9dzKYFufWvrvDnZnz0svDwToQ9LAjXFij
igDA0os9lNV7Pn4nlK0c+Fk/2+wZdF4rzl0Bia4C6CMso0M+3Kqe7aqY6+/I6jgy
kGOsCMSImzajpmtonx3ccPgSOyEWyoEaGij6u80QtFkj9g==
-----END CERTIFICATE-----"""


class ServiceVerificationModes(str, Enum):
	STRICT_CHECK = "strict_check"
	FETCH_CA = "fetch_ca"
	FETCH_CA_TRUST_UIB = "fetch_ca_trust_uib"
	ACCEPT_ALL = "accept_all"


logger = get_logger("opsicommon.general")


class ServiceClient:  # pylint: disable=too-many-instance-attributes
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
		ca_cert_file: Union[str, Path] = None,
		verify: str = ServiceVerificationModes.STRICT_CHECK,
		session_cookie: str = None,
		session_lifetime: int = 150,
		proxy_url: str = "system",
		ip_version: Union[str, int] = "auto",
		user_agent: str = None,
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

		self._ca_cert_file = None
		if ca_cert_file:
			if not isinstance(ca_cert_file, Path):
				ca_cert_file = Path(ca_cert_file)
			self._ca_cert_file = ca_cert_file

		if verify and not isinstance(verify, ServiceVerificationModes):
			verify = ServiceVerificationModes(verify)
		if verify not in ServiceVerificationModes:
			raise ValueError("Invalid verification mode")
		if verify in (ServiceVerificationModes.FETCH_CA, ServiceVerificationModes.FETCH_CA_TRUST_UIB) and not self._ca_cert_file:
			raise ValueError("ca_cert_file required for selected verification mode")
		self._verify = verify

		if session_cookie and "=" not in session_cookie:
			raise ValueError("Invalid session cookie, <name>=<value> is needed")
		self._session_cookie = session_cookie or None

		self._session_lifetime = max(1, int(session_lifetime))
		self._proxy_url = str(proxy_url) if proxy_url else None

		ip_version = str(ip_version)
		if ip_version not in ("4", "6", "auto"):
			raise ValueError(f"Invalid IP version: {ip_version!r}")
		self._ip_version = ip_version

		self._user_agent = f"opsi-service-client/{__version__}" if user_agent is None else str(user_agent)
		self._connect_timeout = max(0.0, float(connect_timeout))

		self._set_address(address)

		ca_bundle = os.environ.get("REQUESTS_CA_BUNDLE", None)
		if ca_bundle:
			logger.warning("Environment variable REQUESTS_CA_BUNDLE is set to %r", ca_bundle)

		if self._password:
			secret_filter.add_secrets(self._password)

		self._session = Session()
		if self._username or self._password:
			self._session.auth = (  # type: ignore[assignment] # session.auth should be Tuple of str, but that is a problem with weird locales
				(self._username or "").encode("utf-8"),
				(self._password or "").encode("utf-8"),
			)
		self._session.headers.update(
			{
				"User-Agent": self._user_agent,
				"X-opsi-session-lifetime": str(self._session_lifetime),
			}
		)
		if self._session_cookie:
			logger.confidential("Using session cookie passed: %s", self._session_cookie)
			cookie_name, cookie_value = self._session_cookie.split("=", 1)
			self._session.cookies.set(cookie_name, quote(cookie_value))  # type: ignore[no-untyped-call]

		service_hostname = urlparse(self.base_url).hostname or ""
		self._session = prepare_proxy_environment(
			service_hostname,
			self._proxy_url,
			no_proxy_addresses=self.no_proxy_addresses,
			session=self._session,
		)

		if self._verify == ServiceVerificationModes.ACCEPT_ALL:
			self._session.verify = False
		else:
			self._session.verify = str(self._ca_cert_file) if self._ca_cert_file else True

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
			try:
				ipa = ip_address(address)
				if isinstance(ipa, IPv6Address):
					address = f"[{ipa.compressed}]"
			except ValueError:
				pass
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

	def fetch_opsi_ca(self, skip_verify: bool = False) -> None:
		if not self._ca_cert_file:
			raise RuntimeError("CA cert file not set")

		logger.info("Fetching opsi CA from service")
		verify = False if skip_verify else self._session.verify

		ca_certs = []
		self._ca_cert_file.parent.mkdir(exist_ok=True)

		try:  # pylint: disable=broad-except
			response = self._session.get(f"{self.base_url}/ssl/opsi-ca-cert.pem", timeout=(self._connect_timeout, 5), verify=verify)
			response.raise_for_status()
		except Exception as err:
			raise OpsiServiceError(f"Failed to fetch opsi-ca-cert.pem: {err}") from err

		for match in re.finditer(  # pylint: disable=dotted-import-in-loop
			r"(-+BEGIN CERTIFICATE-+.*?-+END CERTIFICATE-+)", response.text, re.DOTALL  # pylint: disable=dotted-import-in-loop
		):
			try:  # pylint: disable=loop-try-except-usage
				ca_certs.append(load_certificate(FILETYPE_PEM, match.group(1).encode("utf-8")))
			except Exception as err:  # pylint: disable=broad-except
				logger.error("Failed to load cert %r: %s", match.group(1), err, exc_info=True)  # pylint: disable=loop-global-usage

		if not ca_certs:
			raise OpsiServiceError("Failed to fetch opsi-ca-cert.pem: No certificates in response")

		data = "\n".join([dump_certificate(FILETYPE_PEM, cert).decode("utf-8") for cert in ca_certs])
		if self._verify == ServiceVerificationModes.FETCH_CA_TRUST_UIB:
			data += "\n" + UIB_OPSI_CA
		self._ca_cert_file.write_text(data, encoding="utf-8")

		logger.info("CA cert file '%s' successfully updated", self._ca_cert_file)

	def connect(self) -> None:
		self.disconnect()

		ca_cert_file_exists = self._ca_cert_file and self._ca_cert_file.exists()
		verify = self._session.verify
		if (
			self._verify in (ServiceVerificationModes.FETCH_CA, ServiceVerificationModes.FETCH_CA_TRUST_UIB)
			and self._ca_cert_file
			and (not ca_cert_file_exists or self._ca_cert_file.stat().st_size == 0)
		):
			logger.info("Service verification enabled, but CA cert file %r does not exist or is empty, skipping verification")
			verify = False

		if self._ca_cert_file and verify and not ca_cert_file_exists:
			# Prevent OSError invalid path
			verify = True

		try:
			timeout = (self._connect_timeout, self._connect_timeout)
			response = self._session.head(self.base_url, timeout=timeout, verify=verify)
		except SSLError as err:
			raise OpsiServiceVerificationError(str(err)) from err
		except Exception as err:  # pylint: disable=broad-except
			raise OpsiConnectionError(str(err)) from err

		self._connected = True
		if "server" in response.headers:
			self.server_name = response.headers["server"]
			match = re.search(r"^opsi\D+(\d+\.\d+\.\d+\.\d+)", self.server_name)
			if match:
				tuple(int(v) for v in match.group(1).split("."))

		if self._verify in (ServiceVerificationModes.FETCH_CA, ServiceVerificationModes.FETCH_CA_TRUST_UIB):
			self.fetch_opsi_ca(skip_verify=not verify)

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

	def _assert_connected(self) -> None:
		if not self._connected:
			self.connect()

	def get(
		self, path: str, headers: Optional[Dict[str, str]] = None, read_timeout: float = 60.0
	) -> Tuple[int, str, CaseInsensitiveDict, bytes]:
		self._assert_connected()
		try:
			if not path.startswith("/"):
				path = f"/{path}"
			response = self._session.get(
				f"{self.base_url}{path}", headers=headers, timeout=(self._connect_timeout, read_timeout), stream=True
			)
		except Timeout as err:
			raise OpsiTimeoutError(str(err)) from err
		except Exception as err:  # pylint: disable=broad-except
			raise OpsiConnectionError(str(err)) from err
		return (response.status_code, response.reason, response.headers, response.content)
