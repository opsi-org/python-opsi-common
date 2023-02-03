# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""
# pylint: disable=too-many-lines

from __future__ import annotations

import asyncio
import gzip
import os
import re
import ssl
import time
import warnings
from base64 import b64encode
from contextlib import contextmanager
from contextvars import copy_context
from dataclasses import astuple, dataclass
from datetime import datetime
from enum import Enum
from ipaddress import IPv6Address, ip_address
from pathlib import Path
from threading import Event, Lock, Thread
from traceback import TracebackException
from types import MethodType, TracebackType
from typing import Any, Callable, Generator, Iterable, Type
from urllib.parse import quote, unquote, urlparse
from uuid import uuid4

import lz4.frame  # type: ignore[import,no-redef]
import msgspec
from OpenSSL.crypto import (  # type: ignore[import]
	FILETYPE_PEM,
	X509,
	dump_certificate,
	load_certificate,
)
from packaging import version
from requests import HTTPError
from requests import Response as RequestsResponse
from requests import Session
from requests.exceptions import SSLError, Timeout
from requests.structures import CaseInsensitiveDict
from urllib3.exceptions import InsecureRequestWarning
from websocket import WebSocketApp  # type: ignore[import]
from websocket._abnf import ABNF  # type: ignore[import]

from .. import __version__
from ..exceptions import (
	OpsiRpcError,
	OpsiServiceAuthenticationError,
	OpsiServiceConnectionError,
	OpsiServiceError,
	OpsiServicePermissionError,
	OpsiServiceTimeoutError,
	OpsiServiceUnavailableError,
	OpsiServiceVerificationError,
)
from ..logging import get_logger, secret_filter
from ..messagebus import (
	ChannelSubscriptionEventMessage,
	ChannelSubscriptionRequestMessage,
	JSONRPCRequestMessage,
	JSONRPCResponseMessage,
	Message,
	MessageType,
	timestamp,
)
from ..objects import deserialize, serialize
from ..system import set_system_datetime
from ..types import forceHostId, forceOpsiHostKey
from ..utils import prepare_proxy_environment

warnings.simplefilter("ignore", InsecureRequestWarning)


MIN_VERSION_MESSAGEBUS = version.parse("4.2.0.287")
MIN_VERSION_MSGPACK = version.parse("4.2.0.171")
MIN_VERSION_LZ4 = version.parse("4.2.0.171")
MIN_VERSION_GZIP = version.parse("4.2.0.0")
MIN_VERSION_SESSION_API = version.parse("4.2.0.285")

RPC_TIMEOUTS = {
	"depot_installPackage": 3600,
	"depot_librsyncPatchFile": 24 * 3600,
	"depot_getMD5Sum": 3600,
}

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


logger = get_logger("opsicommon.general")


class ServiceVerificationFlags(str, Enum):
	STRICT_CHECK = "strict_check"
	OPSI_CA = "opsi_ca"
	UIB_OPSI_CA = "uib_opsi_ca"
	ACCEPT_ALL = "accept_all"
	REPLACE_EXPIRED_CA = "replace_expired_ca"


class CallbackThread(Thread):
	def __init__(self, callback: Callable, **kwargs: Any) -> None:
		super().__init__()
		self.daemon = True
		self.callback = callback
		self.kwargs = kwargs
		self._context = copy_context()

	def run(self) -> None:
		for var in self._context:
			var.set(self._context[var])
		try:
			self.callback(**self.kwargs)
		except Exception as err:  # pylint: disable=broad-except
			logger.error("Error in %s: %s", self, err, exc_info=True)


class ServiceConnectionListener:  # pylint: disable=too-few-public-methods
	def connection_open(self, service_client: ServiceClient) -> None:
		"""
		Called when the connection to the service is opened.
		"""

	def connection_established(self, service_client: ServiceClient) -> None:
		"""
		Called when the connection to the service is established.
		"""

	def connection_closed(self, service_client: ServiceClient) -> None:
		"""
		Called when the connection to the service is close.
		"""

	def connection_failed(self, service_client: ServiceClient, exception: Exception) -> None:
		"""
		Called when a connection to the service failed.
		"""

	@contextmanager
	def register(self, service_client: ServiceClient) -> Generator[None, None, None]:
		"""
		Context manager for register this listener on and off the message bus.
		"""
		try:
			service_client.register_connection_listener(self)
			yield
		finally:
			service_client.unregister_connection_listener(self)


@dataclass
class Response:
	status_code: int
	reason: str
	headers: CaseInsensitiveDict
	content: bytes

	def __getitem__(self, item: int) -> int | str | CaseInsensitiveDict | bytes:
		return astuple(self)[item]

	def __iter__(self) -> Generator[int | str | CaseInsensitiveDict | bytes, None, None]:
		for item in astuple(self):
			yield item


class ServiceClient:  # pylint: disable=too-many-instance-attributes,too-many-public-methods
	no_proxy_addresses = ["localhost", "127.0.0.1", "ip6-localhost", "::1"]

	def __init__(  # pylint: disable=too-many-branches,too-many-statements,too-many-locals
		self,
		address: Iterable[str] | str,
		*,
		username: str | None = None,
		password: str | None = None,
		ca_cert_file: str | Path | None = None,
		verify: str | Iterable[str] = ServiceVerificationFlags.STRICT_CHECK,
		session_cookie: str | None = None,
		session_lifetime: int = 150,
		proxy_url: str | None = "system",
		user_agent: str | None = None,
		connect_timeout: float = 10.0,
		max_time_diff: float = 5.0,
		jsonrpc_create_objects: bool = False,
		jsonrpc_create_methods: bool = False,
	) -> None:
		"""
		proxy_url:
			system = Use system proxy
			None = Do not use a proxy

		verify:
			strict_check:
				Check server certifcate against default certs or ca_cert_file if provided.
			opsi_ca:
				Needs ca_cert_file to be set.
				Check server certifcate against ca_cert_file.
				If ca_cert_file missing or empty, accept every certificate once.
				Fetch opsi ca from service after each successful connection.
			uib_opsi_ca:
				Accept server certficates signed by uib.
			accept_all:
				Do not check server certificate.
				Fetch opsi ca from service and update ca_cert_file if provided.
			replace_expired_ca:
				To use in combination with opsi_ca.
				If opsi_ca from ca_cert_file is expired, accept every certificate once.
		"""
		self._messagebus = Messagebus(self)

		self._addresses: list[str] = []
		self._address_index = 0
		self.server_name = ""
		self.server_version = version.parse("0")
		self.new_host_id: str | None = None
		self.new_host_key: str | None = None
		self.jsonrpc_create_objects = bool(jsonrpc_create_objects)
		self.jsonrpc_create_methods = bool(jsonrpc_create_methods)
		self.jsonrpc_interface: list[dict[str, Any]] = []
		self._jsonrpc_path = "/rpc"
		self._jsonrpc_method_params: dict[str, dict[str, Any]] = {}
		self._messagebus_available = False
		self._connected = False
		self._max_time_diff = max_time_diff
		self._connect_lock = Lock()
		self._messagebus_connect_lock = Lock()
		self._listener_lock = Lock()
		self._listener: list[ServiceConnectionListener] = []
		self._service_unavailable: OpsiServiceUnavailableError | None = None
		self._username = ""
		self._password = ""

		self._msgpack_decoder = msgspec.msgpack.Decoder()
		self._msgpack_encoder = msgspec.msgpack.Encoder()
		self._json_decoder = msgspec.json.Decoder()
		self._json_encoder = msgspec.json.Encoder()

		self._session = Session()

		self.username = username
		self.password = password

		self.set_addresses(address)

		self._ca_cert_file = None
		if ca_cert_file:
			if not isinstance(ca_cert_file, Path):
				ca_cert_file = Path(ca_cert_file)
			self._ca_cert_file = ca_cert_file

		verify = verify or []
		if isinstance(verify, (str, ServiceVerificationFlags)):
			verify = [verify]  # type: ignore[list-item]

		self._verify: list[ServiceVerificationFlags] = []
		for verify_flag in list(verify):
			if not isinstance(verify_flag, ServiceVerificationFlags):
				verify_flag = ServiceVerificationFlags(verify_flag)
			if verify_flag not in ServiceVerificationFlags:
				raise ValueError(f"Invalid verification mode {verify_flag}")
			self._verify.append(verify_flag)

		if ServiceVerificationFlags.STRICT_CHECK in self._verify:
			self._verify = [ServiceVerificationFlags.STRICT_CHECK]

		if ServiceVerificationFlags.UIB_OPSI_CA in verify and ServiceVerificationFlags.OPSI_CA not in self._verify:
			self._verify.append(ServiceVerificationFlags.OPSI_CA)

		if ServiceVerificationFlags.OPSI_CA in self._verify and not self._ca_cert_file:
			raise ValueError(f"ca_cert_file required for selected {ServiceVerificationFlags.OPSI_CA}")

		if session_cookie and "=" not in session_cookie:
			raise ValueError("Invalid session cookie, <name>=<value> is needed")
		self._session_cookie = session_cookie or None

		self._session_lifetime = max(1, int(session_lifetime))
		self._proxy_url = str(proxy_url) if proxy_url else None

		self._user_agent = f"opsi-service-client/{__version__}" if user_agent is None else str(user_agent)
		self._connect_timeout = max(0.0, float(connect_timeout))

		self.default_headers = {
			"User-Agent": self._user_agent,
			"X-opsi-session-lifetime": str(self._session_lifetime),
		}

		ca_bundle = os.environ.get("REQUESTS_CA_BUNDLE", None)
		if ca_bundle:
			logger.warning("Environment variable REQUESTS_CA_BUNDLE is set to %r", ca_bundle)

		self._session.headers.update(self.default_headers)
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

		if ServiceVerificationFlags.ACCEPT_ALL in self._verify:
			self._session.verify = False
		else:
			self._session.verify = str(self._ca_cert_file) if self._ca_cert_file else True

	def set_addresses(self, address: Iterable[str] | str) -> None:
		self._addresses = []
		self._address_index = 0

		for addr in [address] if isinstance(address, str) else address:
			if "://" not in addr:
				try:
					ipa = ip_address(addr)
					if isinstance(ipa, IPv6Address):
						addr = f"[{ipa.compressed}]"
				except ValueError:
					pass
				addr = f"https://{addr}"
			url = urlparse(addr)
			if url.scheme != "https":
				raise ValueError(f"Protocol {url.scheme} not supported")

			hostname = str(url.hostname)
			if ":" in hostname:
				hostname = f"[{hostname}]"

			if url.username is not None:
				if self.username and self.username != url.username:
					raise ValueError("Different usernames supplied")
				self.username = url.username

			if url.password is not None:
				if self.password and self.password != url.password:
					raise ValueError("Different passwords supplied")
				self.password = url.password

			path = url.path.rstrip("/")
			if path and path != "/rpc":
				self._jsonrpc_path = path

			self._addresses.append(f"{url.scheme}://{hostname}:{url.port or _DEFAULT_HTTPS_PORT}")

	@property
	def base_url(self) -> str:
		return self._addresses[self._address_index]

	@property
	def verify(self) -> list[ServiceVerificationFlags]:
		return self._verify

	@property
	def ca_cert_file(self) -> Path | None:
		return self._ca_cert_file

	@property
	def connected(self) -> bool:
		return self._connected

	@property
	def username(self) -> str | None:
		return self._username

	@username.setter
	def username(self, username: str) -> None:
		self._username = username
		self._session.auth = (  # type: ignore[assignment] # session.auth should be Tuple of str, but that is a problem with weird locales
			(self._username or "").encode("utf-8"),
			(self._password or "").encode("utf-8"),
		)

	@property
	def password(self) -> str | None:
		return self._password

	@password.setter
	def password(self, password: str) -> None:
		self._password = password
		secret_filter.add_secrets(self._password)
		self._session.auth = (  # type: ignore[assignment] # session.auth should be Tuple of str, but that is a problem with weird locales
			(self._username or "").encode("utf-8"),
			(self._password or "").encode("utf-8"),
		)

	@property
	def proxy_url(self) -> str | None:
		return self._proxy_url

	@property
	def session_cookie(self) -> str | None:
		if not self._session.cookies or not self._session.cookies._cookies:  # type: ignore[attr-defined] # pylint: disable=protected-access
			return None
		for tmp1 in self._session.cookies._cookies.values():  # type: ignore[attr-defined] # pylint: disable=protected-access
			for tmp2 in tmp1.values():
				for cookie in tmp2.values():
					return f"{cookie.name}={unquote(cookie.value)}"
		return None

	def register_connection_listener(self, listener: ServiceConnectionListener) -> None:
		with self._listener_lock:
			if listener not in self._listener:
				self._listener.append(listener)

	def unregister_connection_listener(self, listener: ServiceConnectionListener) -> None:
		with self._listener_lock:
			if listener in self._listener:
				self._listener.remove(listener)

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

		for match in re.finditer(r"(-+BEGIN CERTIFICATE-+.*?-+END CERTIFICATE-+)", response.text, re.DOTALL):
			try:
				ca_certs.append(load_certificate(FILETYPE_PEM, match.group(1).encode("utf-8")))
			except Exception as err:  # pylint: disable=broad-except
				logger.error("Failed to load cert %r: %s", match.group(1), err, exc_info=True)

		if not ca_certs:
			raise OpsiServiceError("Failed to fetch opsi-ca-cert.pem: No certificates in response")

		data = "\n".join([dump_certificate(FILETYPE_PEM, cert).decode("utf-8") for cert in ca_certs])
		if ServiceVerificationFlags.UIB_OPSI_CA in self._verify:
			data += "\n" + UIB_OPSI_CA
		self._ca_cert_file.write_text(data, encoding="utf-8")

		logger.info("CA cert file '%s' successfully updated", self._ca_cert_file)

	def opsi_ca_certs_expired(self) -> bool:
		if not self._ca_cert_file or not self._ca_cert_file.exists():
			return False

		data = self._ca_cert_file.read_text(encoding="utf-8")
		now = datetime.now()
		for match in re.finditer(r"(-+BEGIN CERTIFICATE-+.*?-+END CERTIFICATE-+)", data, re.DOTALL):
			try:
				cert = load_certificate(FILETYPE_PEM, match.group(1).encode("utf-8"))
				enddate = datetime.strptime((cert.get_notAfter() or b"").decode("utf-8"), "%Y%m%d%H%M%SZ")
				if enddate <= now:
					logger.notice("Expired certificate found: %r", cert)
					return True
			except Exception as err:  # pylint: disable=broad-except
				logger.error(err, exc_info=True)
				return True
		return False

	def get_opsi_ca_certs(self) -> list[X509]:
		ca_certs: list[X509] = []
		if not self._ca_cert_file or not self._ca_cert_file.exists() or self._ca_cert_file.stat().st_size == 0:
			return ca_certs
		try:
			data = self._ca_cert_file.read_text(encoding="utf-8")
			for match in re.finditer(r"(-+BEGIN CERTIFICATE-+.*?-+END CERTIFICATE-+)", data, re.DOTALL):
				try:
					ca_certs.append(load_certificate(FILETYPE_PEM, match.group(1).encode("utf-8")))
				except Exception as err:  # pylint: disable=broad-except
					logger.error(err, exc_info=True)
		except Exception as err:  # pylint: disable=broad-except
			logger.warning(err, exc_info=True)
		return ca_certs

	def create_jsonrpc_methods(self, instance: Any = None) -> None:  # pylint: disable=too-many-locals
		if self.jsonrpc_interface is None:
			raise ValueError("Interface description not available")

		instance = instance or self

		def backend_getInterface(self: ServiceClient) -> list[dict[str, Any]]:  # pylint: disable=invalid-name,unused-variable
			return self.jsonrpc_interface

		def backend_exit(self: ServiceClient) -> None:  # pylint: disable=unused-variable
			return self.disconnect()

		for method in self.jsonrpc_interface:  # pylint: disable=too-many-nested-blocks
			try:  # pylint: disable=too-many-nested-blocks
				method_name = method["name"]

				if method_name not in ("backend_getInterface", "backend_exit"):
					logger.debug("Creating instance method: %s", method_name)

					args = method["args"]
					varargs = method["varargs"]
					keywords = method["keywords"]
					defaults = method["defaults"]

					arg_list = []
					call_list = []
					for i, argument in enumerate(args):
						if argument == "self":
							continue

						if isinstance(defaults, (tuple, list)) and len(defaults) + i >= len(args):
							default = defaults[len(defaults) - len(args) + i]
							if isinstance(default, str):
								default = repr(default)
							arg_list.append(f"{argument}={default}")
						else:
							arg_list.append(argument)
						call_list.append(argument)

					if varargs:
						for vararg in varargs:
							arg_list.append(f"*{vararg}")
							call_list.append(vararg)

					if keywords:
						arg_list.append(f"**{keywords}")
						call_list.append(keywords)

					arg_string = ", ".join(arg_list)
					call_string = ", ".join(call_list)

					logger.trace("%s: arg string is: %s", method_name, arg_string)
					logger.trace("%s: call string is: %s", method_name, call_string)
					with warnings.catch_warnings():
						exec(  # pylint: disable=exec-used
							f'def {method_name}(self, {arg_string}): return self.jsonrpc("{method_name}", [{call_string}])'
						)
				setattr(instance, method_name, MethodType(eval(method_name), self))  # pylint: disable=eval-used
			except Exception as err:  # pylint: disable=broad-except
				logger.error("Failed to create instance method '%s': %s", method, err)

	def connect(self) -> None:  # pylint: disable=too-many-branches,too-many-statements,too-many-locals
		if self._connect_lock.locked():
			return

		self.disconnect()
		with self._connect_lock:
			ca_cert_file_exists = self._ca_cert_file and self._ca_cert_file.exists()
			verify = self._session.verify
			if ServiceVerificationFlags.OPSI_CA in self._verify and self._ca_cert_file:
				if not ca_cert_file_exists or self._ca_cert_file.stat().st_size == 0:
					logger.info(
						"Service verification enabled, but CA cert file %r does not exist or is empty, skipping verification",
						self._ca_cert_file,
					)
					verify = False
				elif ServiceVerificationFlags.REPLACE_EXPIRED_CA in self._verify and self.opsi_ca_certs_expired():
					logger.info(
						"Service verification enabled, but a certificate from CA cert file %r is expired, skipping verification",
						self._ca_cert_file,
					)
					verify = False

			if self._ca_cert_file and verify and not ca_cert_file_exists:
				# Prevent OSError invalid path
				verify = True

			for listener in self._listener:
				CallbackThread(listener.connection_open, service_client=self).start()

			for address_index in range(len(self._addresses)):
				self._address_index = address_index
				try:
					response = self._request(
						method="HEAD",
						path=self._jsonrpc_path,
						timeout=(self._connect_timeout, self._connect_timeout),
						verify=verify,
						# Accept status 405 for older opsiconfd versions
						allow_status_codes=(200, 405),
					)
					break
				except OpsiServiceError as err:
					if self._address_index >= len(self._addresses) - 1:
						for listener in self._listener:
							CallbackThread(listener.connection_failed, service_client=self, exception=err).start()
						raise

			self._connected = True
			session_cookie = self.session_cookie
			if session_cookie:
				secret_filter.add_secrets(session_cookie.split("=", 1)[-1])

			if "server" in response.headers:
				self.server_name = response.headers["server"]
				match = re.search(r"^opsi\D+([\d\.]+)", self.server_name)
				if match:
					self.server_version = version.parse(match.group(1))
					self._messagebus_available = self.server_version >= MIN_VERSION_MESSAGEBUS

			if "x-opsi-new-host-id" in response.headers:
				try:
					self.new_host_id = forceHostId(response.headers["x-opsi-new-host-id"])
				except ValueError as error:
					logger.error("Could not get HostId from header: %s", error, exc_info=True)

			if "x-opsi-new-host-key" in response.headers:
				try:
					self.new_host_key = forceOpsiHostKey(response.headers["x-opsi-new-host-key"])
				except ValueError as error:
					logger.error("Could not get OpsiHostKey from header: %s", error, exc_info=True)

			if self._max_time_diff >= 0 and "date" in response.headers:
				try:
					server_dt = datetime.strptime(response.headers["date"], "%a, %d %b %Y %H:%M:%S %Z")
					local_dt = datetime.utcnow()
					diff = server_dt - local_dt
					if diff.total_seconds() > self._max_time_diff:
						logger.warning(
							"Local time %r differs from server time (max diff: %0.3f), setting system time to %r",
							local_dt.strftime("%Y-%m-%d %H:%M:%S"),
							self._max_time_diff,
							server_dt.strftime("%Y-%m-%d %H:%M:%S"),
						)
						set_system_datetime(server_dt)
				except Exception as err:  # pylint: disable=broad-except
					logger.warning("Failed to process date header %r: %r", response.headers["date"], err)

			if self._ca_cert_file:
				self.fetch_opsi_ca(skip_verify=not verify)

		try:
			self.jsonrpc_interface = self.jsonrpc("backend_getInterface")
		except Exception as err:  # pylint: disable=broad-except
			logger.error("Failed to get interface description: %s", err, exc_info=True)

		self._jsonrpc_method_params = {}
		for method in self.jsonrpc_interface:
			self._jsonrpc_method_params[method["name"]] = {}
			def_idx = 0
			for param in method["params"]:
				default = None
				if param[0] == "*":
					param = param.lstrip("*")
					if method["defaults"]:
						try:
							default = method["defaults"][def_idx]
						except IndexError:
							pass
					def_idx += 1
				self._jsonrpc_method_params[method["name"]][param] = default

		if self.jsonrpc_create_methods:
			self.create_jsonrpc_methods()

		for listener in self._listener:
			CallbackThread(listener.connection_established, service_client=self).start()

	def disconnect(self) -> None:
		self.disconnect_messagebus()
		was_connected = self._connected
		if self._connected:
			try:
				if self.server_version >= MIN_VERSION_SESSION_API:
					self.post("/session/logout")
				else:
					self.jsonrpc("backend_exit")
			except Exception:  # pylint: disable=broad-except
				pass
			try:
				self._session.close()
			except Exception:  # pylint: disable=broad-except
				pass

		self._connected = False
		self.server_version = version.parse("0")
		self.server_name = ""
		self._messagebus_available = False

		if was_connected:
			for listener in self._listener:
				CallbackThread(listener.connection_closed, service_client=self).start()

	def _assert_connected(self) -> None:
		with self._connect_lock:
			if self._connected:
				return
		self.connect()

	def _get_url(self, path: str) -> str:
		if not path.startswith("/"):
			path = f"/{path}"
		return f"{self.base_url}{path}"

	def _request(  # pylint: disable=too-many-arguments
		self,
		method: str,
		path: str,
		headers: dict[str, str] | None = None,
		timeout: float | tuple[float, float] = 60.0,
		data: bytes | None = None,
		verify: str | bool | None = None,
		allow_status_codes: Iterable[int] | None = None,
	) -> RequestsResponse:
		if self._service_unavailable and self._service_unavailable.until and self._service_unavailable.until >= time.time():
			raise self._service_unavailable

		self._service_unavailable = None

		allow_status_codes = (200, 201, 202, 203, 204, 206, 207, 208) if allow_status_codes is None else allow_status_codes
		try:
			response = self._session.request(
				method=method, url=self._get_url(path), headers=headers, data=data, timeout=timeout, stream=True, verify=verify
			)
			if allow_status_codes and allow_status_codes != ... and response.status_code not in allow_status_codes:
				response.raise_for_status()
			return response
		except SSLError as err:
			try:
				if err.args[0].reason.args[0].errno == 8:
					# EOF occurred in violation of protocol
					raise OpsiServiceConnectionError(str(err)) from err
			except (AttributeError, IndexError):
				pass
			raise OpsiServiceVerificationError(str(err)) from err
		except Timeout as err:
			raise OpsiServiceTimeoutError(str(err)) from err
		except HTTPError as err:
			if err.response.status_code == 503:
				retry_after = 60
				try:
					retry_after = int(err.response.headers.get("Retry-After", ""))
					retry_after = max(1, min(retry_after, 7200))
				except ValueError:
					pass
				self._service_unavailable = OpsiServiceUnavailableError(
					str(err), status_code=err.response.status_code, content=err.response.text, until=time.time() + retry_after
				)
				raise self._service_unavailable from err

			cls = OpsiServiceError
			if err.response.status_code == 401:
				cls = OpsiServiceAuthenticationError
			elif err.response.status_code == 403:
				cls = OpsiServicePermissionError
			raise cls(str(err), status_code=err.response.status_code, content=err.response.text) from err
		except Exception as err:  # pylint: disable=broad-except
			raise OpsiServiceConnectionError(str(err)) from err

	def request(  # pylint: disable=too-many-arguments
		self,
		method: str,
		path: str,
		*,
		headers: dict[str, str] | None = None,
		read_timeout: float = 60.0,
		data: bytes | None = None,
		allow_status_codes: Iterable[int] | None = None,
	) -> Response:
		self._assert_connected()
		response = self._request(
			method=method, path=path, headers=headers, timeout=read_timeout, data=data, allow_status_codes=allow_status_codes
		)
		return Response(status_code=response.status_code, reason=response.reason, headers=response.headers, content=response.content)

	def get(
		self,
		path: str,
		*,
		headers: dict[str, str] | None = None,
		read_timeout: float = 60.0,
		allow_status_codes: Iterable[int] | None = None,
	) -> Response:
		return self.request("GET", path=path, headers=headers, read_timeout=read_timeout, allow_status_codes=allow_status_codes)

	def post(
		self,
		path: str,
		data: bytes | None = None,
		*,
		headers: dict[str, str] | None = None,
		read_timeout: float = 60.0,
		allow_status_codes: Iterable[int] | None = None,
	) -> Response:
		return self.request("POST", path=path, headers=headers, read_timeout=read_timeout, data=data, allow_status_codes=allow_status_codes)

	def jsonrpc(  # pylint: disable=too-many-branches,too-many-statements,too-many-locals
		self,
		method: str,
		params: tuple[Any, ...] | list[Any] | dict[str, Any] | None = None,
		read_timeout: float | None = None,
		return_result_only: bool = True,
	) -> Any:
		params = params or []
		if isinstance(params, tuple):
			params = list(params)
		if isinstance(params, dict):
			m_params = self._jsonrpc_method_params.get(method)
			if m_params is None:
				raise ValueError(f"Method {method!r} not found in interface description")

			m_param_names = list(m_params)
			new_params = list(m_params.values())
			max_idx = 0
			for name, val in params.items():
				try:
					idx = m_param_names.index(name)
				except ValueError as err:
					raise ValueError(f"Invalid param {name!r} for method {method!r}") from err
				new_params[idx] = val
				max_idx = max(max_idx, idx)
			params = [p for i, p in enumerate(new_params) if i <= max_idx]

		headers = {"Accept-Encoding": "deflate, gzip, lz4"}

		rpc_id = str(uuid4())
		data_dict = {
			"jsonrpc": "2.0",
			"id": rpc_id,
			"method": method,
			"params": serialize(params),
		}

		serialization = "msgpack" if self.server_version >= MIN_VERSION_MSGPACK else "json"
		if serialization == "msgpack":
			headers["Content-Type"] = headers["Accept"] = "application/msgpack"
			data = self._msgpack_encoder.encode(data_dict)
		else:
			headers["Content-Type"] = headers["Accept"] = "application/json"
			data = self._json_encoder.encode(data_dict)

		if not isinstance(data, bytes):
			data = data.encode("utf-8")

		if self.server_version >= MIN_VERSION_LZ4:
			logger.trace("Compressing data with lz4")
			headers["Content-Encoding"] = headers["Accept-Encoding"] = "lz4"
			data = lz4.frame.compress(data, compression_level=0, block_linked=True)
		elif self.server_version >= MIN_VERSION_GZIP:
			logger.trace("Compressing data with gzip")
			headers["Content-Encoding"] = headers["Accept-Encoding"] = "gzip"
			data = gzip.compress(data)

		if not read_timeout:
			read_timeout = float(RPC_TIMEOUTS.get(method, 300))

		logger.info(
			"JSONRPC request to %s: id=%r, method=%s, Content-Type=%s, Content-Encoding=%s, timeout=%r",
			self.base_url,
			rpc_id,
			method,
			headers.get("Content-Type", ""),
			headers.get("Content-Encoding", ""),
			read_timeout,
		)
		start_time = time.time()

		allow_status_codes = (200, 500) if return_result_only else ...
		response = self.post(
			self._jsonrpc_path,
			headers=headers,
			data=data,
			read_timeout=read_timeout,
			allow_status_codes=allow_status_codes,  # type: ignore[arg-type]
		)
		data = response.content
		content_type = response.headers.get("Content-Type", "")
		content_encoding = response.headers.get("Content-Encoding", "")
		logger.info(
			"Got response status=%s, Content-Type=%s, Content-Encoding=%s, duration=%0.3fs",
			response.status_code,
			content_type,
			content_encoding,
			(time.time() - start_time),
		)

		# gzip and deflate transfer-encodings are automatically decoded
		if "lz4" in content_encoding:
			logger.trace("Decompressing data with lz4")
			data = lz4.frame.decompress(data)

		error_cls: Type[Exception] | None = None
		error_msg = None
		if response.status_code != 200:
			error_msg = response.reason
			error_cls = OpsiRpcError
			error_msg = f"{response.status_code} - {response.reason}"

		rpc = {}
		try:
			if content_type == "application/msgpack":
				rpc = self._msgpack_decoder.decode(data)
			else:
				rpc = self._json_decoder.decode(data)
			if not return_result_only:
				return rpc
		except Exception:  # pylint: disable=broad-except
			if error_cls:
				raise error_cls(error_msg) from None
			raise

		if rpc.get("error"):
			logger.debug("JSONRPC-response contains error")
			if not error_cls:
				error_cls = OpsiRpcError
			if isinstance(rpc["error"], dict) and rpc["error"].get("message"):
				error_msg = rpc["error"]["message"]
			else:
				error_msg = str(rpc["error"])

		if error_cls:
			raise error_cls(error_msg)

		if self.jsonrpc_create_objects:
			return deserialize(rpc.get("result"))

		return rpc.get("result")

	@property
	def messagebus(self) -> "Messagebus":
		return self._messagebus

	@property
	def messagebus_available(self) -> bool:
		self._assert_connected()
		return self._messagebus_available

	def _assert_messagebus_connected(self) -> None:
		if not self.messagebus_available:
			raise RuntimeError(f"Messagebus not available (connected to: {self.server_name})")
		with self._messagebus_connect_lock:
			if not self._messagebus.connected:
				self._messagebus.connect()

	def connect_messagebus(self) -> "Messagebus":
		self._assert_messagebus_connected()
		return self._messagebus

	def disconnect_messagebus(self) -> None:
		self._messagebus.disconnect()

	def stop(self) -> None:
		self.disconnect()
		self.messagebus.stop()
		if self.messagebus.is_alive():
			self.messagebus.join(7)

	@property
	def messagebus_connected(self) -> bool:
		return self._messagebus.connected

	def __enter__(self) -> "ServiceClient":
		return self

	def __exit__(self, exc_type: Exception, exc_value: TracebackException, traceback: TracebackType) -> None:
		self.stop()


class MessagebusListener:  # pylint: disable=too-few-public-methods
	def __init__(self, message_types: Iterable[MessageType | str] | None = None) -> None:
		"""
		message_types:
		"""
		self.message_types = {MessageType(mt) for mt in message_types} if message_types else None

	def messagebus_connection_open(self, messagebus: Messagebus) -> None:
		"""
		Called when the connection to the messagebus is opened.
		"""

	def messagebus_connection_established(self, messagebus: Messagebus) -> None:
		"""
		Called when the connection to the messagebus is established.
		"""

	def messagebus_connection_closed(self, messagebus: Messagebus) -> None:
		"""
		Called when the connection to the messagebus is closed.
		"""

	def messagebus_connection_failed(self, messagebus: Messagebus, exception: Exception) -> None:
		"""
		Called when a connection to the messagebus failed.
		"""

	def message_received(self, message: Message) -> None:
		"""
		Called when a valid message is received.
		"""

	def expired_message_received(self, message: Message) -> None:
		"""
		Called when a expired message is received.
		Expired messages should not be processed!
		"""

	@contextmanager
	def register(self, messagebus: "Messagebus") -> Generator[None, None, None]:
		"""
		Context manager for register this listener on and off the message bus.
		"""
		try:
			messagebus.register_message_listener(self)
			yield
		finally:
			messagebus.unregister_message_listener(self)


class Messagebus(Thread):  # pylint: disable=too-many-instance-attributes
	_messagebus_path = "/messagebus/v1"

	def __init__(self, opsi_service_client: ServiceClient) -> None:
		super().__init__()
		self.daemon = True
		self._context = copy_context()
		self._client = opsi_service_client
		self._app: WebSocketApp | None = None
		self._should_stop = Event()
		self._should_be_connected = False
		self._connected = False
		self._connected_result = Event()
		self._connect_exception: Exception | None = None
		self._disconnected_result = Event()
		self._send_lock = Lock()
		self._listener: list[MessagebusListener] = []
		self._listener_lock = Lock()
		self._connect_timeout = 10.0
		self.ping_interval = 15.0  # Send ping every specified period in seconds.
		self.ping_timeout = 10.0  # Ping timeout in seconds.
		self.reconnect_wait = 5.0  # After connection lost, reconnect after specified seconds.
		self._next_connect_wait = 0.0
		self._subscribed_channels: list[str] = []
		self.threaded_callbacks = True
		# from websocket import enableTrace
		# enableTrace(True)

	@property
	def connected(self) -> bool:
		return self._connected

	@property
	def websocket_connected(self) -> bool:
		return bool(self._app and self._app.sock and self._app.sock.connected)

	def _on_open(self, app: WebSocketApp) -> None:  # pylint: disable=unused-argument
		logger.debug("Websocket opened")
		if not self._connected:
			logger.notice("Connected to opsi messagebus")
		self._next_connect_wait = self.reconnect_wait
		self._connected = True
		self._connected_result.set()
		if self._subscribed_channels:
			# Restore subscriptions on reconnect
			self.send_message(
				ChannelSubscriptionRequestMessage(
					sender="@", channel="service:messagebus", channels=self._subscribed_channels, operation="add"
				)
			)

		for listener in self._listener:
			self._run_listener_callback(listener, "messagebus_connection_established", messagebus=self)

	def _on_error(self, app: WebSocketApp, error: Exception) -> None:  # pylint: disable=unused-argument
		status_code = getattr(error, "status_code", 0)
		logger.error("Websocket error: %d - %s", status_code, error)
		self._connect_exception = error
		next_reconnect_wait = self._next_connect_wait or self.reconnect_wait
		if status_code == 503:
			next_reconnect_wait = 60
			try:
				next_reconnect_wait = int(getattr(error, "resp_headers", {}).get("retry-after", ""))
				next_reconnect_wait = max(1, min(next_reconnect_wait, 7200))
			except ValueError:
				pass
		self._next_connect_wait = next_reconnect_wait
		self._connected_result.set()
		for listener in self._listener:
			self._run_listener_callback(listener, "messagebus_connection_failed", messagebus=self, exception=error)

	def _on_close(self, app: WebSocketApp, close_status_code: int, close_message: str) -> None:  # pylint: disable=unused-argument
		logger.debug("Websocket closed with status_code=%r and message %r", close_status_code, close_message)
		self._connected = False
		for listener in self._listener:
			self._run_listener_callback(listener, "messagebus_connection_closed", messagebus=self)

	def _on_message(self, app: WebSocketApp, message: bytes) -> None:  # pylint: disable=unused-argument
		logger.debug("Websocket message received")
		try:
			msg = Message.from_msgpack(message)

			expired = msg.expires and msg.expires <= timestamp()
			if expired:
				callback = "expired_message_received"
				logger.debug("Received expired message: %r", msg)
			else:
				callback = "message_received"
				logger.debug("Received message: %r", msg)

			if isinstance(msg, ChannelSubscriptionEventMessage):
				self._subscribed_channels = msg.subscribed_channels

			for listener in self._listener:
				if listener.message_types and msg.type not in listener.message_types:
					continue
				self._run_listener_callback(listener, callback, message=msg)
		except Exception as err:  # pylint: disable=broad-except
			logger.error("Failed to process websocket message: %s", err, exc_info=True)

	def _on_ping(self, app: WebSocketApp, message: bytes) -> None:  # pylint: disable=unused-argument
		logger.debug("Ping message received")
		if self._app:
			self._app.send(b"", ABNF.OPCODE_PONG)

	def _on_pong(self, app: WebSocketApp, message: bytes) -> None:  # pylint: disable=unused-argument
		logger.debug("Pong message received")

	def register_message_listener(self, listener: MessagebusListener) -> None:
		with self._listener_lock:
			if listener not in self._listener:
				self._listener.append(listener)

	def unregister_message_listener(self, listener: MessagebusListener) -> None:
		with self._listener_lock:
			if listener in self._listener:
				self._listener.remove(listener)

	def _run_listener_callback(self, listener: MessagebusListener, callback_name: str, **kwargs: Any) -> None:
		try:
			callback = getattr(listener, callback_name)
			if self.threaded_callbacks:
				CallbackThread(callback, **kwargs).start()
			else:
				callback(**kwargs)
		except Exception as err:  # pylint: disable=broad-except
			logger.error("Error running callback %r on listener %r: %s", callback_name, listener, err, exc_info=True)

	def wait_for_jsonrpc_response_message(self, rpc_id: str, timeout: float | None = None) -> JSONRPCResponseMessage:
		class JSONRPCResponseListener(MessagebusListener):
			def __init__(self, rpc_id: str, timeout: float | None = None) -> None:
				super().__init__((MessageType.JSONRPC_RESPONSE,))
				self.rpc_id = rpc_id
				self.timeout = timeout
				self.message_received_event = Event()
				self.message: JSONRPCResponseMessage | None = None

			def wait_for_message(self) -> JSONRPCResponseMessage:
				if self.message_received_event.wait(self.timeout) and self.message:
					return self.message
				raise OpsiServiceTimeoutError(f"Timed out waiting for JSONRPCResponseMessage with rpc_id={self.rpc_id}")

			def message_received(self, message: Message) -> None:
				if isinstance(message, JSONRPCResponseMessage) and message.rpc_id == self.rpc_id:
					self.message = message
					self.message_received_event.set()

		listener = JSONRPCResponseListener(rpc_id, timeout)
		with listener.register(self):
			return listener.wait_for_message()

	def jsonrpc(self, method: str, params: tuple[Any, ...] | list[Any] | None = None, return_result_only: bool = True) -> Any:
		params = params or tuple()
		if isinstance(params, list):
			params = tuple(params)
		msg = JSONRPCRequestMessage(
			sender="*", channel="service:config:jsonrpc", method=method, params=params
		)  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
		self.send_message(msg)
		timeout = float(RPC_TIMEOUTS.get(method, 300))
		res = self.wait_for_jsonrpc_response_message(rpc_id=msg.rpc_id, timeout=timeout)
		if not return_result_only:
			return {"jsonrpc": "2.0", "id": res.rpc_id, "result": res.result, "error": res.error}

		if res.error:
			logger.debug("JSONRPC-response contains error: %s", res.error)
			error_cls: Type[Exception] = OpsiRpcError
			if res.error["data"]["class"] in ("BackendPermissionDeniedError", "OpsiServicePermissionError"):
				error_cls = OpsiServicePermissionError
			raise error_cls(res.error["message"])

		return res.result

	async def async_send_message(self, message: Message) -> None:
		await asyncio.get_event_loop().run_in_executor(None, self.send_message, message)

	def send_message(self, message: Message) -> None:
		if not self._app:
			raise RuntimeError("Messagebus not connected")
		with self._send_lock:
			self._app.send(message.to_msgpack(), ABNF.OPCODE_BINARY)

	def connect(self, wait: bool = True) -> None:
		logger.debug("Messagebus.connect")
		if self._should_be_connected:
			return
		self._connected_result.clear()
		self._should_be_connected = True
		if not self.is_alive():
			logger.debug("Starting thread")
			self.start()
		if wait:
			logger.debug("Waiting for connected result (timeout=%r)", self._connect_timeout)
			if not self._connected_result.wait(self._connect_timeout):
				self._connect_exception = OpsiServiceTimeoutError(
					f"Timed out after {self._connect_timeout} seconds while waiting for connect result"
				)
			if self._connect_exception:
				logger.debug("Raising connect exception %r", self._connect_exception)
				raise self._connect_exception

	def disconnect(self, wait: bool = True) -> None:
		self._should_be_connected = False
		if not self._connected:
			return
		self._disconnected_result.clear()
		self._disconnect()
		if wait:
			if not self._disconnected_result.wait(5):
				logger.warning("Timed out after 5 seconds while waiting for disconnect result")

	def _connect(self) -> None:
		logger.notice("Connecting to opsi messagebus")
		if self._connected:
			self._disconnect()
		self._connected_result.clear()
		self._connect_exception = None

		sslopt: dict[str, str | ssl.VerifyMode] = {}  # pylint: disable=no-member
		if ServiceVerificationFlags.ACCEPT_ALL in self._client.verify:
			sslopt["cert_reqs"] = ssl.CERT_NONE
		if self._client.ca_cert_file:
			sslopt["ca_certs"] = str(self._client.ca_cert_file)

		http_proxy_host = None
		http_proxy_port = None
		http_proxy_auth = None
		http_no_proxy = None
		proxy_url = None
		if self._client.proxy_url is None:
			# no proxy
			http_no_proxy = "*"
		elif self._client.proxy_url == "system":
			# Use system proxy
			proxy_url = os.environ.get("https_proxy") or None
			http_no_proxy = os.environ.get("no_proxy") or None
		else:
			# Use explicit proxy url
			proxy_url = self._client.proxy_url

		if proxy_url:
			purl = urlparse(proxy_url)
			http_proxy_host = purl.hostname
			http_proxy_port = purl.port or None
			if purl.username or purl.password:
				http_proxy_auth = (purl.username, purl.password)

		url = self._client.base_url.replace("https://", "wss://") + self._messagebus_path
		header = [f"{k}: {v + ('/messagebus' if k.lower() == 'user-agent' else '')}" for k, v in self._client.default_headers.items()]
		if self._client.username is not None or self._client.password is not None:
			basic_auth = b64encode(f"{self._client.username or ''}:{self._client.password or ''}".encode("utf-8")).decode("ascii")
			header.append(f"Authorization: Basic {basic_auth}")

		cookie = self._client.session_cookie
		if cookie and "=" in cookie:
			name, value = cookie.split("=", 1)
			cookie = f"{name}={quote(value)}"

		self._app = WebSocketApp(
			url,
			header=header,
			cookie=cookie,
			on_open=self._on_open,
			on_error=self._on_error,
			on_close=self._on_close,
			on_message=self._on_message,
			on_ping=self._on_ping,
			on_pong=self._on_pong,
		)

		for listener in self._listener:
			self._run_listener_callback(listener, "messagebus_connection_open", messagebus=self)

		self._app.run_forever(  # type: ignore[attr-defined]
			sslopt=sslopt,
			skip_utf8_validation=True,
			http_proxy_host=http_proxy_host,
			http_proxy_port=http_proxy_port,
			http_proxy_auth=http_proxy_auth,
			http_no_proxy=http_no_proxy,
			http_proxy_timeout=self._connect_timeout,
			ping_interval=self.ping_interval,
			ping_timeout=self.ping_timeout,
			reconnect=0,
		)

	def _disconnect(self) -> None:
		logger.notice("Disconnecting from opsi messagebus")
		self._disconnected_result.clear()
		if self._app and self._app.sock:
			try:
				self._app.close()  # type: ignore[attr-defined]
			except Exception as err:  # pylint: disable=broad-except
				logger.error(err, exc_info=True)
		self._connected = False
		self._disconnected_result.set()

	def run(self) -> None:
		for var in self._context:
			var.set(self._context[var])
		logger.debug("Messagebus thread started")
		try:  # pylint: disable=too-many-nested-blocks
			while not self._should_stop.wait(1):
				if self._should_be_connected and not self._connected:
					if self._next_connect_wait:
						logger.info("Waiting %d seconds before reconnect", self._next_connect_wait)
						for _ in range(round(self._next_connect_wait)):
							if self._should_stop.wait(1):
								return
					logger.debug("Calling _connect()")
					# Call of _connect() will block
					self._connect()
				if self._next_connect_wait == 0.0:
					self._next_connect_wait = self.reconnect_wait
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)

	def stop(self) -> None:
		self.disconnect()
		self._should_stop.set()
