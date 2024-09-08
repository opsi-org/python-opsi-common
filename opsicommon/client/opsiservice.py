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
import locale
import os
import random
import re
import ssl
import sys
import time
import warnings
from abc import ABC
from base64 import b64encode
from contextlib import contextmanager
from contextvars import copy_context
from dataclasses import astuple, dataclass
from datetime import datetime, timezone
from enum import Enum
from functools import lru_cache
from ipaddress import IPv6Address, ip_address
from pathlib import Path
from random import randint
from threading import Event, Lock, Thread
from traceback import TracebackException
from types import MethodType, TracebackType
from typing import Any, Callable, Generator, Iterable, Literal, Type, cast, overload
from urllib.parse import quote, unquote, urlparse
from uuid import uuid4

import lz4.frame  # type: ignore[import,no-redef]
import msgspec
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from packaging import version
from requests import HTTPError, Session
from requests import Response as RequestsResponse
from requests.adapters import HTTPAdapter
from requests.exceptions import SSLError, Timeout
from requests.structures import CaseInsensitiveDict
from urllib3.exceptions import InsecureRequestWarning
from websocket import WebSocket, WebSocketApp  # type: ignore[import]
from websocket import setdefaulttimeout as websocket_setdefaulttimeout
from websocket._abnf import ABNF  # type: ignore[import]

from opsicommon.system.network import get_ip_addresses, get_hostnames
from opsicommon import __version__
from opsicommon.config import OPSI_CA_CERT_FILE, OpsiConfig
from opsicommon.exceptions import (
	OpsiRpcError,
	OpsiServiceAuthenticationError,
	OpsiServiceClientCertificateError,
	OpsiServiceConnectionError,
	OpsiServiceError,
	OpsiServicePermissionError,
	OpsiServiceTimeoutError,
	OpsiServiceUnavailableError,
	OpsiServiceVerificationError,
)
from opsicommon.logging import get_logger, secret_filter
from opsicommon.logging.constants import TRACE
from opsicommon.messagebus.message import (
	ChannelSubscriptionEventMessage,
	ChannelSubscriptionRequestMessage,
	JSONRPCRequestMessage,
	JSONRPCResponseMessage,
	Message,
	MessageType,
	timestamp,
)
from opsicommon.objects import deserialize, serialize
from opsicommon.server import get_opsiconfd_config
from opsicommon.ssl.common import load_key, x509_name_to_dict
from opsicommon.system import lock_file, set_system_datetime
from opsicommon.system.info import is_windows
from opsicommon.types import forceHostId, forceOpsiHostKey
from opsicommon.utils import prepare_proxy_environment

warnings.simplefilter("ignore", InsecureRequestWarning)


MIN_VERSION_MESSAGEBUS = version.parse("4.2.0.287")
MIN_VERSION_MSGPACK = version.parse("4.2.0.171")
MIN_VERSION_LZ4 = version.parse("4.2.0.171")
MIN_VERSION_GZIP = version.parse("4.2.0.0")
MIN_VERSION_SESSION_API = version.parse("4.2.0.285")
MIN_VERSION_CA_CERTS = version.parse("4.3.18.15")

RPC_TIMEOUTS = {
	"depot_installPackage": 4 * 3600,
	"depot_librsyncPatchFile": 24 * 3600,
	"depot_getMD5Sum": 3600,
	"depot_createMd5SumFile": 3600,
	"depot_createZsyncFile": 3600,
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
opsi_config = OpsiConfig(upgrade_config=False)


class ServiceVerificationFlags(str, Enum):
	STRICT_CHECK = "strict_check"
	UIB_OPSI_CA = "uib_opsi_ca"
	ACCEPT_ALL = "accept_all"
	OPSI_CA = "opsi_ca"
	REPLACE_EXPIRED_CA = "replace_expired_ca"


class OpsiCaState(str, Enum):
	UNAVAILABLE = "unavailable"
	AVAILABLE = "available"
	EXPIRED = "expired"


class CallbackThread(Thread):
	def __init__(self, callback: Callable, **kwargs: Any) -> None:
		super().__init__(daemon=True, name="opsiservice-CallbackThread")
		self.callback = callback
		self.kwargs = kwargs
		self._context = copy_context()

	def run(self) -> None:
		for var in self._context:
			var.set(self._context[var])
		try:
			self.callback(**self.kwargs)
		except Exception as err:
			logger.error("Error in %s: %s", self, err, exc_info=True)


class ServiceConnectionListener(ABC):
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


class KeyPasswordHTTPAdapter(HTTPAdapter):
	def __init__(self, key_password: str | None) -> None:
		self.key_password = key_password
		super().__init__()

	def init_poolmanager(self, *args: Any, **kwargs: Any) -> None:
		if self.key_password:
			kwargs["key_password"] = self.key_password
		super().init_poolmanager(*args, **kwargs)  # type: ignore[no-untyped-call]


class ServiceClient:
	no_proxy_addresses = ["localhost", "127.0.0.1", "ip6-localhost", "ip6-loopback", "::1"]

	def __init__(
		self,
		address: Iterable[str] | str | None = None,
		*,
		username: str | None = None,
		password: str | None = None,
		client_cert_file: str | Path | None = None,
		client_key_file: str | Path | None = None,
		client_key_password: str | None = None,
		ca_cert_file: str | Path | None = None,
		verify: str | Iterable[str] = ServiceVerificationFlags.STRICT_CHECK,
		session_cookie: str | None = None,
		session_lifetime: int = 150,
		proxy_url: str | None = "system",
		user_agent: str | None = None,
		connect_timeout: float = 10.0,
		max_time_diff: float = 0.0,
		jsonrpc_create_objects: bool = False,
		jsonrpc_create_methods: bool = False,
	) -> None:
		"""
		proxy_url:
		    system = Use system proxy
		    None = Do not use a proxy

		verify:
		    strict_check:
		        Check server certificate against ca_cert_file.
		    uib_opsi_ca:
		        In combination with verify. Also accept server certificates signed by uib.
		    accept_all:
		        Do not check server certificate.
		    opsi_ca:
		        If ca_cert_file missing or empty: Do not verify certificate.
		        If ca_cert_file is present: Verify if accept_all is not set.
		        After every successful connection: Fetch CA certs from service and update ca_cert_file.
		    replace_expired_ca:
		        To use in combination with fetch_ca_certs.
		        If a CA from ca_cert_file is expired => accept_all.
		"""

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
		self._ca_cert_lock = Lock()
		self._listener: list[ServiceConnectionListener] = []
		self._service_unavailable: OpsiServiceUnavailableError | None = None
		self._username = ""
		self._password = ""

		self._uib_opsi_ca_cert = x509.load_pem_x509_certificate(UIB_OPSI_CA.encode("ascii"))

		self._msgpack_decoder = msgspec.msgpack.Decoder()
		self._msgpack_encoder = msgspec.msgpack.Encoder()
		self._json_decoder = msgspec.json.Decoder()
		self._json_encoder = msgspec.json.Encoder()

		self._session = Session()

		self.username = username
		self.password = password

		self._client_cert_file = None
		self._client_key_file = None
		self._client_key_password = None
		if client_key_password:
			secret_filter.add_secrets(client_key_password)
		if client_cert_file:
			self._client_cert_file = Path(client_cert_file)
			self._session.cert = str(self._client_cert_file)

			if client_key_file:
				self._client_key_file = Path(client_key_file)
				self._session.cert = (str(self._client_cert_file), str(self._client_key_file))

			logger.info(
				"Using client certificate file '%s' and key file '%s'",
				self._client_cert_file,
				self._client_key_file or self._client_cert_file,
			)
			self._client_key_password = client_key_password or None

			logger.debug("Trying to load private key")
			# Test key loading (passphrase)
			load_key(self._client_key_file or self._client_cert_file, self._client_key_password)
			if self._client_key_password:
				self._session.mount("https://", KeyPasswordHTTPAdapter(self._client_key_password))

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

		if not self._verify:
			self._verify = [ServiceVerificationFlags.STRICT_CHECK]

		if session_cookie and "=" not in session_cookie:
			raise ValueError("Invalid session cookie, <name>=<value> is needed")
		self._session_cookie = session_cookie or None

		self._session_lifetime = max(1, int(session_lifetime))
		self._proxy_url = str(proxy_url) if proxy_url and proxy_url != "none" else None

		self._user_agent = f"opsi-service-client/{__version__}" if user_agent is None else str(user_agent)
		self._connect_timeout = max(0.0, float(connect_timeout))
		self._read_timeout = 60.0

		self.default_headers = {
			"User-Agent": self._user_agent,
			"X-opsi-version": __version__,
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

		self.set_addresses(address)

		if ServiceVerificationFlags.ACCEPT_ALL in self._verify:
			self._session.verify = False
		elif self._addresses:
			self._session.verify = str(self.ca_cert_file)
		else:
			self._session.verify = True

		self._messagebus = Messagebus(self)

	@property
	def addresses(self) -> Iterable[str] | str | None:
		return self._addresses

	@staticmethod
	def normalize_service_address(address: str) -> tuple[str, str]:
		scheme = "https"
		auth = ""
		host = ""
		port = _DEFAULT_HTTPS_PORT
		path = ""
		if "://" in address:
			scheme, address = address.split("://", 1)
			if "/" in address:
				address, path = address.split("/", 1)
				path = f"/{path.strip('/')}"

		if scheme != "https":
			raise ValueError(f"Protocol {scheme} not supported")

		if "@" in address:
			auth, address = address.split("@", 1)
			auth += "@"

		columns = address.count(":")
		if columns > 1 or ("[" in address and "]" in address):
			# IPv6 address
			if "]:" in address:
				address, str_port = address.split("]:", 1)
				port = int(str_port)
			host = address.replace("[", "").replace("]", "")
		elif columns:
			host, str_port = address.split(":", 1)
			port = int(str_port)
		else:
			host = address

		try:
			ipa = ip_address(host)
			if isinstance(ipa, IPv6Address):
				host = f"[{ipa.exploded}]"
		except ValueError:
			pass

		return f"{scheme}://{auth}{host}:{port}", path

	def set_addresses(self, address: Iterable[str] | str | None) -> None:
		self._addresses = []
		self._address_index = 0
		if not address:
			return

		for addr in [address] if isinstance(address, str) else address:
			addr, path = self.normalize_service_address(addr)
			url = urlparse(addr)

			if url.username is not None:
				if self.username and self.username != url.username:
					raise ValueError("Different usernames supplied")
				self.username = url.username

			if url.password is not None:
				if self.password and self.password != url.password:
					raise ValueError("Different passwords supplied")
				self.password = url.password

			path = path.rstrip("/")
			if path and path != "/rpc":
				self._jsonrpc_path = path

			self._addresses.append(addr)

		service_hostname = urlparse(self.base_url).hostname or ""

		self._session = prepare_proxy_environment(
			service_hostname,
			self._proxy_url,
			no_proxy_addresses=self.no_proxy_addresses,
			session=self._session,
		)

	@property
	def base_url(self) -> str:
		if not self._addresses:
			raise ValueError("Service address undefined")
		return self._addresses[self._address_index]

	def service_is_opsiclientd(self) -> bool:
		addr = urlparse(self._addresses[self._address_index])
		return addr.hostname in ("127.0.0.1", "localhost") and addr.port == 4441

	@property
	def verify(self) -> list[ServiceVerificationFlags]:
		return self._verify

	@staticmethod
	@lru_cache
	def is_local_address(service_address: str) -> bool:
		service_address = ServiceClient.normalize_service_address(service_address)[0]
		url = urlparse(service_address)
		if not url.hostname:
			raise ValueError(f"Invalid service address: {service_address}")
		host = url.hostname.lower().replace("[", "").replace("]", "")
		return (
			host in ("0000:0000:0000:0000:0000:0000:0000:0001", "127.0.0.1", "localhost", "ip6-localhost", "ip6-loopback")
			or host in [a["ip_address"].exploded for a in get_ip_addresses()]
			or host in get_hostnames()
		)

	@staticmethod
	@lru_cache
	def get_ca_cert_file_path(service_address: str) -> Path:
		base_dir = Path.home() / ".config"
		if is_windows():
			appdata = os.getenv("APPDATA")
			if not appdata:
				raise RuntimeError("APPDATA environment variable not set")
			base_dir = Path(appdata)

		service_address = ServiceClient.normalize_service_address(service_address)[0]
		url = urlparse(service_address)
		if not url.hostname:
			raise ValueError(f"Invalid service address: {service_address}")

		host = url.hostname.lower().replace("[", "").replace("]", "")
		if ServiceClient.is_local_address(service_address):
			host = "localhost"

		dirname = f"{host}_{url.port}".replace(":", ".")
		return base_dir / "opsi" / "services" / dirname / "ca-certs.pem"

	@property
	def ca_cert_file(self) -> Path:
		if self._ca_cert_file:
			return self._ca_cert_file
		return self.get_ca_cert_file_path(self.base_url)

	@property
	def client_cert_file(self) -> Path | None:
		return self._client_cert_file

	@property
	def client_key_file(self) -> Path | None:
		return self._client_key_file

	@property
	def client_key_password(self) -> str | None:
		return self._client_key_password

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
		if not self._session.cookies or not self._session.cookies._cookies:  # type: ignore[attr-defined]
			return None
		for tmp1 in self._session.cookies._cookies.values():  # type: ignore[attr-defined]
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

	def certs_from_pem(self, pem_data: str) -> list[x509.Certificate]:
		certs = []
		for match in re.finditer(r"BEGIN CERTIFICATE-+(.*?)-+END CERTIFICATE", pem_data, re.DOTALL):
			try:
				pem = f"-----BEGIN CERTIFICATE-----{match.group(1)}-----END CERTIFICATE-----"
				certs.append(x509.load_pem_x509_certificate(pem.encode("utf-8")))
			except Exception as err:
				logger.error("Failed to load cert %r: %s", match.group(1), err, exc_info=True)
		return certs

	def read_ca_cert_file(self) -> list[x509.Certificate]:
		with self._ca_cert_lock:
			with open(self.ca_cert_file, "r", encoding="utf-8") as file:
				with lock_file(file=file, exclusive=False, timeout=5.0):
					return self.certs_from_pem(file.read())

	def write_ca_cert_file(self, certs: list[x509.Certificate]) -> None:
		with self._ca_cert_lock:
			ca_cert_file = self.ca_cert_file
			if str(ca_cert_file) == OPSI_CA_CERT_FILE:
				# Never touch the opsi CA file
				logger.warning("Not writing to opsiconfd CA file")
				return

			ca_cert_file.parent.mkdir(parents=True, exist_ok=True)
			certs_pem = []
			subjects = []
			for cert in certs:
				subj = x509_name_to_dict(cert.subject)
				if subj in subjects:
					continue
				certs_pem.append(cert.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8").strip() + "\n")
				subjects.append(subj)

			with open(ca_cert_file, "a+", encoding="utf-8") as file:
				with lock_file(file=file, exclusive=True, timeout=5.0):
					file.seek(0)
					file.truncate()
					file.write("".join(certs_pem))

			logger.info("CA cert file '%s' successfully updated (%d certificates total)", ca_cert_file, len(certs))

	def fetch_ca_certs(self, skip_verify: bool = False) -> None:
		verify = False if skip_verify else self._session.verify
		logger.info("Fetching opsi CA from service (verify=%s)", verify)

		pem_name = "ca-certs.pem" if self.server_version >= MIN_VERSION_CA_CERTS else "opsi-ca-cert.pem"
		try:
			response = self._session.get(f"{self.base_url}/ssl/{pem_name}", timeout=(self._connect_timeout, 5), verify=verify)
			response.raise_for_status()
		except Exception as err:
			raise OpsiServiceError(f"Failed to fetch {pem_name}: {err}") from err

		ca_certs = self.certs_from_pem(response.text)
		if not ca_certs:
			raise OpsiServiceError(f"Failed to fetch {pem_name}: No certificates in response")

		if ServiceVerificationFlags.UIB_OPSI_CA in self._verify:
			ca_certs.extend(self.certs_from_pem(UIB_OPSI_CA))

		self.write_ca_cert_file(ca_certs)

	def handle_uib_opsi_ca_in_cert_file(self, action: Literal["add", "remove"]) -> None:
		uib_opsi_ca_cn = self._uib_opsi_ca_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
		found = False
		ca_certs = []
		for cert in self.get_opsi_ca_certs():
			if cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == uib_opsi_ca_cn:
				found = True
			else:
				ca_certs.append(cert)

		if action == "remove":
			if found:
				logger.info("Removing uib opsi CA from cert file '%s' (%d certificates total)", self.ca_cert_file, len(ca_certs))
			else:
				logger.info(
					"uib opsi CA not found in cert file '%s', nothing to remove (%d certificates total)", self.ca_cert_file, len(ca_certs)
				)
				return

		elif action == "add":
			ca_certs.extend(self.certs_from_pem(UIB_OPSI_CA))
			if found:
				logger.info("Updating uib opsi CA in cert file '%s' (%d certificates total)", self.ca_cert_file, len(ca_certs))
			else:
				logger.info("Adding uib opsi CA to cert file '%s' (%d certificates total)", self.ca_cert_file, len(ca_certs))

		self.write_ca_cert_file(ca_certs)

	def get_opsi_ca_certs(self) -> list[x509.Certificate]:
		ca_certs: list[x509.Certificate] = []
		ca_cert_file = self.ca_cert_file
		if not ca_cert_file.exists() or ca_cert_file.stat().st_size == 0:
			return ca_certs
		try:
			ca_certs = self.read_ca_cert_file()
		except Exception as err:
			logger.warning(err, exc_info=True)
		return ca_certs

	def get_opsi_ca_certs_state(self) -> OpsiCaState:
		now = datetime.now(tz=timezone.utc)
		uib_opsi_ca_cn = self._uib_opsi_ca_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
		for cert in self.get_opsi_ca_certs():
			if cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value != uib_opsi_ca_cn:
				if cert.not_valid_after_utc <= now:
					logger.notice("Expired certificate found: %r", cert)
					return OpsiCaState.EXPIRED
				return OpsiCaState.AVAILABLE
		return OpsiCaState.UNAVAILABLE

	def create_jsonrpc_methods(self, instance: Any = None) -> None:
		if self.jsonrpc_interface is None:
			raise ValueError("Interface description not available")

		instance = instance or self

		def backend_getInterface(self: ServiceClient) -> list[dict[str, Any]]:
			return self.jsonrpc_interface

		def backend_exit(self: ServiceClient) -> None:
			return self.disconnect()

		for method in self.jsonrpc_interface:
			try:
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
						exec(f'def {method_name}(self, {arg_string}): return self.jsonrpc("{method_name}", [{call_string}])')
				setattr(instance, method_name, MethodType(eval(method_name), self))
			except Exception as err:
				logger.error("Failed to create instance method '%s': %s", method, err)

	@contextmanager
	def connection(self, connect_messagebus: bool = False) -> Generator[None, None, None]:
		self.connect()
		if connect_messagebus:
			self.connect_messagebus()
		try:
			yield
		finally:
			self.stop()

	def connect(self) -> None:
		if not self._addresses:
			raise OpsiServiceConnectionError("Service address undefined")

		if self._connect_lock.locked():
			return
		logger.debug("service_is_opsiclientd: %r", self.service_is_opsiclientd())

		self.disconnect()
		with self._connect_lock:
			for listener in self._listener:
				CallbackThread(listener.connection_open, service_client=self).start()

			for address_index in range(len(self._addresses)):
				self._address_index = address_index
				ca_cert_file = self.ca_cert_file
				ca_cert_file_exists = ca_cert_file.exists()

				if ServiceVerificationFlags.ACCEPT_ALL in self._verify:
					self._session.verify = False
				else:
					self._session.verify = str(self.ca_cert_file)

				verify = cast(bool | str, self._session.verify)
				logger.debug(
					"ca_cert_file: '%s', exists: %r, verify_flags: %r, session.verify: %r, verify: %r",
					ca_cert_file,
					ca_cert_file_exists,
					self._verify,
					self._session.verify,
					verify,
				)
				if ServiceVerificationFlags.OPSI_CA in self._verify:
					opsi_ca_state = self.get_opsi_ca_certs_state()
					if opsi_ca_state == OpsiCaState.UNAVAILABLE:
						logger.info(
							"Service verification enabled, but '%s' does not contain CA certs, skipping verification",
							ca_cert_file,
						)
						verify = False
					elif ServiceVerificationFlags.REPLACE_EXPIRED_CA in self._verify and opsi_ca_state == OpsiCaState.EXPIRED:
						logger.info(
							"Service verification enabled, but a certificate from CA cert file '%s' is expired, skipping verification",
							ca_cert_file,
						)
						verify = False

				if verify:
					if ca_cert_file_exists:
						if ServiceVerificationFlags.UIB_OPSI_CA in self._verify:
							self.handle_uib_opsi_ca_in_cert_file("add")
						else:
							self.handle_uib_opsi_ca_in_cert_file("remove")
					else:
						# Prevent OSError invalid path
						verify = True

				verify_addr: str | bool = verify
				# Accept status 405 for older opsiconfd versions
				allow_status_codes = [200, 405]
				if self.service_is_opsiclientd():
					logger.notice("Connecting to local opsiclientd, skipping verification and allowing error 500")
					# Accept status 500 for older opsiclientd versions
					allow_status_codes.append(500)
					verify_addr = False

				try:
					response = self._request(
						method="HEAD",
						path=self._jsonrpc_path,
						connect_timeout=self._connect_timeout,
						read_timeout=self._connect_timeout,
						verify=verify_addr,
						allow_status_codes=allow_status_codes,
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

			logger.debug("max_time_diff: %r", self._max_time_diff)
			if self._max_time_diff > 0 and not self.service_is_opsiclientd():
				try:
					server_dt = None
					uxts_hdr = response.headers.get("x-date-unix-timestamp")
					date_hdr = response.headers.get("date")
					logger.debug("uxts_hdr: %r, date_hdr: %r", uxts_hdr, date_hdr)
					if uxts_hdr:
						server_dt = datetime.fromtimestamp(int(uxts_hdr), tz=timezone.utc)
					elif date_hdr:
						times, timez = date_hdr.rsplit(" ", 1)
						if timez == "UTC":
							# Parsing UTC dates only
							loc = locale.getlocale()
							locale.setlocale(locale.LC_ALL, "en_US.UTF-8")
							try:
								server_dt = datetime.strptime(times, "%a, %d %b %Y %H:%M:%S").replace(tzinfo=timezone.utc)
							finally:
								locale.setlocale(locale.LC_ALL, loc)
					if server_dt:
						local_dt = datetime.now(timezone.utc)
						diff = (server_dt - local_dt).total_seconds()
						logger.debug("server_dt: %r, local_dt: %r, diff: %r", server_dt, local_dt, diff)
						if abs(diff) > self._max_time_diff:
							logger.warning(
								"Local time %r differs from server time (max diff: %0.3f), setting system time to %r",
								local_dt.strftime("%Y-%m-%d %H:%M:%S %Z"),
								self._max_time_diff,
								server_dt.strftime("%Y-%m-%d %H:%M:%S %Z"),
							)
							set_system_datetime(server_dt)
					else:
						logger.debug("Not parsing non UTC date header: %s", response.headers["date"])
				except Exception as err:
					logger.warning("Failed to process date header %r: %r", response.headers["date"], err, exc_info=True)

			if ServiceVerificationFlags.OPSI_CA in self._verify and not self.service_is_opsiclientd():
				try:
					self.fetch_ca_certs(skip_verify=not verify)
				except Exception as err:
					logger.error(err, exc_info=True)

		try:
			self.jsonrpc_interface = self.jsonrpc("backend_getInterface")
		except Exception as err:
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
					self.post("/session/logout", connect_timeout=3.0, read_timeout=3.0)
				else:
					self.jsonrpc("backend_exit", connect_timeout=3.0, read_timeout=3.0)
			except Exception:
				pass
		try:
			self._session.close()
		except Exception:
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

	def _request(
		self,
		method: str,
		path: str,
		headers: dict[str, str] | None = None,
		connect_timeout: float | None = None,
		read_timeout: float | None = None,
		data: bytes | None = None,
		verify: str | bool | None = None,
		allow_status_codes: Iterable[int] | None = None,
	) -> RequestsResponse:
		if self._service_unavailable and self._service_unavailable.until and self._service_unavailable.until >= time.time():
			raise self._service_unavailable

		if connect_timeout is None:
			connect_timeout = self._connect_timeout
		if read_timeout is None:
			read_timeout = self._read_timeout

		self._service_unavailable = None

		allow_status_codes = (200, 201, 202, 203, 204, 206, 207, 208) if allow_status_codes is None else allow_status_codes
		max_attempts = 3
		for attempt in range(1, max_attempts + 1):
			try:
				response = self._session.request(
					method=method,
					url=self._get_url(path),
					headers=headers,
					data=data,
					timeout=(connect_timeout, read_timeout),
					stream=True,
					verify=verify,
				)
				if allow_status_codes and allow_status_codes != ... and response.status_code not in allow_status_codes:
					response.raise_for_status()
				return response
			except SSLError as err:
				str_err = str(err).lower()
				if "permission denied" in str_err and attempt < max_attempts:
					# Possible permission error in context.load_verify_locations accessing ca_cert_file (file locked?)
					wait_time = random.randint(500, 3000) / 1000
					logger.warning("%s, retrying in %0.3f seconds", err, wait_time)
					time.sleep(wait_time)
					continue
				if "certificate required" in str_err or "unknown ca" in str_err:
					raise OpsiServiceClientCertificateError(str(err)) from err
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
				if err.response is None:
					raise OpsiServiceError(str(err)) from err

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
			except Exception as err:
				raise OpsiServiceConnectionError(str(err)) from err
		# Should never be reached
		raise OpsiServiceConnectionError("Failed to connect")

	@overload
	def request(
		self,
		method: str,
		path: str,
		*,
		headers: dict[str, str] | None = None,
		connect_timeout: float | None = None,
		read_timeout: float | None = None,
		data: bytes | None = None,
		allow_status_codes: Iterable[int] | None = None,
		raw_response: Literal[False] = ...,
	) -> Response: ...

	@overload
	def request(
		self,
		method: str,
		path: str,
		*,
		headers: dict[str, str] | None = None,
		connect_timeout: float | None = None,
		read_timeout: float | None = None,
		data: bytes | None = None,
		allow_status_codes: Iterable[int] | None = None,
		raw_response: Literal[True],
	) -> RequestsResponse: ...

	@overload
	def request(
		self,
		method: str,
		path: str,
		*,
		headers: dict[str, str] | None = None,
		connect_timeout: float | None = None,
		read_timeout: float | None = None,
		data: bytes | None = None,
		allow_status_codes: Iterable[int] | None = None,
		raw_response: bool = ...,
	) -> RequestsResponse | Response: ...

	def request(
		self,
		method: str,
		path: str,
		*,
		headers: dict[str, str] | None = None,
		connect_timeout: float | None = None,
		read_timeout: float | None = None,
		data: bytes | None = None,
		allow_status_codes: Iterable[int] | None = None,
		raw_response: bool = False,
	) -> Response | RequestsResponse:
		self._assert_connected()
		response = self._request(
			method=method,
			path=path,
			headers=headers,
			connect_timeout=connect_timeout,
			read_timeout=read_timeout,
			data=data,
			allow_status_codes=allow_status_codes,
		)
		if raw_response:
			return response
		return Response(status_code=response.status_code, reason=response.reason, headers=response.headers, content=response.content)

	@overload
	def get(
		self,
		path: str,
		*,
		headers: dict[str, str] | None = None,
		connect_timeout: float | None = None,
		read_timeout: float | None = None,
		allow_status_codes: Iterable[int] | None = None,
		raw_response: Literal[False] = ...,
	) -> Response: ...

	@overload
	def get(
		self,
		path: str,
		*,
		headers: dict[str, str] | None = None,
		connect_timeout: float | None = None,
		read_timeout: float | None = None,
		allow_status_codes: Iterable[int] | None = None,
		raw_response: Literal[True],
	) -> RequestsResponse: ...

	@overload
	def get(
		self,
		path: str,
		*,
		headers: dict[str, str] | None = None,
		connect_timeout: float | None = None,
		read_timeout: float | None = None,
		allow_status_codes: Iterable[int] | None = None,
		raw_response: bool = ...,
	) -> RequestsResponse | Response: ...

	def get(
		self,
		path: str,
		*,
		headers: dict[str, str] | None = None,
		connect_timeout: float | None = None,
		read_timeout: float | None = None,
		allow_status_codes: Iterable[int] | None = None,
		raw_response: bool = False,
	) -> Response | RequestsResponse:
		return self.request(
			"GET",
			path=path,
			headers=headers,
			connect_timeout=connect_timeout,
			read_timeout=read_timeout,
			allow_status_codes=allow_status_codes,
			raw_response=raw_response,
		)

	@overload
	def post(
		self,
		path: str,
		data: bytes | None = None,
		*,
		headers: dict[str, str] | None = None,
		connect_timeout: float | None = None,
		read_timeout: float | None = None,
		allow_status_codes: Iterable[int] | None = None,
		raw_response: Literal[False] = ...,
	) -> Response: ...

	@overload
	def post(
		self,
		path: str,
		data: bytes | None = None,
		*,
		headers: dict[str, str] | None = None,
		connect_timeout: float | None = None,
		read_timeout: float | None = None,
		allow_status_codes: Iterable[int] | None = None,
		raw_response: Literal[True],
	) -> RequestsResponse: ...

	@overload
	def post(
		self,
		path: str,
		data: bytes | None = None,
		*,
		headers: dict[str, str] | None = None,
		connect_timeout: float | None = None,
		read_timeout: float | None = None,
		allow_status_codes: Iterable[int] | None = None,
		raw_response: bool = ...,
	) -> RequestsResponse | Response: ...

	def post(
		self,
		path: str,
		data: bytes | None = None,
		*,
		headers: dict[str, str] | None = None,
		connect_timeout: float | None = None,
		read_timeout: float | None = None,
		allow_status_codes: Iterable[int] | None = None,
		raw_response: bool = False,
	) -> Response | RequestsResponse:
		return self.request(
			"POST",
			path=path,
			headers=headers,
			connect_timeout=connect_timeout,
			read_timeout=read_timeout,
			data=data,
			allow_status_codes=allow_status_codes,
			raw_response=raw_response,
		)

	def jsonrpc(
		self,
		method: str,
		params: tuple[Any, ...] | list[Any] | dict[str, Any] | None = None,
		*,
		connect_timeout: float | None = None,
		read_timeout: float | None = None,
		return_result_only: bool = True,
		create_objects: bool | None = None,
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
		if logger.isEnabledFor(TRACE):
			logger.trace("RPC: %s", data_dict)

		serial = "msgpack" if self.server_version >= MIN_VERSION_MSGPACK else "json"
		if serial == "msgpack":
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
		response = self.post(  # type: ignore[call-overload]  # ellipsis -> object
			self._jsonrpc_path,
			headers=headers,
			data=data,
			connect_timeout=connect_timeout,
			read_timeout=read_timeout,
			allow_status_codes=allow_status_codes,  # type: ignore[arg-type]
		)
		data = response.content
		content_type = response.headers.get("Content-Type", "")
		content_encoding = response.headers.get("Content-Encoding", "")
		logger.info(
			"Got response status=%s, id=%r, method=%s, Content-Type=%s, Content-Encoding=%s, duration=%0.3fs",
			response.status_code,
			rpc_id,
			method,
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
		except Exception:
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

		if create_objects is None:
			create_objects = self.jsonrpc_create_objects and not method.endswith(("_hash", "_listOfHashes", "_getHashes"))

		if create_objects:
			return deserialize(rpc.get("result"))

		return rpc.get("result")

	@property
	def messagebus(self) -> Messagebus:
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

	def connect_messagebus(self) -> Messagebus:
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


class MessagebusListener(ABC):
	def __init__(self, messagebus: Messagebus | None = None, message_types: Iterable[MessageType | str] | None = None) -> None:
		"""
		message_types:
		"""
		self.messagebus: Messagebus | None = messagebus
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
	def register(self, messagebus: Messagebus) -> Generator[None, None, None]:
		"""
		Context manager for register this listener on and off the message bus.
		"""
		self.messagebus = messagebus
		try:
			self.messagebus.register_messagebus_listener(self)
			yield
		finally:
			self.messagebus.unregister_messagebus_listener(self)


class Messagebus(Thread):
	_messagebus_path = "/messagebus/v1"

	def __init__(self, opsi_service_client: ServiceClient) -> None:
		super().__init__(daemon=True, name="opsiservice-Messagebus")
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
		self._connect_timeout = self._client._connect_timeout
		self.ping_interval = 15.0  # Send ping every specified period in seconds.
		self.ping_timeout = 10.0  # Ping timeout in seconds.
		# After connection lost, reconnect after specified seconds (min/max).
		self.reconnect_wait_min = 5
		self.reconnect_wait_max = 5
		self._connect_attempt = 0
		self._next_connect_wait = 0.0
		self._subscribed_channels: list[str] = []
		self.threaded_callbacks = True
		self.compression: str | None = "lz4"
		# from websocket import enableTrace
		# enableTrace(True)

	@property
	def connected(self) -> bool:
		return self._connected

	@property
	def websocket_connected(self) -> bool:
		return bool(self._app and self._app.sock and self._app.sock.connected)

	def _on_open(self, websocket: WebSocket) -> None:
		logger.debug("Websocket opened")
		if not self._connected:
			logger.notice("Connected to opsi messagebus")
		self._next_connect_wait = 0.0
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
		self._connect_attempt = 0

	def _on_error(self, websocket: WebSocket, error: Exception) -> None:
		status_code = getattr(error, "status_code", 0)
		logger.warning("Websocket error: %d - %s", status_code, error)
		self._connect_exception = error
		self._connected_result.set()
		for listener in self._listener:
			self._run_listener_callback(listener, "messagebus_connection_failed", messagebus=self, exception=error)

	def _on_close(self, websocket: WebSocket, close_status_code: int, close_message: str) -> None:
		logger.info("Websocket closed with status_code=%r and message=%r", close_status_code, close_message)
		self._connected = False
		if close_status_code == 1013:
			# Try again later
			self._next_connect_wait = 60
			try:
				match = re.search(r"retry-after:\s*(\d+)", close_message, flags=re.IGNORECASE)
				if match:
					self._next_connect_wait = max(1, min(int(match.group(1)), 7200))
			except ValueError:
				pass
		else:
			self._next_connect_wait = 0

		# Add random wait time to reduce the load on the server
		self._next_connect_wait += float(randint(self.reconnect_wait_min, self.reconnect_wait_max))

		for listener in self._listener:
			self._run_listener_callback(listener, "messagebus_connection_closed", messagebus=self)

	def _on_message(self, websocket: WebSocket, message: bytes) -> None:
		logger.debug("Websocket message received")
		try:
			if self.compression == "lz4":
				message = lz4.frame.decompress(message)
			msg = Message.from_msgpack(message)

			cur_timestamp = timestamp()
			expired = msg.expires and msg.expires <= cur_timestamp
			if expired:
				callback = "expired_message_received"
				logger.info("Received expired message: %r (expires=%d, timestamp=%d)", msg, msg.expires, cur_timestamp)
			else:
				callback = "message_received"
				logger.debug("Received message: %r", msg)

			if isinstance(msg, ChannelSubscriptionEventMessage):
				self._subscribed_channels = msg.subscribed_channels

			for listener in self._listener:
				if listener.message_types and msg.type not in listener.message_types:
					continue
				self._run_listener_callback(listener, callback, message=msg)
		except Exception as err:
			logger.error("Failed to process websocket message: %s", err, exc_info=True)

	def _on_ping(self, websocket: WebSocket, message: bytes) -> None:
		logger.debug("Ping message received")
		# We do not need to send a pong, the websocket library will do that for us

	def _on_pong(self, websocket: WebSocket, message: bytes) -> None:
		logger.debug("Pong message received")

	def register_messagebus_listener(self, listener: MessagebusListener) -> None:
		with self._listener_lock:
			if listener not in self._listener:
				if not listener.messagebus:
					listener.messagebus = self
				self._listener.append(listener)

	def unregister_messagebus_listener(self, listener: MessagebusListener) -> None:
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
		except Exception as err:
			logger.error("Error running callback %r on listener %r: %s", callback_name, listener, err, exc_info=True)

	def wait_for_jsonrpc_response_message(self, rpc_id: str | int, timeout: float | None = None) -> JSONRPCResponseMessage:
		class JSONRPCResponseListener(MessagebusListener):
			def __init__(self, rpc_id: str | int, timeout: float | None = None) -> None:
				super().__init__(message_types=(MessageType.JSONRPC_RESPONSE,))
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
		msg = JSONRPCRequestMessage(sender="*", channel="service:config:jsonrpc", method=method, params=params)
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
		logger.debug("Sending message: %r", message)
		data = message.to_msgpack()
		if self.compression == "lz4":
			data = lz4.frame.compress(data, compression_level=0, block_linked=True)
		with self._send_lock:
			self._app.send(data, ABNF.OPCODE_BINARY)

	def connect(self, wait: bool = True) -> None:
		logger.debug("Messagebus.connect")
		if self._should_be_connected:
			return
		if not self._client.addresses:
			raise OpsiServiceConnectionError("Service address undefined")

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
				raise self._connect_exception
			if self._connect_exception:
				status_code = getattr(self._connect_exception, "status_code", 0)
				headers = getattr(self._connect_exception, "headers", {})
				cls: Type[OpsiServiceError] = OpsiServiceConnectionError
				if status_code == 401:
					cls = OpsiServiceAuthenticationError
				elif status_code == 403:
					cls = OpsiServicePermissionError
				elif status_code == 503:
					cls = OpsiServiceUnavailableError
					self._next_connect_wait = 60
					try:
						retry_after = int(headers.get("Retry-After", ""))
						self._next_connect_wait = max(1, min(retry_after, 7200))
					except ValueError:
						pass
				logger.debug("Raising %r: %r", cls, self._connect_exception)
				raise cls(str(self._connect_exception)) from self._connect_exception

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
		self._connect_attempt += 1
		self._connected_result.clear()
		self._connect_exception = None

		sslopt: dict[str, str | ssl.VerifyMode] = {}
		sslopt["ca_certs"] = str(self._client.ca_cert_file)
		if ServiceVerificationFlags.ACCEPT_ALL in self._client.verify:
			sslopt["cert_reqs"] = ssl.CERT_NONE
		if self._client.client_cert_file:
			sslopt["certfile"] = str(self._client.client_cert_file)
			if self._client.client_key_file:
				sslopt["keyfile"] = str(self._client.client_key_file)
			if self._client.client_key_password:
				sslopt["password"] = self._client.client_key_password

		proxy_type = None
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
			proxy_type = "http"
			purl = urlparse(proxy_url)
			http_proxy_host = purl.hostname
			http_proxy_port = purl.port or None
			if purl.username or purl.password:
				http_proxy_auth = (purl.username, purl.password)

		url = self._client.base_url.replace("https://", "wss://") + self._messagebus_path
		if self.compression:
			url = f"{url}?compression={self.compression}"
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

		logger.debug(
			"Websocket connection params: sslopt=%r, "
			"proxy_type=%r, http_proxy_host=%r, http_proxy_port=%r, http_proxy_auth=%r, http_no_proxy=%r, "
			"connect_timeout=%r, ping_interval=%r, ping_timeout=%r",
			sslopt,
			proxy_type,
			http_proxy_host,
			http_proxy_port,
			http_proxy_auth,
			http_no_proxy,
			self._connect_timeout,
			self.ping_interval,
			self.ping_timeout,
		)

		websocket_setdefaulttimeout(self._connect_timeout)
		self._app.run_forever(  # type: ignore[attr-defined]
			sslopt=sslopt,
			skip_utf8_validation=True,
			proxy_type=proxy_type,  # type: ignore[arg-type]
			http_proxy_host=http_proxy_host,  # type: ignore[arg-type]
			http_proxy_port=http_proxy_port,  # type: ignore[arg-type]
			http_proxy_auth=http_proxy_auth,  # type: ignore[arg-type]
			http_no_proxy=http_no_proxy,  # type: ignore[arg-type]
			http_proxy_timeout=self._connect_timeout,
			ping_interval=self.ping_interval,
			ping_timeout=self.ping_timeout,
			reconnect=0,
		)

	def _disconnect(self) -> None:
		logger.notice("Disconnecting from opsi messagebus")
		self._disconnected_result.clear()
		self._connect_attempt = 0
		if self._app and self._app.sock:
			try:
				self._app.close()  # type: ignore[attr-defined]
			except Exception as err:
				logger.error(err, exc_info=True)
		self._connected = False
		self._disconnected_result.set()

	def run(self) -> None:
		for var in self._context:
			var.set(self._context[var])
		logger.debug("Messagebus thread started")
		try:
			while not self._should_stop.wait(1):
				if self._should_be_connected and not self._connected:
					if self._next_connect_wait:
						logger.info("Waiting %d seconds before reconnect", self._next_connect_wait)
						for _ in range(round(self._next_connect_wait)):
							if self._should_stop.wait(1):
								return
					logger.debug("Calling _connect()")
					# Call of _connect() will block until the connection is lost
					self._connect()
		except Exception as err:
			logger.error(err, exc_info=True)

	def stop(self) -> None:
		self.disconnect()
		self._should_stop.set()


class BackendManager(ServiceClient):
	"""
	For backwards compatibility
	"""

	def __init__(self, username: str | None = None, password: str | None = None, **kwargs: Any) -> None:
		warnings.warn("BackendManager is deprecated, please use opsicommon.client.opsiservice.get_service_client()")
		super().__init__(
			address=opsi_config.get("service", "url"),
			username=username or opsi_config.get("host", "id"),
			password=password or opsi_config.get("host", "key"),
			user_agent=f"BackendManager/{__version__}/{os.path.basename(sys.argv[0])}",
			# BackendManager can only be used to connect to the local opsi service.
			# Using local CA cert file read-only with strict verification and.
			ca_cert_file=OPSI_CA_CERT_FILE,
			verify=ServiceVerificationFlags.STRICT_CHECK,
			jsonrpc_create_objects=True,
			jsonrpc_create_methods=True,
		)
		self.connect()


def get_service_client(
	*,
	address: str | None = None,
	username: str | None = None,
	password: str | None = None,
	client_cert_file: str | Path | None = None,
	client_key_file: str | Path | None = None,
	client_key_password: str | None = None,
	ca_cert_file: str | Path | None = None,
	verify: str | None = None,
	client_cert_auth: bool | None = None,
	auto_connect: bool = True,
	session_cookie: str | None = None,
	session_lifetime: int = 150,
	proxy_url: str | None = "system",
	user_agent: str | None = None,
	connect_timeout: float = 10,
	max_time_diff: float = 0,
	jsonrpc_create_objects: bool = True,
	jsonrpc_create_methods: bool = True,
) -> ServiceClient:
	if user_agent is None:
		user_agent = f"service-client/{__version__}/{os.path.basename(sys.argv[0])}"

	service_url = opsi_config.get("service", "url")
	service_url_is_local = False
	if service_url:
		service_url = ServiceClient.normalize_service_address(service_url)[0]
		service_url_is_local = ServiceClient.is_local_address(service_url)

	address = ServiceClient.normalize_service_address(address)[0] if address else service_url

	if not verify:
		verify = ServiceVerificationFlags.OPSI_CA

	ca_cert_file = None

	if opsi_config.get("host", "server-role") in ("configserver", "depotserver") and (
		service_url == address or (service_url_is_local and ServiceClient.is_local_address(address))
	):
		if not ca_cert_file and os.path.exists(OPSI_CA_CERT_FILE):
			ca_cert_file = OPSI_CA_CERT_FILE
		if str(ca_cert_file) == str(OPSI_CA_CERT_FILE):
			verify = ServiceVerificationFlags.STRICT_CHECK
		if client_cert_auth is None:
			client_cert_auth = True

	if client_key_file and ca_cert_file and client_cert_auth is None:
		client_cert_auth = True

	if client_cert_auth and (not client_cert_file or not client_key_file):
		cfg = get_opsiconfd_config({"ssl_server_key": "", "ssl_server_cert": "", "ssl_server_key_passphrase": ""})
		logger.debug("opsiconfd config: %r", cfg)
		if (
			cfg["ssl_server_key"]
			and os.path.exists(cfg["ssl_server_key"])
			and cfg["ssl_server_cert"]
			and os.path.exists(cfg["ssl_server_cert"])
		):
			client_cert_file = cfg["ssl_server_cert"]
			client_key_file = cfg["ssl_server_key"]
			client_key_password = cfg["ssl_server_key_passphrase"]

	service_client = ServiceClient(
		address=address,
		username=username or opsi_config.get("host", "id"),
		password=password or opsi_config.get("host", "key"),
		user_agent=user_agent,
		verify=verify,
		ca_cert_file=ca_cert_file,
		client_cert_file=client_cert_file,
		client_key_file=client_key_file,
		client_key_password=client_key_password,
		jsonrpc_create_objects=jsonrpc_create_objects,
		jsonrpc_create_methods=jsonrpc_create_methods,
		session_cookie=session_cookie,
		session_lifetime=session_lifetime,
		proxy_url=proxy_url,
		connect_timeout=connect_timeout,
		max_time_diff=max_time_diff,
	)
	if auto_connect:
		service_client.connect()
		logger.info("Connected to %s", service_client.server_name)
	return service_client
