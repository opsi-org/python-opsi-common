# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import os
import re
import ssl
import time
import warnings
from abc import ABC, abstractmethod
from base64 import b64encode
from contextlib import contextmanager
from enum import Enum
from ipaddress import IPv6Address, ip_address
from pathlib import Path
from threading import Event, Lock, Thread
from traceback import TracebackException
from types import TracebackType
from typing import Any, Callable, Dict, Generator, List, Optional, Tuple, Union
from urllib.parse import quote, unquote, urlparse

from OpenSSL.crypto import (  # type: ignore[import]
	FILETYPE_PEM,
	dump_certificate,
	load_certificate,
)
from packaging import version
from requests import Session
from requests.exceptions import SSLError, Timeout
from requests.structures import CaseInsensitiveDict
from urllib3.exceptions import InsecureRequestWarning
from websocket import WebSocketApp  # type: ignore[import]
from websocket._abnf import ABNF  # type: ignore[import]
from websocket._app import Dispatcher, SSLDispatcher  # type: ignore[import]

from .. import __version__
from ..exceptions import (
	OpsiConnectionError,
	OpsiServiceError,
	OpsiServiceVerificationError,
	OpsiTimeoutError,
)
from ..logging import get_logger, secret_filter
from ..messagebus import (
	JSONRPCRequestMessage,
	JSONRPCResponseMessage,
	Message,
	MessageTypes,
)
from ..utils import prepare_proxy_environment

warnings.simplefilter("ignore", InsecureRequestWarning)

# Workaround websocket bug
setattr(SSLDispatcher, 'timeout', Dispatcher.timeout)

MESSAGBUS_MIN_VERSION = "4.2.1.0"
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
		user_agent: str = None,
		connect_timeout: float = 10.0,
	) -> None:
		"""
		proxy_url:
			system = Use system proxy
			None = Do not use a proxy
		"""
		self._messagebus = Messagebus(self)

		self.base_url = "https://localhost:4447"
		self.server_name = ""
		self.server_version = (0, 0, 0, 0)
		self._messagebus_available = False
		self._connected = False
		self._connect_lock = Lock()
		self._messagebus_connect_lock = Lock()

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
		if verify and isinstance(verify, ServiceVerificationModes):
			self._verify: ServiceVerificationModes = verify

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

		if self._verify == ServiceVerificationModes.ACCEPT_ALL:
			self._session.verify = False
		else:
			self._session.verify = str(self._ca_cert_file) if self._ca_cert_file else True

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
	def verify(self) -> ServiceVerificationModes:
		return self._verify

	@property
	def ca_cert_file(self) -> Optional[Path]:
		return self._ca_cert_file

	@property
	def connected(self) -> bool:
		return self._connected

	@property
	def username(self) -> Optional[str]:
		return self._username

	@property
	def password(self) -> Optional[str]:
		return self._password

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
		if self._connect_lock.locked():
			return
		self.disconnect()
		with self._connect_lock:
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
				match = re.search(r"^opsi\D+([\d\.]+)", self.server_name)
				if match:
					ver = [0, 0, 0, 0]
					for idx, part in enumerate(match.group(1).split(".")):
						if idx > 3:
							break
						try:  # pylint: disable=loop-try-except-usage
							ver[idx] = int(part)
						except ValueError:
							pass
					self.server_version = tuple(ver)  # type: ignore[assignment]
					self._messagebus_available = version.parse(".".join([str(v) for v in ver])) >= version.parse(MESSAGBUS_MIN_VERSION)

			if self._verify in (ServiceVerificationModes.FETCH_CA, ServiceVerificationModes.FETCH_CA_TRUST_UIB):
				self.fetch_opsi_ca(skip_verify=not verify)

	def disconnect(self) -> None:
		self.disconnect_messagebus()
		if self._connected:
			try:
				# TODO: server version specific session deletion (backend_exit or /session/logout)
				self._session.close()
			except Exception:  # pylint: disable=broad-except
				pass
		self._connected = False
		self.server_version = (0, 0, 0, 0)
		self.server_name = ""
		self._messagebus_available = False

	def _assert_connected(self) -> None:
		with self._connect_lock:
			if self._connected:
				return
		self.connect()

	def _get_url(self, path: str) -> str:
		if not path.startswith("/"):
			path = f"/{path}"
		return f"{self.base_url}{path}"

	def get(
		self, path: str, headers: Optional[Dict[str, str]] = None, read_timeout: float = 60.0
	) -> Tuple[int, str, CaseInsensitiveDict, bytes]:
		self._assert_connected()
		try:

			response = self._session.get(self._get_url(path), headers=headers, timeout=(self._connect_timeout, read_timeout), stream=True)
		except Timeout as err:
			raise OpsiTimeoutError(str(err)) from err
		except Exception as err:  # pylint: disable=broad-except
			raise OpsiConnectionError(str(err)) from err
		return (response.status_code, response.reason, response.headers, response.content)

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

	@property
	def messagebus_connected(self) -> bool:
		return self._messagebus.connected

	def __enter__(self) -> "ServiceClient":
		return self

	def __exit__(self, exc_type: Exception, exc_value: TracebackException, traceback: TracebackType) -> None:
		self.disconnect()


class MessagebusListener(ABC):  # pylint: disable=too-few-public-methods
	def __init__(self, message_types: List[MessageTypes] = None) -> None:
		self.message_types = message_types

	@abstractmethod
	def message_received(self, message: Message) -> None:
		pass

	@contextmanager
	def register(self, messagebus: "Messagebus") -> Generator[None, None, None]:
		try:
			messagebus.register_message_listener(self)
			yield
		finally:
			messagebus.unregister_message_listener(self)


class CallbackThread(Thread):
	def __init__(self, callback: Callable, **kwargs: Any):
		super().__init__()
		self.daemon = True
		self.callback = callback
		self.kwargs = kwargs

	def run(self) -> None:
		try:
			self.callback(**self.kwargs)
		except Exception as err:  # pylint: disable=broad-except
			logger.error("Error in %s: %s", self, err, exc_info=True)


class Messagebus(Thread):  # pylint: disable=too-many-instance-attributes
	_messagebus_path = "/messagebus/v1"
	_ping_interval = 60  # Send ping every specified period in seconds.
	_reconnect = 5  # After connection lost, reconnect after specified seconds.

	def __init__(self, opsi_service_client: ServiceClient) -> None:
		super().__init__()
		self.daemon = True
		self._client = opsi_service_client
		self._app: Optional[WebSocketApp] = None
		self._should_be_connected = False
		self._connected = False
		self._connected_result = Event()
		self._connect_exception: Optional[Exception] = None
		self._send_lock = Lock()
		self._listener: List[MessagebusListener] = []
		self._listener_lock = Lock()

		# from websocket import enableTrace
		# enableTrace(True)

	@property
	def connected(self) -> bool:
		return self._connected

	def _on_open(self, app: WebSocketApp) -> None:  # pylint: disable=unused-argument
		logger.debug("Websocket opened")
		self._connected = True
		self._connect_exception = None
		self._connected_result.set()

	def _on_error(self, app: WebSocketApp, error: Exception) -> None:  # pylint: disable=unused-argument
		logger.debug("Websocket error")
		self._connected = False
		self._connect_exception = error
		self._connected_result.set()

	def _on_close(self, app: WebSocketApp, close_status_code: int, close_message: str) -> None:  # pylint: disable=unused-argument
		logger.debug("Websocket closed")
		self._connected = False
		self._connect_exception = None
		self._connected_result.set()

	def _on_message(self, app: WebSocketApp, message: bytes) -> None:  # pylint: disable=unused-argument
		logger.debug("Websocket message")
		try:
			msg = Message.from_msgpack(message)
			for listener in self._listener:
				if listener.message_types and msg.type not in listener.message_types:
					continue
				CallbackThread(listener.message_received, message=msg).start()
		except Exception as err:  # pylint: disable=broad-except
			logger.error("Failed to process websocket message: %s", err, exc_info=True)

	def _on_ping(self, app: WebSocketApp, message: bytes) -> None:  # pylint: disable=unused-argument
		logger.debug("Ping message")
		if self._app:
			self._app.send(b"", ABNF.OPCODE_PONG)

	def _on_pong(self, app: WebSocketApp, message: bytes) -> None:  # pylint: disable=unused-argument
		logger.debug("Pong message")

	def register_message_listener(self, listener: MessagebusListener) -> None:
		with self._listener_lock:
			if listener not in self._listener:
				self._listener.append(listener)

	def unregister_message_listener(self, listener: MessagebusListener) -> None:
		with self._listener_lock:
			if listener in self._listener:
				self._listener.remove(listener)

	def wait_for_jsonrpc_response_message(self, rpc_id: str, timeout: float = None) -> JSONRPCResponseMessage:
		class JSONRPCResponseListener(MessagebusListener):
			def __init__(self, rpc_id: str, timeout: float = None) -> None:
				super().__init__([MessageTypes.JSONRPC_RESPONSE])
				self.rpc_id = rpc_id
				self.timeout = timeout
				self.message_received_event = Event()
				self.message: Optional[JSONRPCResponseMessage] = None
				self.messages_received = 0

			def wait_for_message(self) -> JSONRPCResponseMessage:
				if self.messages_received > 0:
					self.message_received_event.clear()
				if self.message_received_event.wait(self.timeout) and self.message:
					return self.message
				raise OpsiTimeoutError(f"Timed out waiting for JSONRPCResponseMessage with {self.rpc_id=}")

			def message_received(self, message: Message) -> None:
				if isinstance(message, JSONRPCResponseMessage) and message.rpc_id == self.rpc_id:
					self.message = message
					self.messages_received += 1
					self.message_received_event.set()

		listener = JSONRPCResponseListener(rpc_id, timeout)
		with listener.register(self):
			return listener.wait_for_message()

	def jsonrpc(self, method: str, params: Union[Tuple[Any, ...], List[Any]] = None, wait: int = None) -> Any:
		if isinstance(params, list):
			params = tuple(params)
		msg = JSONRPCRequestMessage(sender="*", channel="service:config:jsonrpc", method=method, params=params)  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
		self.send_message(msg)
		if wait is None:
			return msg
		res = self.wait_for_jsonrpc_response_message(rpc_id=msg.rpc_id, timeout=wait)
		return {"id": res.rpc_id, "result": res.result, "error": res.error}

	def send_message(self, message: Message) -> None:
		if not self._app:
			raise RuntimeError("Messagebus not connected")
		with self._send_lock:
			self._app.send(message.to_msgpack(), ABNF.OPCODE_BINARY)

	def connect(self, wait: bool = True) -> None:
		self._connected_result.clear()
		if not self.is_alive():
			self.start()
		self._should_be_connected = True
		if wait:
			self._connected_result.wait()
			if self._connect_exception:
				raise self._connect_exception

	def disconnect(self, wait: bool = True) -> None:
		if not self._connected:
			return
		self._should_be_connected = False
		self._disconnect()
		if wait:
			self._connected_result.wait()

	def _connect(self) -> None:
		self._connected_result.clear()
		self._disconnect()
		self._connect_exception = None

		sslopt: Dict[str, Union[str, ssl.VerifyMode]] = {}  # pylint: disable=no-member
		if self._client.verify == ServiceVerificationModes.ACCEPT_ALL:
			sslopt["cert_reqs"] = ssl.CERT_NONE
		if self._client.ca_cert_file:
			sslopt["ca_certs"] = str(self._client.ca_cert_file)

		sslopt = {"cert_reqs": ssl.CERT_NONE}
		http_proxy_host = None
		http_proxy_port = None
		http_proxy_auth = None
		if os.environ.get("https_proxy"):
			proxy_url = urlparse(os.environ["https_proxy"])
			http_proxy_host = proxy_url.hostname
			http_proxy_port = proxy_url.port or None
			if proxy_url.username or proxy_url.password:
				http_proxy_auth = (proxy_url.username, proxy_url.password)

		url = self._client.base_url.replace("https://", "wss://") + self._messagebus_path
		header = [f"{k}: {v}" for k, v in self._client.default_headers.items()]
		if self._client.username is not None or self._client.password is not None:
			basic_auth = b64encode(f"{self._client.username or ''}:{self._client.password or ''}".encode("utf-8")).decode("ascii")
			header.append(f"Authorization: Basic {basic_auth}")

		self._app = WebSocketApp(
			url,
			header=header,
			on_open=self._on_open,
			on_error=self._on_error,
			on_close=self._on_close,
			on_message=self._on_message,
			on_ping=self._on_ping,
			on_pong=self._on_pong
		)

		self._app.run_forever(  # type: ignore[attr-defined]
			sslopt=sslopt,
			http_proxy_host=http_proxy_host,
			http_proxy_port=http_proxy_port,
			http_proxy_auth=http_proxy_auth,
			http_no_proxy=os.environ.get("no_proxy"),
			ping_interval=self._ping_interval,
			reconnect=self._reconnect,
		)

	def _disconnect(self) -> None:
		if self._app and self._app.sock:
			self._connected_result.clear()
			try:
				self._app.close()  # type: ignore[attr-defined]
			except Exception as err:  # pylint: disable=broad-except
				logger.error(err, exc_info=True)
			self._connected = False
			self._connected_result.set()

	def run(self) -> None:
		_sleep = time.sleep
		try:
			while True:
				if self._should_be_connected and not self._connected:
					self._connect()
				_sleep(1)
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)
