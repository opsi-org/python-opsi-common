# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import gzip
import ipaddress
import os
import re
import socket
import threading
import time
import types
import warnings
from typing import Any, Callable, Dict, List, Optional, Type, Union
from urllib.parse import quote, unquote, urlparse

import msgpack  # type: ignore[import]
import requests
import urllib3
from requests.adapters import HTTPAdapter
from requests.exceptions import SSLError
from urllib3.util.retry import Retry

try:
	# pyright: reportMissingModuleSource=false
	import orjson as json  # type: ignore[import] # pylint: disable=import-error
except ModuleNotFoundError:
	try:
		import ujson as json  # type: ignore[import,no-redef]
	except ModuleNotFoundError:
		import json  # type: ignore[no-redef]

import lz4.frame  # type: ignore[import,no-redef]

from opsicommon import __version__
from opsicommon.exceptions import (
	BackendAuthenticationError,
	BackendPermissionDeniedError,
	OpsiRpcError,
	OpsiServiceVerificationError,
)
from opsicommon.logging import get_logger, secret_filter
from opsicommon.utils import deserialize, prepare_proxy_environment, serialize

warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)

_GZIP_COMPRESSION = "gzip"
_LZ4_COMPRESSION = "lz4"
_DEFAULT_HTTP_PORT = 4444
_DEFAULT_HTTPS_PORT = 4447

logger = get_logger("opsicommon.general")


def no_export(func: Callable) -> Callable:
	setattr(func, "no_export", True)
	return func


class TimeoutHTTPAdapter(HTTPAdapter):
	def __init__(self, *args, **kwargs) -> None:
		self.timeout = None
		if "timeout" in kwargs:
			self.timeout = kwargs["timeout"]
			del kwargs["timeout"]
		super().__init__(*args, **kwargs)

	def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):  # pylint: disable=too-many-arguments
		if timeout is None:
			timeout = self.timeout
		return super().send(request, stream, timeout, verify, cert, proxies)


class JSONRPCClient:  # pylint: disable=too-many-instance-attributes
	_rpc_timeouts = {
		"depot_installPackage": 3600,
		"depot_librsyncPatchFile": 24 * 3600,
		"depot_getMD5Sum": 3600,
	}
	no_proxy_addresses = ["localhost", "127.0.0.1", "ip6-localhost", "::1"]  # pylint: disable=use-tuple-over-list

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

	def __init__(self, address: str, **kwargs) -> None:  # pylint: disable=too-many-branches,too-many-statements
		"""
		JSONRPC client
		"""

		self._application = f"opsi-jsonrpc-client/{__version__}"
		self._compression: Union[bool, str] = False
		self._connect_on_init = True
		self._create_methods = True
		self._connected = False
		self._interface: Optional[List[Dict[str, Any]]] = None
		self._rpc_id = 0
		self._rpc_id_lock = threading.Lock()
		self._ca_cert_file = None
		self._verify_server_cert = False
		self._proxy_url: Optional[str] = "system"  # Use system proxy by default
		self._username = None
		self._password = None
		self._serialization = "auto"
		self._ip_version: Union[str, int] = "auto"
		self._connect_timeout = 10
		self._read_timeout = 300
		self._http_pool_maxsize = 10
		self._http_max_retries = 1
		self._session_lifetime = 150  # In seconds
		self.create_objects = True
		self.raw_responses = False
		self.server_name: Optional[str] = None
		self.base_url = None
		self.no_proxy_addresses = list(set(self.no_proxy_addresses + [socket.getfqdn()]))

		session_id = None
		for option, value in kwargs.items():
			option = option.lower().replace("_", "")
			if option == "application":
				self._application = str(value)
			elif option == "username":
				self._username = str(value or "")
			elif option == "password":
				self._password = str(value or "")
			elif option == "sessionid":
				if value:
					session_id = str(value)
			elif option == "compression":
				self.set_compression(value)
			elif option == "connectoninit":
				self._connect_on_init = bool(value)
			elif option == "createmethods":
				self._create_methods = bool(value)
			elif option in ("connectionpoolsize", "httppoolmaxsize"):
				if value not in (None, ""):
					self._http_pool_maxsize = int(value)
			elif option in ("retry", "httpmaxretries"):
				if not value:
					self._http_max_retries = 0
				elif isinstance(value, int):
					self._http_max_retries = max(value, 0)
			elif option == "connecttimeout":
				if value not in (None, ""):
					self._connect_timeout = int(value)
			elif option in ("readtimeout", "timeout", "sockettimeout"):
				if value not in (None, ""):
					self._read_timeout = int(value)
			elif option == "verifyservercert":
				self._verify_server_cert = bool(value)
			elif option == "cacertfile":
				if value not in (None, ""):
					self._ca_cert_file = str(value)
			elif option == "proxyurl":
				self._proxy_url = str(value) if value else None
			elif option == "ipversion":
				if value not in (None, ""):
					if str(value) in ("auto", "4", "6"):
						self._ip_version = str(value)
					else:
						logger.error("Invalid ip version '%s', using %s", value, self._ip_version)  # pylint: disable=loop-global-usage
			elif option == "serialization":
				self.serialization = value
			elif option == "sessionlifetime":
				if value:
					self._session_lifetime = int(value)
			elif option == "createobjects":
				self.create_objects = bool(value)
			elif option == "rawresponses":
				self.raw_responses = bool(value)
			else:
				if self.__class__.__name__ != "JSONRPCBackend":
					logger.warning("Invalid argument '%s'", option)  # pylint: disable=loop-global-usage

		self._set_address(address)

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
				"User-Agent": self._application,
				"X-opsi-session-lifetime": str(self._session_lifetime),
			}
		)
		if session_id:
			if "=" in session_id:
				logger.confidential("Using session id passed: %s", session_id)
				cookie_name, cookie_value = session_id.split("=", 1)
				self._session.cookies.set(cookie_name, quote(cookie_value))
			else:
				logger.warning("Invalid session id passed: %s", session_id)

		self._session = prepare_proxy_environment(
			self.hostname,
			self._proxy_url,
			no_proxy_addresses=self.no_proxy_addresses,
			session=self._session,
		)

		if self._verify_server_cert:
			self._session.verify = self._ca_cert_file or True
		else:
			self._session.verify = False

		self._http_adapter = TimeoutHTTPAdapter(
			timeout=(self._connect_timeout, self._read_timeout),
			pool_maxsize=self._http_pool_maxsize,
			max_retries=0,  # No retry on connect
		)
		self._session.mount("http://", self._http_adapter)
		self._session.mount("https://", self._http_adapter)

		try:
			my_address = ipaddress.ip_address(self.hostname)
			if isinstance(my_address, ipaddress.IPv6Address) and self._ip_version != "6":
				logger.info("%s is an ipv6 address, forcing ipv6", self.hostname)
				self._ip_version = 6
			elif isinstance(my_address, ipaddress.IPv4Address) and self._ip_version != "4":
				logger.info("%s is an ipv4 address, forcing ipv4", self.hostname)
				self._ip_version = 4
		except ValueError:
			pass

		setattr(urllib3.util.connection, "allowed_gai_family", self._allowed_gai_family)

		if self._connect_on_init:
			self.connect()

	def __enter__(self):
		return self

	def __exit__(
		self,
		exc_type: Type[BaseException] | None,
		exc_value: BaseException | None,
		traceback: types.TracebackType | None
	) -> None:
		self.disconnect()

	@property
	def serialization(self) -> str:
		return self._serialization

	@serialization.setter
	def serialization(self, serialization: str) -> None:
		if serialization in (None, ""):
			return
		if serialization in ("auto", "json", "msgpack"):
			self._serialization = serialization
		else:
			logger.error(
				"Invalid serialization %r, using %r",
				serialization,
				self._serialization,
			)

	@property
	def hostname(self) -> str:
		return str(urlparse(self.base_url).hostname or "localhost")

	@property
	def session(self) -> requests.Session:
		if not self._connected:
			self.connect()
		return self._session

	@property
	def session_id(self) -> Optional[str]:
		if not self._session.cookies or not self._session.cookies._cookies:  # type: ignore[attr-defined] # pylint: disable=protected-access
			return None
		for tmp1 in self._session.cookies._cookies.values():  # type: ignore[attr-defined] # pylint: disable=protected-access
			for tmp2 in tmp1.values():
				for cookie in tmp2.values():
					return f"{cookie.name}={unquote(cookie.value)}"
		return None

	@property
	def server_version(self) -> Optional[List[int]]:
		if self.server_name:
			match = re.search(r"^opsi\D+(\d+\.\d+\.\d+\.\d+)", self.server_name)
			if match:
				return [int(v) for v in match.group(1).split(".")]
		return None

	serverVersion = server_version

	@property
	def serverName(self) -> Optional[str]:  # pylint: disable=invalid-name
		return self.server_name

	@property
	def interface(self) -> Optional[List[Dict[str, Any]]]:
		if not self._interface and self._create_methods:
			self.connect()
		return self._interface

	def backend_getInterface(self) -> Optional[List[Dict[str, Any]]]:  # pylint: disable=invalid-name
		return self.interface

	@no_export
	def getInterface(self) -> Optional[List[Dict[str, Any]]]:  # pylint: disable=invalid-name
		return self.interface

	@no_export
	def set_compression(self, compression: Union[bool, str]) -> None:
		if isinstance(compression, bool):
			self._compression = compression
		else:
			compression = str(compression).strip().lower()
			if compression in ("true", "false"):
				self._compression = compression == "true"
			elif compression == _GZIP_COMPRESSION:
				self._compression = _GZIP_COMPRESSION
			elif compression == _LZ4_COMPRESSION:
				self._compression = _LZ4_COMPRESSION
			else:
				self._compression = False

	setCompression = set_compression

	@no_export
	def get(self, path: str, headers: Optional[Dict[str, str]] = None):
		if not self.base_url:
			raise ValueError("No url provided for jsonrpcclient.")
		url = self.base_url
		if path.startswith("/"):
			url = f"{'/'.join(url.split('/')[:3])}{path}"
		else:
			url = f"{url.rstrip('/')}/{path}"

		response = self.session.get(url, headers=headers)
		response.raise_for_status()
		return response

	def _set_address(self, address: str) -> None:
		if "://" not in address:
			address = f"https://{address}"
		url = urlparse(address)
		if url.scheme not in ("http", "https"):
			raise ValueError(f"Protocol {url.scheme} not supported")

		if url.scheme == "https":
			ca_bundle = os.environ.get("REQUESTS_CA_BUNDLE", None)
			if ca_bundle:
				logger.warning("Environment variable REQUESTS_CA_BUNDLE is set to '%s'", ca_bundle)

		port = url.port
		if not port:
			port = _DEFAULT_HTTP_PORT if url.scheme == "http" else _DEFAULT_HTTPS_PORT

		path = url.path
		if not path or path == "/":
			path = "/rpc"

		hostname = str(url.hostname)
		if ":" in hostname:
			hostname = f"[{hostname}]"
		self.base_url = f"{url.scheme}://{hostname}:{port}{path}"
		if url.username and not self._username:
			self._username = url.username
		if url.password and not self._password:
			self._password = url.password

	@no_export
	def execute_rpc(self, method: str, params: Optional[Union[List, Dict[str, Any]]] = None) -> Any:  # pylint: disable=too-many-branches,too-many-statements,too-many-locals
		params = params or []

		rpc_id = 0
		with self._rpc_id_lock:
			self._rpc_id += 1
			rpc_id = self._rpc_id

		headers = {"Accept-Encoding": "deflate, gzip, lz4"}

		data_dict = {
			"jsonrpc": "2.0",
			"id": rpc_id,
			"method": method,
			"params": serialize(params),
		}

		serialization = self._serialization
		if serialization == "auto":
			serialization = "json"
			serv = self.server_version
			if serv and (serv[0] > 4 or (serv[0] == 4 and serv[1] > 1)):
				serialization = "msgpack"

		if serialization == "msgpack":
			headers["Accept"] = headers["Content-Type"] = "application/msgpack"
			data = msgpack.dumps(data_dict)
		else:
			headers["Accept"] = headers["Content-Type"] = "application/json"
			data = json.dumps(data_dict)

		if not isinstance(data, bytes):
			data = data.encode("utf-8")

		if self._compression:
			compression = self._compression
			if compression is True:
				# Auto choose by server version
				# Do not compress if opsi server version < 4.2
				# opsiconfd 4.2.0.96 (uvicorn)
				compression = "uncompressed"
				serv = self.server_version
				if serv and (serv[0] > 4 or (serv[0] == 4 and serv[1] > 1)):
					compression = _LZ4_COMPRESSION

			if compression == _LZ4_COMPRESSION:
				logger.trace("Compressing data with lz4")
				headers["Content-Encoding"] = "lz4"
				headers["Accept-Encoding"] = "lz4"
				data = lz4.frame.compress(data, compression_level=0, block_linked=True)
			elif compression == _GZIP_COMPRESSION:
				logger.trace("Compressing data with gzip")
				headers["Content-Encoding"] = "gzip"
				headers["Accept-Encoding"] = "gzip"
				data = gzip.compress(data)

		timeout = (self._connect_timeout, self._rpc_timeouts.get(method, self._read_timeout))

		logger.info(
			"JSONRPC request to %s: ip_version=%s, id=%r, method=%s, Content-Type=%s, Content-Encoding=%s, timeout=%r",
			self.base_url,
			self._ip_version,
			rpc_id,
			method,
			headers.get("Content-Type", ""),
			headers.get("Content-Encoding", ""),
			timeout,
		)
		start_time = time.time()
		if not self.base_url:
			raise ValueError("No url provided for jsonrpcclient.")
		try:
			response = self.session.post(self.base_url, headers=headers, data=data, stream=True, timeout=timeout)
		except SSLError as err:
			try:
				if err.args[0].reason.args[0].errno == 8:
					raise err
			except (AttributeError, IndexError):
				pass
			raise OpsiServiceVerificationError(str(err)) from err

		content_type = response.headers.get("Content-Type", "")
		content_encoding = response.headers.get("Content-Encoding", "")
		logger.info(
			"Got response status=%s, Content-Type=%s, Content-Encoding=%s, duration=%0.3fs",
			response.status_code,
			content_type,
			content_encoding,
			(time.time() - start_time),
		)

		if "server" in response.headers:
			self.server_name = response.headers.get("server")

		data = response.content
		# gzip and deflate transfer-encodings are automatically decoded
		if "lz4" in content_encoding:
			logger.trace("Decompressing data with lz4")
			data = lz4.frame.decompress(data)

		error_cls = None
		error_msg = None
		if response.status_code != 200:
			error_cls = OpsiRpcError
			error_msg = str(response.status_code)
			if response.status_code == 401:
				error_cls = BackendAuthenticationError
			if response.status_code == 403:
				error_cls = BackendPermissionDeniedError

		if self.raw_responses:
			if error_cls:
				raise error_cls(f"{error_msg} (error on server)")
			return data

		try:
			if content_type == "application/msgpack":
				data = msgpack.loads(data)
			else:
				data = json.loads(data)
		except Exception:  # pylint: disable=broad-except
			if error_cls:
				raise error_cls(f"{error_msg} (error on server)") from None
			raise

		if data.get("error"):
			logger.debug("JSONRPC-response contains error")
			if not error_cls:
				error_cls = OpsiRpcError
			if isinstance(data["error"], dict) and data["error"].get("message"):
				error_msg = data["error"]["message"]
			else:
				error_msg = str(data["error"])

		if error_cls:
			raise error_cls(f"{error_msg} (error on server)")

		data = deserialize(data.get("result"), prevent_object_creation=method.endswith("_getHashes") if self.create_objects else True)

		return data

	def _create_instance_methods(self) -> None:  # pylint: disable=too-many-locals
		if self._interface is None:
			raise ValueError("No interface specification present for _create_instance_methods.")
		for method in self._interface:
			try:  # pylint: disable=loop-try-except-usage
				method_name = method["name"]

				if method_name in (
					"backend_exit",
					"backend_getInterface",
					"jsonrpc_getSessionId",
				):
					continue

				logger.debug("Creating instance method: %s", method_name)  # pylint: disable=loop-global-usage

				args = method["args"]
				varargs = method["varargs"]
				keywords = method["keywords"]
				defaults = method["defaults"]

				arg_list = []
				call_list = []
				for i, argument in enumerate(args):
					if argument == "self":
						continue

					if isinstance(defaults, (tuple, list)) and len(defaults) + i >= len(args):  # pylint: disable=loop-invariant-statement
						default = defaults[len(defaults) - len(args) + i]  # pylint: disable=loop-invariant-statement
						if isinstance(default, str):
							default = "{0!r}".format(default).replace('"', "'")  # pylint: disable=consider-using-f-string
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

				logger.trace("%s: arg string is: %s", method_name, arg_string)  # pylint: disable=loop-global-usage
				logger.trace("%s: call string is: %s", method_name, call_string)  # pylint: disable=loop-global-usage
				with warnings.catch_warnings():  # pylint: disable=dotted-import-in-loop
					exec(  # pylint: disable=exec-used
						f'def {method_name}(self, {arg_string}): return self.execute_rpc("{method_name}", [{call_string}])'
					)
					setattr(self, method_name, types.MethodType(eval(method_name), self))  # pylint: disable=eval-used,dotted-import-in-loop
			except Exception as err:  # pylint: disable=broad-except
				logger.critical("Failed to create instance method '%s': %s", method, err)  # pylint: disable=loop-global-usage

	@no_export
	def connect(self) -> None:
		logger.info("Connecting to service %s", self.base_url)
		if self._create_methods:
			self._interface = self.execute_rpc("backend_getInterface")
			self._create_instance_methods()
		self._http_adapter.max_retries = Retry.from_int(self._http_max_retries)
		logger.debug("Connected to service %s", self.base_url)
		self._connected = True

	@no_export
	def disconnect(self) -> None:
		if self._connected:
			try:
				self.execute_rpc("backend_exit")
			except Exception:  # pylint: disable=broad-except
				pass
			try:
				self.session.close()
			except Exception:  # pylint: disable=broad-except
				pass
			self._connected = False
