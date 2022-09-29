# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import json
import platform
import time
from datetime import datetime, timedelta
from pathlib import Path
from threading import Thread
from typing import Any, Iterable, List, Optional, Tuple, Union
from unittest import mock
from urllib.parse import unquote

import pytest

from opsicommon import __version__
from opsicommon.client.opsiservice import (
	MIN_VERSION_GZIP,
	MIN_VERSION_LZ4,
	MIN_VERSION_MESSAGEBUS,
	MIN_VERSION_MSGPACK,
	MIN_VERSION_SESSION_API,
	UIB_OPSI_CA,
	Messagebus,
	MessagebusListener,
	OpsiConnectionError,
	OpsiServiceVerificationError,
	OpsiTimeoutError,
	ServiceClient,
	ServiceConnectionListener,
	ServiceVerificationModes,
	WebSocketApp,
)
from opsicommon.exceptions import (
	BackendAuthenticationError,
	BackendPermissionDeniedError,
	OpsiRpcError,
)
from opsicommon.messagebus import (
	FileUploadResultMessage,
	JSONRPCRequestMessage,
	JSONRPCResponseMessage,
	Message,
	MessageType,
)
from opsicommon.ssl import as_pem, create_ca, create_server_cert
from opsicommon.system import set_system_datetime
from opsicommon.testing.helpers import (  # type: ignore[import]
	HTTPTestServerRequestHandler,
	environment,
	http_test_server,
)


class MyConnectionListener(ServiceConnectionListener):
	def __init__(self) -> None:
		super().__init__()
		self.events: List[Tuple[str, ServiceClient, Optional[Exception]]] = []

	def connection_open(self, service_client: ServiceClient) -> None:
		self.events.append(("open", service_client, None))

	def connection_established(self, service_client: "ServiceClient") -> None:
		self.events.append(("established", service_client, None))

	def connection_failed(self, service_client: ServiceClient, exception: Exception) -> None:
		self.events.append(("failed", service_client, exception))

	def connection_closed(self, service_client: ServiceClient) -> None:
		self.events.append(("closed", service_client, None))


def test_arguments() -> None:  # pylint: disable=too-many-statements
	# address
	assert ServiceClient("localhost").base_url == "https://localhost:4447"
	assert ServiceClient("https://localhost").base_url == "https://localhost:4447"
	assert ServiceClient("https://localhost:4448").base_url == "https://localhost:4448"
	assert ServiceClient("https://localhost:4448/xy").base_url == "https://localhost:4448"
	assert ServiceClient("localhost:4448").base_url == "https://localhost:4448"
	assert ServiceClient("1.2.3.4").base_url == "https://1.2.3.4:4447"
	assert ServiceClient("::1").base_url == "https://[::1]:4447"
	assert ServiceClient("2001:0db8:85a3:0000:0000:8a2e:0370:7334").base_url == "https://[2001:db8:85a3::8a2e:370:7334]:4447"
	assert (
		ServiceClient("[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:4448").base_url == "https://[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:4448"
	)
	with pytest.raises(ValueError):
		ServiceClient("http://localhost:4448")

	# username / password
	client = ServiceClient("localhost")
	assert client._username is None  # pylint: disable=protected-access
	assert client._password is None  # pylint: disable=protected-access

	client = ServiceClient("localhost", username="", password="")
	assert client._username == ""  # pylint: disable=protected-access
	assert client._password == ""  # pylint: disable=protected-access

	client = ServiceClient("localhost", username="user", password="pass")
	assert client._username == "user"  # pylint: disable=protected-access
	assert client._password == "pass"  # pylint: disable=protected-access

	client = ServiceClient("https://usr:pas@localhost")
	assert client._username == "usr"  # pylint: disable=protected-access
	assert client._password == "pas"  # pylint: disable=protected-access

	with pytest.raises(ValueError, match="Different usernames supplied"):
		client = ServiceClient("https://usr:pas@localhost", username="user", password="pass")

	with pytest.raises(ValueError, match="Different usernames supplied"):
		client = ServiceClient("https://usr:pas@localhost", username="user")

	with pytest.raises(ValueError, match="Different passwords supplied"):
		client = ServiceClient("https://usr:pas@localhost", username="usr", password="pass")

	with pytest.raises(ValueError, match="Different passwords supplied"):
		client = ServiceClient("https://usr:pas@localhost", password="pass")

	client = ServiceClient("https://:pass@localhost")
	assert client._username == ""  # pylint: disable=protected-access
	assert client._password == "pass"  # pylint: disable=protected-access

	# verify / ca_cert_file
	assert ServiceClient("::1")._ca_cert_file is None  # pylint: disable=protected-access
	assert ServiceClient("::1", ca_cert_file="cacert.pem")._ca_cert_file == Path("cacert.pem")  # pylint: disable=protected-access
	assert ServiceClient("::1", ca_cert_file=Path("/x/cacert.pem"))._ca_cert_file == Path(  # pylint: disable=protected-access
		"/x/cacert.pem"
	)
	for mode in ServiceVerificationModes:
		assert ServiceClient("::1", ca_cert_file="ca.pem", verify=mode)._verify == mode  # pylint: disable=protected-access
		assert ServiceClient("::1", ca_cert_file="ca.pem", verify=mode.value)._verify == mode  # pylint: disable=protected-access
	for mode in ServiceVerificationModes.OPSI_CA, ServiceVerificationModes.UIB_OPSI_CA:
		with pytest.raises(ValueError, match="ca_cert_file required"):  # pylint: disable=dotted-import-in-loop
			ServiceClient("::1", verify=mode)
	with pytest.raises(ValueError, match="bad_mode"):  # pylint: disable=dotted-import-in-loop
		ServiceClient("::1", verify="bad_mode")

	# session_cookie
	assert ServiceClient("::1", session_cookie="cookie=val")._session_cookie == "cookie=val"  # pylint: disable=protected-access
	with pytest.raises(ValueError):
		assert ServiceClient("::1", session_cookie="cookie")

	# session_lifetime
	assert ServiceClient("::1", session_lifetime=10)._session_lifetime == 10  # pylint: disable=protected-access
	assert ServiceClient("::1", session_lifetime=-3)._session_lifetime == 1  # pylint: disable=protected-access

	# proxy_url
	assert ServiceClient("::1", proxy_url="system")._proxy_url == "system"  # pylint: disable=protected-access
	assert ServiceClient("::1", proxy_url=None)._proxy_url is None  # type: ignore[arg-type]  # pylint: disable=protected-access
	assert ServiceClient("::1", proxy_url="https://proxy:1234")._proxy_url == "https://proxy:1234"  # pylint: disable=protected-access

	# user_agent
	assert ServiceClient("::1")._user_agent == f"opsi-service-client/{__version__}"  # pylint: disable=protected-access
	assert ServiceClient("::1", user_agent=None)._user_agent == f"opsi-service-client/{__version__}"  # pylint: disable=protected-access
	assert ServiceClient("::1", user_agent="my app")._user_agent == "my app"  # pylint: disable=protected-access

	# connect_timeout
	assert ServiceClient("::1", connect_timeout=123)._connect_timeout == 123.0  # pylint: disable=protected-access
	assert ServiceClient("::1", connect_timeout=1.2)._connect_timeout == 1.2  # pylint: disable=protected-access
	assert ServiceClient("::1", connect_timeout=-1)._connect_timeout == 0.0  # pylint: disable=protected-access


def test_verify(tmpdir: Path) -> None:  # pylint: disable=too-many-statements
	other_ca_cert, _ = create_ca(subject={"CN": "python-opsi-common test other ca"}, valid_days=3)

	ca_cert, ca_key = create_ca(subject={"CN": "python-opsi-common test ca"}, valid_days=3)
	ca_key_file = tmpdir / "ca_key.pem"
	ca_cert_file = tmpdir / "ca_cert.pem"
	ca_key_file.write_text(as_pem(ca_key), encoding="utf-8")
	ca_cert_file.write_text(as_pem(ca_cert), encoding="utf-8")

	server_cert, server_key = create_server_cert(
		subject={"CN": "python-opsi-common test server cert"},
		valid_days=3,
		ip_addresses={"127.0.0.1", "::1"},
		hostnames={"localhost", "ip6-localhost"},
		ca_key=ca_key,
		ca_cert=ca_cert,
	)
	server_key_file = tmpdir / "server_key.pem"
	server_cert_file = tmpdir / "server_cert.pem"
	server_key_file.write_text(as_pem(server_key), encoding="utf-8")
	server_cert_file.write_text(as_pem(server_cert), encoding="utf-8")

	opsi_ca_file_on_client = tmpdir / "opsi_ca_file_on_client.pem"

	with http_test_server(
		server_key=server_key_file,
		server_cert=server_cert_file,
		response_body=as_pem(ca_cert).encode("utf-8"),
		response_headers={"server": "opsiconfd 4.2.1.1 (uvicorn)"},
	) as server:
		# strict_check
		assert not opsi_ca_file_on_client.exists()
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="strict_check") as client:
			with pytest.raises(OpsiServiceVerificationError):
				client.connect()
			with pytest.raises(OpsiServiceVerificationError):
				client.connect_messagebus()

		with ServiceClient(f"https://127.0.0.1:{server.port}", ca_cert_file=ca_cert_file, verify="strict_check") as client:
			client.connect()
			client.connect_messagebus()

		with ServiceClient(f"https://127.0.0.1:{server.port}", ca_cert_file=opsi_ca_file_on_client, verify="strict_check") as client:
			with pytest.raises(OpsiServiceVerificationError):
				client.connect()

		assert not opsi_ca_file_on_client.exists()

		# accept_all
		with ServiceClient(f"https://127.0.0.1:{server.port}", ca_cert_file=None, verify="accept_all") as client:
			client.connect()

		with ServiceClient(f"https://127.0.0.1:{server.port}", ca_cert_file=ca_cert_file, verify="accept_all") as client:
			client.connect()

		with ServiceClient(f"https://127.0.0.1:{server.port}", ca_cert_file=opsi_ca_file_on_client, verify="accept_all") as client:
			client.connect()

		assert opsi_ca_file_on_client.exists()
		assert opsi_ca_file_on_client.read_text(encoding="utf-8") == as_pem(ca_cert)

		# opsi_ca
		with ServiceClient(f"https://127.0.0.1:{server.port}", ca_cert_file=opsi_ca_file_on_client, verify="opsi_ca") as client:
			client.connect()
		assert opsi_ca_file_on_client.read_text(encoding="utf-8") == as_pem(ca_cert)

		opsi_ca_file_on_client.write_text(as_pem(other_ca_cert), encoding="utf-8")
		with ServiceClient(f"https://127.0.0.1:{server.port}", ca_cert_file=opsi_ca_file_on_client, verify="opsi_ca") as client:
			with pytest.raises(OpsiServiceVerificationError):
				client.connect()

			opsi_ca_file_on_client.write_text("", encoding="utf-8")
			client.connect()

			assert opsi_ca_file_on_client.read_text(encoding="utf-8") == as_pem(ca_cert)
			assert client.get("/")[0] == 200

		# uib_opsi_ca
		with ServiceClient(f"https://127.0.0.1:{server.port}", ca_cert_file=opsi_ca_file_on_client, verify="uib_opsi_ca") as client:
			client.connect()
			assert opsi_ca_file_on_client.read_text(encoding="utf-8") == as_pem(ca_cert) + "\n" + UIB_OPSI_CA

		opsi_ca_file_on_client.write_text("", encoding="utf-8")
		with ServiceClient(f"https://127.0.0.1:{server.port}", ca_cert_file=opsi_ca_file_on_client, verify="uib_opsi_ca") as client:
			client.connect()
			assert opsi_ca_file_on_client.read_text(encoding="utf-8") == as_pem(ca_cert) + "\n" + UIB_OPSI_CA


def test_cookie_handling(tmp_path: Path) -> None:
	session_cookie = "COOKIE-NAME=abc"
	with http_test_server(generate_cert=True, response_headers={"Set-Cookie": f"{session_cookie}; SameSite=Lax"}) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all") as client:
			client.get("/")
			assert client.session_cookie == session_cookie

	log_file = tmp_path / "request.log"
	session_cookie = "COOKIE-NAME=üöä"
	with http_test_server(generate_cert=True, log_file=log_file) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all", session_cookie=session_cookie) as client:
			client.get("/")
			assert client.session_cookie == session_cookie
		for line in log_file.read_text(encoding="utf-8").strip().split("\n"):
			request = json.loads(line)  # pylint: disable=dotted-import-in-loop
			assert unquote(request["headers"].get("Cookie")) == session_cookie


def test_proxy(tmp_path: Path) -> None:
	log_file = tmp_path / "request.log"
	with http_test_server(generate_cert=True, log_file=log_file, response_headers={"server": "opsiconfd 4.2.1.0 (uvicorn)"}) as server:
		with ServiceClient(
			f"https://localhost:{server.port+1}", proxy_url=f"http://localhost:{server.port}", verify="accept_all", connect_timeout=2
		) as client:
			# Proxy will not be used for localhost (no_proxy_addresses)
			with pytest.raises(OpsiConnectionError):
				client.connect()

		proxy_env = {"http_proxy": f"http://localhost:{server.port}", "https_proxy": f"http://localhost:{server.port}"}
		with environment(proxy_env), pytest.raises(OpsiConnectionError):
			with ServiceClient(f"https://localhost:{server.port+1}", proxy_url="system", verify="accept_all", connect_timeout=2) as client:
				client.connect()

		with mock.patch("opsicommon.client.opsiservice.ServiceClient.no_proxy_addresses", []):
			# Now proxy will be used for localhost

			proxy_env = {"http_proxy": "http://should-not-be-used", "https_proxy": "http://should-not-be-used"}
			with environment(proxy_env):
				for host, proxy_host in (
					("localhost", "localhost"),
					("localhost", "127.0.0.1"),
					("127.0.0.1", "localhost"),
					("127.0.0.1", "127.0.0.1"),
				):
					with ServiceClient(
						f"https://{host}:{server.port+1}",  # pylint: disable=loop-invariant-statement
						proxy_url=f"https://{proxy_host}:{server.port}",
						verify="accept_all",
						connect_timeout=2,
					) as client:
						with pytest.raises(OpsiConnectionError):  # pylint: disable=dotted-import-in-loop
							# HTTPTestServer sends error 501 on CONNECT requests
							client.connect()
						request = json.loads(log_file.read_text(encoding="utf-8"))  # pylint: disable=dotted-import-in-loop
						# print(request)
						assert request["method"] == "CONNECT"
						assert request["path"] == f"{host}:{server.port+1}"
						log_file.write_bytes(b"")

			proxy_env = {
				"http_proxy": f"http://localhost:{server.port+2}",
				"https_proxy": f"https://localhost:{server.port}",
				"no_proxy": "",
			}
			with environment(proxy_env):
				with ServiceClient(
					f"https://localhost:{server.port+1}",  # pylint: disable=loop-invariant-statement
					proxy_url="system",
					verify="accept_all",
					connect_timeout=2,
				) as client:
					with pytest.raises(OpsiConnectionError):  # pylint: disable=dotted-import-in-loop
						# HTTPTestServer sends error 501 on CONNECT requests
						client.connect()
					request = json.loads(log_file.read_text(encoding="utf-8"))
					# print(request)
					assert request["method"] == "CONNECT"
					assert request.get("path") == f"localhost:{server.port+1}"
					log_file.write_bytes(b"")

			proxy_env = {"http_proxy": "http://should-not-be-used", "https_proxy": "https://should-not-be-used"}
			with environment(proxy_env):
				with ServiceClient(
					f"https://localhost:{server.port}",  # pylint: disable=loop-invariant-statement
					proxy_url=None,  # Do not use any proxy
					verify="accept_all",
					connect_timeout=2,
				) as client:
					client.connect()
					client.connect_messagebus()

					reqs = [json.loads(req) for req in log_file.read_text(encoding="utf-8").strip().split("\n")]
					# print(reqs)
					assert reqs[0]["method"] == "HEAD"
					assert reqs[0]["path"] == "/"

					assert reqs[1]["method"] == "GET"
					assert reqs[1]["path"] == "/messagebus/v1"
					assert reqs[1]["headers"]["Upgrade"] == "websocket"

					log_file.write_bytes(b"")


@pytest.mark.parametrize(
	"server_name, expected_version, expected_content_type, expected_content_encoding, expected_messagebus_available",
	(
		(f"opsiconfd service {MIN_VERSION_MESSAGEBUS}", MIN_VERSION_MESSAGEBUS.release, "application/msgpack", "lz4", True),
		(f"opsiconfd service {MIN_VERSION_MSGPACK}", MIN_VERSION_MSGPACK.release, "application/msgpack", "lz4", False),
		(f"opsiconfd service {MIN_VERSION_LZ4}", MIN_VERSION_LZ4.release, "application/msgpack", "lz4", False),
		(f"opsiconfd service {MIN_VERSION_GZIP}", MIN_VERSION_GZIP.release, "application/json", "gzip", False),
		("opsi 4.1.0.1", (4, 1, 0, 1), "application/json", None, False),
		("apache 2.0.1", (0,), "application/json", None, False),
	),
)
def test_server_name_handling(  # pylint: disable=too-many-arguments
	tmp_path: Path,
	server_name: str,
	expected_version: tuple,
	expected_content_type: str,
	expected_content_encoding: Optional[str],
	expected_messagebus_available: bool,
) -> None:
	log_file = tmp_path / f"{server_name}.log"
	with http_test_server(generate_cert=True, log_file=log_file, response_headers={"Server": server_name}) as server:
		server_version = None
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all") as client:
			client.connect()
			assert client.server_name == server_name
			# print(server_name, client.server_version, client.server_version.release, expected_version)
			assert client.server_version.release == expected_version
			assert client.messagebus_available == expected_messagebus_available
			client.jsonrpc("method", ["param" * 100])
			server_version = client.server_version  # Keep server_version after logout

		reqs = [json.loads(req) for req in log_file.read_text(encoding="utf-8").strip().split("\n")]

		# Connect request
		assert reqs[0]["method"] == "HEAD"

		# JSONRPC request
		assert reqs[1]["method"] == "POST"
		assert reqs[1]["path"] == "/rpc"
		assert reqs[1]["headers"].get("Content-Type") == expected_content_type
		assert reqs[1]["headers"].get("Content-Encoding") == expected_content_encoding

		# Close session request
		assert reqs[2]["method"] == "POST"
		if server_version and server_version >= MIN_VERSION_SESSION_API:
			assert reqs[2]["path"] == "/session/logout"
		else:
			assert reqs[2]["path"] == "/rpc"
			assert reqs[2]["request"]["method"] == "backend_exit"

		# Clear log
		log_file.write_bytes(b"")


def test_connect_disconnect() -> None:  # pylint: disable=too-many-statements
	with http_test_server(generate_cert=True, response_headers={"server": "opsiconfd 4.1.0.1 (uvicorn)"}) as server:
		listener = MyConnectionListener()
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all") as client:
			with listener.register(client):
				assert not client.messagebus_available
				assert client.connected
				with pytest.raises(RuntimeError):
					client.connect_messagebus()
				client.disconnect()
				assert len(listener.events) == 3
				assert listener.events[0][0] == "open"
				assert listener.events[1][0] == "established"
				assert listener.events[2][0] == "closed"

		listener = MyConnectionListener()
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all") as client:
			with listener.register(client):
				with pytest.raises(RuntimeError):
					client.connect_messagebus()
				assert client.connected
				assert not client.messagebus_available
				client.disconnect()
				assert len(listener.events) == 3
				assert listener.events[0][0] == "open"
				assert listener.events[1][0] == "established"
				assert listener.events[2][0] == "closed"

	with http_test_server(generate_cert=True, response_headers={"server": "opsiconfd 4.2.1.0 (uvicorn)"}) as server:
		client = ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all")
		client.connect()
		assert client.connected is True
		assert client.server_name == "opsiconfd 4.2.1.0 (uvicorn)"
		assert client.server_version.release == (4, 2, 1, 0)
		client.disconnect()
		assert client.connected is False
		assert client.server_name == ""
		assert client.server_version.release == (0,)

		client.disconnect()
		assert client.connected is False
		assert client.server_name == ""
		assert client.server_version.release == (0,)

		client.get("/")
		assert client.connected is True
		assert client.server_name == "opsiconfd 4.2.1.0 (uvicorn)"
		assert client.server_version.release == (4, 2, 1, 0)

		client.disconnect()
		assert client.connected is False
		assert client.server_name == ""
		assert client.server_version.release == (0,)

		client.connect_messagebus()
		assert client.messagebus_connected is True

		client.disconnect()
		assert client.messagebus_connected is False
		assert client.connected is False

		client.connect_messagebus()
		assert client.messagebus_connected is True

		client.disconnect()
		assert client.messagebus_connected is False
		assert client.connected is False


def test_multi_address() -> None:
	with http_test_server(generate_cert=True, response_headers={"server": "opsiconfd 4.1.0.1 (uvicorn)"}) as server:
		with ServiceClient((f"https://127.0.0.1:{server.port+1}", f"https://127.0.0.1:{server.port}"), verify="accept_all") as client:
			client.connect()
			assert client.connected
			assert client.base_url == f"https://127.0.0.1:{server.port}"

		with ServiceClient((f"https://127.0.0.1:{server.port}", f"https://localhost:{server.port}"), verify="accept_all") as client:
			client.connect()
			assert client.connected
			assert client.base_url == f"https://127.0.0.1:{server.port}"


def test_messagebus_reconnect() -> None:
	class MBListener(MessagebusListener):
		messages = []  # pylint: disable=use-tuple-over-list

		def message_received(self, message: Message) -> None:
			self.messages.append(message)

	rpc_id = 0

	def ws_connect_callback(handler: HTTPTestServerRequestHandler) -> None:
		nonlocal rpc_id
		for _ in range(3):
			rpc_id += 1
			msg = JSONRPCResponseMessage(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
				sender="service:worker:test:1", channel="host:test-client.uib.local", rpc_id=str(rpc_id), result="RESULT"
			)
			handler.ws_send_message(msg.to_msgpack())

	with http_test_server(
		generate_cert=True, ws_connect_callback=ws_connect_callback, response_headers={"server": "opsiconfd 4.2.1.0 (uvicorn)"}
	) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all") as client:
			client.messagebus.reconnect_wait = 5
			listener = MBListener()

			with listener.register(client.messagebus):
				client.connect_messagebus()
				time.sleep(3)
				server.restart(new_cert=True)
				time.sleep(10)

			expected_messages = 6
			assert len(listener.messages) == expected_messages
			rpc_ids = sorted([int(m.rpc_id) for m in listener.messages])  # type: ignore[attr-defined]
			assert rpc_ids[:6] == list(range(1, expected_messages + 1))


def test_get() -> None:
	response_body = b"test" * 1000
	thread_count = 10 if platform.system().lower() == "linux" else 5

	class ReqThread(Thread):
		def __init__(self, client: ServiceClient) -> None:
			super().__init__()
			self.daemon = True
			self.client = client
			self.response: Tuple[int, str, dict, bytes] = (0, "", {}, b"")

		def run(self) -> None:
			self.client.get("/")
			self.response = self.client.get("test")  # type: ignore[assignment]

	with http_test_server(
		generate_cert=True, response_status=(202, "status"), response_headers={"x-1": "1", "x-2": "2"}, response_body=response_body
	) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all") as client:
			threads = [ReqThread(client) for _ in range(thread_count)]
			for thread in threads:
				thread.start()
			for thread in threads:
				thread.join(10)
			for thread in threads:
				(status_code, reason, headers, content) = thread.response
				assert status_code == 202  # pylint: disable=loop-invariant-statement
				assert reason == "status"  # pylint: disable=loop-invariant-statement
				assert headers["x-1"] == "1"  # pylint: disable=loop-invariant-statement
				assert headers["x-2"] == "2"  # pylint: disable=loop-invariant-statement
				assert content == response_body  # pylint: disable=loop-invariant-statement


def test_timeouts() -> None:
	listener = MyConnectionListener()

	with http_test_server(generate_cert=True, response_delay=3) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port+1}", connect_timeout=4) as client:
			client.register_connection_listener(listener)
			with pytest.raises(OpsiConnectionError):
				client.connect()
			assert len(listener.events) == 2
			assert listener.events[0][0] == "open"
			assert listener.events[1][0] == "failed"
			assert listener.events[1][1] is client
			assert "max retries exceeded" in str(listener.events[1][2]).lower()

		with ServiceClient(f"https://127.0.0.1:{server.port}", connect_timeout=4, verify="accept_all") as client:
			client.connect()
			start = time.time()
			with pytest.raises(OpsiTimeoutError):
				client.get("/", read_timeout=2)
			assert round(time.time() - start) >= 2

			assert client.get("/", read_timeout=4)[0] == 200


def test_messagebus_ping() -> None:
	pong_count = 0

	def ws_connect_callback(handler: HTTPTestServerRequestHandler) -> None:
		handler._ws_send_message(handler._opcode_ping, b"")  # pylint: disable=protected-access

	def _on_pong(messagebus: Messagebus, app: WebSocketApp, message: bytes) -> None:  # pylint: disable=unused-argument
		nonlocal pong_count
		pong_count += 1

	with http_test_server(
		generate_cert=True, ws_connect_callback=ws_connect_callback, response_headers={"server": "opsiconfd 4.2.1.0 (uvicorn)"}
	) as server:
		# Test original _on_pong method
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all") as client:
			client.messagebus.ping_interval = 1
			client.messagebus.ping_timeout = None  # type: ignore[assignment]
			client.connect_messagebus()
			time.sleep(3)

		# Override _on_pong method and count pongs
		with mock.patch("opsicommon.client.opsiservice.Messagebus._on_pong", _on_pong):
			with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all") as client:
				client.messagebus.ping_interval = 1
				client.messagebus.ping_timeout = None  # type: ignore[assignment]
				client.connect_messagebus()
				time.sleep(5)
				assert pong_count >= 3


def test_jsonrpc(tmp_path: Path) -> None:
	log_file = tmp_path / "request.log"
	with http_test_server(generate_cert=True, log_file=log_file, response_headers={"server": "opsiconfd 4.2.0.0 (uvicorn)"}) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all") as client:
			params: List[Union[Tuple[Any, ...], List[Any], None]] = [
				[1],
				(1, 2),
				["1", "2", 3],
				[None, "str"],
				(True, False),
				[],
				None,
				("test",),
				tuple(),
			]
			for _params in params:
				client.jsonrpc("method", params=_params)  # pylint: disable=loop-invariant-statement

			server.restart(new_cert=True)

			client.jsonrpc("reconnect")

			reqs = [json.loads(req) for req in log_file.read_text(encoding="utf-8").strip().split("\n")]
			assert reqs[0]["method"] == "HEAD"
			for idx in range(len(params)):  # pylint: disable=consider-using-enumerate
				assert reqs[idx + 1]["path"] == "/rpc"
				assert reqs[idx + 1]["method"] == "POST"
				assert reqs[idx + 1]["request"]["method"] == "method"
				assert reqs[idx + 1]["request"]["jsonrpc"] == "2.0"
				assert reqs[idx + 1]["request"]["params"] == list(params[idx] or [])

			assert reqs[-1]["method"] == "POST"
			assert reqs[-1]["request"]["method"] == "reconnect"


def test_jsonrpc_error_handling() -> None:
	with http_test_server(generate_cert=True) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all") as client:
			client.connect()
			server.response_status = (500, "internal server error")
			server.response_body = json.dumps({"error": {"message": "internal server error"}}).encode("utf-8")
			with pytest.raises(OpsiRpcError):
				client.jsonrpc("method")
			res = client.jsonrpc("method", return_result_only=False)
			assert res["error"]["message"] == "internal server error"

	with http_test_server(generate_cert=True) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all") as client:
			client.connect()
			server.response_status = (401, "auth error")
			server.response_body = json.dumps({"error": {"message": "auth error"}}).encode("utf-8")
			with pytest.raises(BackendAuthenticationError):
				client.jsonrpc("method")
			res = client.jsonrpc("method", return_result_only=False)
			assert res["error"]["message"] == "auth error"

	with http_test_server(generate_cert=True) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all") as client:
			client.connect()
			server.response_status = (403, "permission denied")
			server.response_body = json.dumps({"error": {"message": "permission denied"}}).encode("utf-8")
			with pytest.raises(BackendPermissionDeniedError):
				client.jsonrpc("method")
			res = client.jsonrpc("method", return_result_only=False)
			assert res["error"]["message"] == "permission denied"

	with http_test_server(generate_cert=True) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all") as client:
			client.connect()
			server.response_body = json.dumps({"error": {"message": "err_msg"}}).encode("utf-8")
			with pytest.raises(OpsiRpcError) as err:
				client.jsonrpc("method")
			assert err.value.message == "err_msg"
			res = client.jsonrpc("method", return_result_only=False)
			assert res["error"]["message"] == "err_msg"

	with http_test_server(generate_cert=True) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all") as client:
			client.connect()
			server.response_body = json.dumps({"error": {"message": "err_msg2"}}).encode("utf-8")
			with pytest.raises(OpsiRpcError) as err:
				client.jsonrpc("method")
			assert err.value.message == "err_msg2"
			res = client.jsonrpc("method", return_result_only=False)
			assert res["error"]["message"] == "err_msg2"


def test_messagebus_jsonrpc() -> None:
	delay = 0.0
	rpc_error = None

	def ws_message_callback(handler: HTTPTestServerRequestHandler, message: bytes) -> None:
		nonlocal delay
		nonlocal rpc_error
		msg = JSONRPCRequestMessage.from_msgpack(message)
		time.sleep(delay)
		res = JSONRPCResponseMessage(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
			sender="service:worker:test:1",
			channel="host:test-client.uib.local",
			rpc_id=msg.rpc_id,
			result=None if rpc_error else msg.params,
			error=rpc_error,
		)
		handler.ws_send_message(res.to_msgpack())

	with http_test_server(
		generate_cert=True, ws_message_callback=ws_message_callback, response_headers={"server": "opsiconfd 4.2.1.0 (uvicorn)"}
	) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all") as client:
			messagebus = client.connect_messagebus()
			params: List[Union[Tuple[Any, ...], List[Any], None]] = [
				[1],
				(1, 2),
				["1", "2", 3],
				[None, "str"],
				(True, False),
				[],
				None,
				("test",),
				tuple(),
			]
			for _params in params:
				res = messagebus.jsonrpc("test", params=_params)  # pylint: disable=loop-invariant-statement
				assert res == list(_params or [])

			delay = 3.0
			with mock.patch("opsicommon.client.opsiservice.RPC_TIMEOUTS", {"test": 1}):
				with pytest.raises(OpsiTimeoutError):
					res = messagebus.jsonrpc("test")

			rpc_error = {"code": 0, "message": "error_message", "data": {"class": "BackendPermissionDeniedError", "details": "details"}}
			with pytest.raises(BackendPermissionDeniedError) as err:
				res = messagebus.jsonrpc("test")
			assert err.value.message == "error_message"

			res = messagebus.jsonrpc("test", return_result_only=False)
			assert res["jsonrpc"] == "2.0"
			assert res["error"] == rpc_error
			assert res["result"] is None


def test_messagebus_multi_thread() -> None:
	class ReqThread(Thread):
		def __init__(self, client: ServiceClient) -> None:
			super().__init__()
			self.daemon = True
			self.client = client
			self.response = None

		def run(self) -> None:
			self.response = client.connect_messagebus().jsonrpc("test", return_result_only=False)

	def ws_message_callback(handler: HTTPTestServerRequestHandler, message: bytes) -> None:
		msg = JSONRPCRequestMessage.from_msgpack(message)
		res = JSONRPCResponseMessage(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
			sender="service:worker:test:1", channel="host:test-client.uib.local", rpc_id=msg.rpc_id, result=f"RESULT {msg.rpc_id}"
		)
		handler.ws_send_message(res.to_msgpack())

	with http_test_server(
		generate_cert=True, ws_message_callback=ws_message_callback, response_headers={"server": "opsiconfd 4.2.1.0 (uvicorn)"}
	) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all") as client:
			threads = [ReqThread(client) for _ in range(10)]
			for thread in threads:
				thread.start()
			for thread in threads:
				thread.join(10)
			for thread in threads:
				res = thread.response
				assert res
				assert res["id"]
				assert res["result"] == f"RESULT {res['id']}"
				assert res["error"] is None


def test_messagebus_listener() -> None:
	class StoringListener(MessagebusListener):
		def __init__(self, message_types: Iterable[Union[MessageType, str]] = None) -> None:
			super().__init__(message_types)
			self.messages_received: List[Message] = []
			self.expired_messages_received: List[Message] = []

		def message_received(self, message: Message) -> None:
			self.messages_received.append(message)

		def expired_message_received(self, message: Message) -> None:
			self.expired_messages_received.append(message)

	listener1 = StoringListener(message_types=(MessageType.JSONRPC_RESPONSE, "file_upload_result", "file_upload_result"))
	assert listener1.message_types == {MessageType.JSONRPC_RESPONSE, MessageType.FILE_UPLOAD_RESULT}

	listener2 = StoringListener(message_types={MessageType.JSONRPC_RESPONSE})
	assert listener2.message_types == {MessageType.JSONRPC_RESPONSE}

	listener3 = StoringListener()
	assert listener3.message_types is None

	listener4 = StoringListener(message_types={MessageType.FILE_CHUNK})
	assert listener4.message_types == {MessageType.FILE_CHUNK}

	def ws_connect_callback(handler: HTTPTestServerRequestHandler) -> None:
		now = int(time.time())
		handler.ws_send_message(
			JSONRPCResponseMessage(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
				id="11111111-1111-1111-1111-111111111111",
				sender="service:worker:test:1",
				channel="host:test-client.uib.local",
				rpc_id="1",
				expires=now - 1,
			).to_msgpack()
		)
		handler.ws_send_message(
			JSONRPCResponseMessage(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
				id="22222222-2222-2222-2222-222222222222",
				sender="service:worker:test:2",
				channel="host:test-client.uib.local",
				rpc_id="2",
				expires=0,
			).to_msgpack()
		)
		handler.ws_send_message(
			JSONRPCResponseMessage(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
				id="33333333-3333-3333-3333-333333333333", sender="service:worker:test:3", channel="host:test-client.uib.local", rpc_id="3"
			).to_msgpack()
		)
		handler.ws_send_message(b"DO NOT CRASH ON INVALID DATA")
		handler.ws_send_message(
			FileUploadResultMessage(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
				id="44444444-4444-4444-4444-444444444444",
				sender="service:worker:test:1",
				channel="host:test-client.uib.local",
				file_id="bcc2b07d-badc-49b8-9ff6-6ce37884686e",
				expires=now - 1,
			).to_msgpack()
		)
		handler.ws_send_message(
			FileUploadResultMessage(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
				id="55555555-5555-5555-5555-555555555555",
				sender="service:worker:test:1",
				channel="host:test-client.uib.local",
				file_id="49730998-2bfa-4ae3-b80c-bd0af20e9441",
			).to_msgpack()
		)

	with http_test_server(
		generate_cert=True, ws_connect_callback=ws_connect_callback, response_headers={"server": "opsiconfd 4.2.1.0 (uvicorn)"}
	) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all") as client:
			with (
				listener1.register(client.messagebus),
				listener2.register(client.messagebus),
				listener3.register(client.messagebus),
				listener4.register(client.messagebus),
			):
				assert len(client.messagebus._listener) == 4  # pylint: disable=protected-access
				client.connect_messagebus()
				# Receive messages for 3 seconds
				time.sleep(3)
			assert len(client.messagebus._listener) == 0  # pylint: disable=protected-access

	# listener1 / listener3: JSONRPC_RESPONSE + FILE_UPLOAD_RESULT
	for listener in (listener1, listener3):
		assert ["11111111-1111-1111-1111-111111111111", "44444444-4444-4444-4444-444444444444"] == sorted(
			[m.id for m in listener.expired_messages_received]
		)
		assert [
			"22222222-2222-2222-2222-222222222222",
			"33333333-3333-3333-3333-333333333333",
			"55555555-5555-5555-5555-555555555555",
		] == sorted([m.id for m in listener.messages_received])

	# listener2: JSONRPC_RESPONSE
	assert ["11111111-1111-1111-1111-111111111111"] == sorted([m.id for m in listener2.expired_messages_received])
	assert [
		"22222222-2222-2222-2222-222222222222",
		"33333333-3333-3333-3333-333333333333",
	] == sorted([m.id for m in listener2.messages_received])

	# listener4: FILE_CHUNK
	assert not listener4.expired_messages_received
	assert not listener4.messages_received


def test_server_date_update() -> None:
	now = datetime.utcnow()
	try:
		server_dt = now + timedelta(seconds=30)
		with http_test_server(
			generate_cert=True, response_headers={"date": datetime.strftime(server_dt, "%a, %d %b %Y %H:%M:%S UTC")}
		) as server:
			now = datetime.utcnow()
			with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all", max_time_diff=5) as client:
				client.connect()
				cur = datetime.utcnow()
				# Check if time was set to server time
				assert abs((server_dt - cur).total_seconds()) < 10
	finally:
		set_system_datetime(now)


def test_server_date_update_max_diff() -> None:
	now = datetime.utcnow()
	try:
		server_dt = now + timedelta(seconds=30)
		with http_test_server(
			generate_cert=True, response_headers={"date": datetime.strftime(server_dt, "%a, %d %b %Y %H:%M:%S UTC")}
		) as server:
			now = datetime.utcnow()
			with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all", max_time_diff=60) as client:
				client.connect()
				cur = datetime.utcnow()
				# Check if time was set to server time
				assert abs((server_dt - cur).total_seconds()) > 20
	finally:
		set_system_datetime(now)
