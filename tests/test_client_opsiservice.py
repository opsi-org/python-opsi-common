# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import time
from pathlib import Path
from threading import Thread
from typing import Tuple
from unittest import mock

import pytest

from opsicommon import __version__
from opsicommon.client.opsiservice import (
	UIB_OPSI_CA,
	Messagebus,
	MessagebusListener,
	OpsiConnectionError,
	OpsiServiceVerificationError,
	OpsiTimeoutError,
	ServiceClient,
	ServiceVerificationModes,
	WebSocketApp,
)
from opsicommon.messagebus import JSONRPCRequestMessage, JSONRPCResponseMessage, Message
from opsicommon.ssl import as_pem, create_ca, create_server_cert
from opsicommon.testing.helpers import (  # type: ignore[import]
	HTTPTestServerRequestHandler,
	http_test_server,
)


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

	client = ServiceClient("https://usr:pas@localhost", username="user", password="pass")
	assert client._username == "user"  # pylint: disable=protected-access
	assert client._password == "pass"  # pylint: disable=protected-access

	client = ServiceClient("https://usr:pas@localhost", password="pass")
	assert client._username == "usr"  # pylint: disable=protected-access
	assert client._password == "pass"  # pylint: disable=protected-access

	client = ServiceClient("https://:pass@localhost")
	assert client._username is None  # pylint: disable=protected-access
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
	for mode in ServiceVerificationModes.FETCH_CA, ServiceVerificationModes.FETCH_CA_TRUST_UIB:
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
		ip_addresses={"172.0.0.1", "::1"},
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
		with ServiceClient(f"https://localhost:{server.port}", verify="strict_check") as client:
			with pytest.raises(OpsiServiceVerificationError):
				client.connect()
			with pytest.raises(OpsiServiceVerificationError):
				client.connect_messagebus()

		with ServiceClient(f"https://localhost:{server.port}", ca_cert_file=ca_cert_file, verify="strict_check") as client:
			client.connect()
			client.connect_messagebus()

		with ServiceClient(f"https://localhost:{server.port}", ca_cert_file=opsi_ca_file_on_client, verify="strict_check") as client:
			with pytest.raises(OpsiServiceVerificationError):
				client.connect()

		# accept_all
		with ServiceClient(f"https://localhost:{server.port}", ca_cert_file=None, verify="accept_all") as client:
			client.connect()

		with ServiceClient(f"https://localhost:{server.port}", ca_cert_file=ca_cert_file, verify="accept_all") as client:
			client.connect()

		with ServiceClient(f"https://localhost:{server.port}", ca_cert_file=opsi_ca_file_on_client, verify="accept_all") as client:
			client.connect()

		assert not opsi_ca_file_on_client.exists()

		# fetch_ca
		with ServiceClient(f"https://localhost:{server.port}", ca_cert_file=opsi_ca_file_on_client, verify="fetch_ca") as client:
			client.connect()
		assert opsi_ca_file_on_client.read_text(encoding="utf-8") == as_pem(ca_cert)

		opsi_ca_file_on_client.write_text(as_pem(other_ca_cert), encoding="utf-8")
		with ServiceClient(f"https://localhost:{server.port}", ca_cert_file=opsi_ca_file_on_client, verify="fetch_ca") as client:
			with pytest.raises(OpsiServiceVerificationError):
				client.connect()

			opsi_ca_file_on_client.write_text("", encoding="utf-8")
			client.connect()

			assert opsi_ca_file_on_client.read_text(encoding="utf-8") == as_pem(ca_cert)
			assert client.get("/")[0] == 200

		# fetch_ca_trust_uib
		with ServiceClient(f"https://localhost:{server.port}", ca_cert_file=opsi_ca_file_on_client, verify="fetch_ca_trust_uib") as client:
			client.connect()
			assert opsi_ca_file_on_client.read_text(encoding="utf-8") == as_pem(ca_cert) + "\n" + UIB_OPSI_CA

		opsi_ca_file_on_client.write_text("", encoding="utf-8")
		with ServiceClient(f"https://localhost:{server.port}", ca_cert_file=opsi_ca_file_on_client, verify="fetch_ca_trust_uib") as client:
			client.connect()
			assert opsi_ca_file_on_client.read_text(encoding="utf-8") == as_pem(ca_cert) + "\n" + UIB_OPSI_CA


def test_connect_disconnect() -> None:
	with http_test_server(generate_cert=True, response_headers={"server": "opsiconfd 4.2.0.1 (uvicorn)"}) as server:
		with ServiceClient(f"https://localhost:{server.port}", verify="accept_all") as client:
			assert not client.messagebus_available
			assert client.connected
			with pytest.raises(RuntimeError):
				client.connect_messagebus()

		with ServiceClient(f"https://localhost:{server.port}", verify="accept_all") as client:
			with pytest.raises(RuntimeError):
				client.connect_messagebus()
			assert client.connected
			assert not client.messagebus_available

	with http_test_server(generate_cert=True, response_headers={"server": "opsiconfd 4.2.1.0 (uvicorn)"}) as server:
		client = ServiceClient(f"https://localhost:{server.port}", verify="accept_all")
		client.connect()
		assert client.connected is True
		assert client.server_name == "opsiconfd 4.2.1.0 (uvicorn)"
		assert client.server_version == (4, 2, 1, 0)
		client.disconnect()
		assert client.connected is False
		assert client.server_name == ""
		assert client.server_version == (0, 0, 0, 0)

		client.disconnect()
		assert client.connected is False
		assert client.server_name == ""
		assert client.server_version == (0, 0, 0, 0)

		client.get("/")
		assert client.connected is True
		assert client.server_name == "opsiconfd 4.2.1.0 (uvicorn)"
		assert client.server_version == (4, 2, 1, 0)

		client.disconnect()
		assert client.connected is False
		assert client.server_name == ""
		assert client.server_version == (0, 0, 0, 0)

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


def test_messagebus_reconnect() -> None:
	class Listener(MessagebusListener):
		messages = []  # pylint: disable=use-tuple-over-list

		def message_received(self, message: Message) -> None:
			self.messages.append(message)

	rpc_id = 0

	def ws_connect_callback(handler: HTTPTestServerRequestHandler) -> None:
		time.sleep(1)
		nonlocal rpc_id
		for _ in range(3):
			rpc_id += 1
			msg = JSONRPCResponseMessage(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
				sender="service:worker:test:1", channel="host:test-client.uib.local", rpc_id=str(rpc_id), result="RESULT"
			)
			handler.ws_send_message(msg.to_msgpack())
		handler._ws_connected = False  # pylint: disable=protected-access

	with http_test_server(
		generate_cert=True, ws_connect_callback=ws_connect_callback, response_headers={"server": "opsiconfd 4.2.1.0 (uvicorn)"}
	) as server:
		with ServiceClient(f"https://localhost:{server.port}", verify="accept_all") as client:
			listener = Listener()

			with listener.register(client.messagebus):
				client.connect_messagebus()
				time.sleep(10)

			assert len(listener.messages) >= 6
			rpc_ids = sorted([int(m.rpc_id) for m in listener.messages])  # type: ignore[attr-defined]
			assert rpc_ids[:6] == [1, 2, 3, 4, 5, 6]


def test_get() -> None:
	response_body = b"test" * 1000

	class ReqThread(Thread):
		def __init__(self, client: ServiceClient) -> None:
			super().__init__()
			self.daemon = True
			self.client = client
			self.response: Tuple[int, str, dict, bytes] = (0, "", {}, b"")

		def run(self) -> None:
			self.response = self.client.get("/")  # type: ignore[assignment]

	with http_test_server(
		generate_cert=True, response_status=(202, "status"), response_headers={"x-1": "1", "x-2": "2"}, response_body=response_body
	) as server:
		with ServiceClient(f"https://localhost:{server.port}", verify="accept_all") as client:
			threads = [ReqThread(client) for _ in range(50)]
			for thread in threads:
				thread.start()
			for thread in threads:
				thread.join(5)
			for thread in threads:
				(status_code, reason, headers, content) = thread.response
				assert status_code == 202  # pylint: disable=loop-invariant-statement
				assert reason == "status"  # pylint: disable=loop-invariant-statement
				assert headers["x-1"] == "1"  # pylint: disable=loop-invariant-statement
				assert headers["x-2"] == "2"  # pylint: disable=loop-invariant-statement
				assert content == response_body  # pylint: disable=loop-invariant-statement


def test_timeouts() -> None:
	with http_test_server(generate_cert=True, response_delay=3) as server:
		with ServiceClient(f"https://localhost:{server.port+1}", connect_timeout=4) as client:
			with pytest.raises(OpsiConnectionError):
				client.connect()

		with ServiceClient(f"https://localhost:{server.port}", connect_timeout=4, verify="accept_all") as client:
			client.connect()
			start = time.time()
			with pytest.raises(OpsiTimeoutError):
				client.get("/", read_timeout=2)
			assert round(time.time() - start) == 2

			assert client.get("/", read_timeout=4)[0] == 200


def test_messagebus_ping() -> None:
	pong_count = 0

	def _on_pong(messagebus: Messagebus, app: WebSocketApp, message: bytes) -> None:  # pylint: disable=unused-argument
		nonlocal pong_count
		pong_count += 1

	with (
		mock.patch("opsicommon.client.opsiservice.Messagebus._ping_interval", 1),
		mock.patch("opsicommon.client.opsiservice.Messagebus._on_pong", _on_pong),
	):
		with http_test_server(generate_cert=True, response_headers={"server": "opsiconfd 4.2.1.0 (uvicorn)"}) as server:
			with ServiceClient(f"https://localhost:{server.port}", verify="accept_all") as client:
				client.connect_messagebus()
				time.sleep(5)
				assert pong_count >= 3


def test_messagebus_jsonrpc() -> None:
	delay = 0.0

	def ws_message_callback(handler: HTTPTestServerRequestHandler, message: bytes) -> None:
		msg = JSONRPCRequestMessage.from_msgpack(message)
		time.sleep(delay)
		res = JSONRPCResponseMessage(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
			sender="service:worker:test:1", channel="host:test-client.uib.local", rpc_id=msg.rpc_id, result=f"RESULT {msg.rpc_id}"
		)
		handler.ws_send_message(res.to_msgpack())

	with http_test_server(
		generate_cert=True, ws_message_callback=ws_message_callback, response_headers={"server": "opsiconfd 4.2.1.0 (uvicorn)"}
	) as server:
		with ServiceClient(f"https://localhost:{server.port}", verify="accept_all") as client:
			messagebus = client.connect_messagebus()
			for _ in range(10):
				res = messagebus.jsonrpc("test", wait=5)  # pylint: disable=loop-invariant-statement
				assert res["id"]
				assert res["result"] == f"RESULT {res['id']}"
				assert res["error"] is None

			delay = 3.0
			with pytest.raises(OpsiTimeoutError):
				res = messagebus.jsonrpc("test", wait=1)


def test_messagebus_multi_thread() -> None:
	class ReqThread(Thread):
		def __init__(self, client: ServiceClient) -> None:
			super().__init__()
			self.daemon = True
			self.client = client
			self.response = None

		def run(self) -> None:
			self.response = client.connect_messagebus().jsonrpc("test", wait=3)

	def ws_message_callback(handler: HTTPTestServerRequestHandler, message: bytes) -> None:
		msg = JSONRPCRequestMessage.from_msgpack(message)
		res = JSONRPCResponseMessage(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
			sender="service:worker:test:1", channel="host:test-client.uib.local", rpc_id=msg.rpc_id, result=f"RESULT {msg.rpc_id}"
		)
		handler.ws_send_message(res.to_msgpack())

	with http_test_server(
		generate_cert=True, ws_message_callback=ws_message_callback, response_headers={"server": "opsiconfd 4.2.1.0 (uvicorn)"}
	) as server:
		with ServiceClient(f"https://localhost:{server.port}", verify="accept_all") as client:
			threads = [ReqThread(client) for _ in range(50)]
			for thread in threads:
				thread.start()
			for thread in threads:
				thread.join(3)
			for thread in threads:
				res = thread.response
				assert res
				assert res["id"]
				assert res["result"] == f"RESULT {res['id']}"
				assert res["error"] is None