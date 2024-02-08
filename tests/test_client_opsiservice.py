# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""
# pylint: disable=too-many-lines

from __future__ import annotations

import asyncio
import base64
import json
import platform
import re
import time
import traceback
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from socket import AF_INET
from ssl import SSLContext
from threading import Thread
from typing import Any, Generator, Iterable
from unittest import mock
from urllib.parse import unquote
from warnings import catch_warnings, simplefilter

import lz4.frame  # type: ignore[import,no-redef]

with catch_warnings():
	simplefilter("ignore")
	import pproxy  # type: ignore[import]
import psutil
import pytest
from cryptography import x509

from opsicommon import __version__
from opsicommon.client.opsiservice import (
	MIN_VERSION_GZIP,
	MIN_VERSION_LZ4,
	MIN_VERSION_MESSAGEBUS,
	MIN_VERSION_MSGPACK,
	MIN_VERSION_SESSION_API,
	UIB_OPSI_CA,
	BackendManager,
	Messagebus,
	MessagebusListener,
	OpsiCaState,
	OpsiServiceAuthenticationError,
	OpsiServiceConnectionError,
	OpsiServiceError,
	OpsiServicePermissionError,
	OpsiServiceTimeoutError,
	OpsiServiceUnavailableError,
	OpsiServiceVerificationError,
	RequestsResponse,
	Response,
	ServiceClient,
	ServiceConnectionListener,
	ServiceVerificationFlags,
	WebSocketApp,
	get_service_client,
)
from opsicommon.exceptions import (
	BackendAuthenticationError,
	BackendPermissionDeniedError,
	OpsiRpcError,
)
from opsicommon.messagebus import (
	ChannelSubscriptionEventMessage,
	FileUploadResultMessage,
	JSONRPCRequestMessage,
	JSONRPCResponseMessage,
	Message,
	MessageType,
	timestamp,
)
from opsicommon.objects import OpsiClient
from opsicommon.ssl import as_pem, create_ca, create_server_cert
from opsicommon.system.info import is_macos, is_windows
from opsicommon.testing.helpers import (  # type: ignore[import]
	HTTPTestServerRequestHandler,
	environment,
	http_test_server,
	opsi_config,
)

from .test_utils import log_level_stderr


class MyConnectionListener(ServiceConnectionListener):
	def __init__(self) -> None:
		super().__init__()
		self.events: list[tuple[str, ServiceClient, Exception | None]] = []

	def connection_open(self, service_client: ServiceClient) -> None:
		self.events.append(("open", service_client, None))

	def connection_established(self, service_client: "ServiceClient") -> None:
		self.events.append(("established", service_client, None))

	def connection_failed(self, service_client: ServiceClient, exception: Exception) -> None:
		self.events.append(("failed", service_client, exception))

	def connection_closed(self, service_client: ServiceClient) -> None:
		self.events.append(("closed", service_client, None))


def test_arguments() -> None:
	# address
	assert ServiceClient("localhost").base_url == "https://localhost:4447"
	assert ServiceClient("https://localhost").base_url == "https://localhost:4447"
	assert ServiceClient("https://localhost:4448").base_url == "https://localhost:4448"
	assert ServiceClient("https://localhost:4448/xy").base_url == "https://localhost:4448"
	assert ServiceClient("https://localhost:4448/xy")._jsonrpc_path == "/xy"
	assert ServiceClient("localhost:4448").base_url == "https://localhost:4448"
	assert ServiceClient("1.2.3.4").base_url == "https://1.2.3.4:4447"
	assert ServiceClient("::1").base_url == "https://[::1]:4447"
	assert ServiceClient("2001:0db8:85a3:0000:0000:8a2e:0370:7334").base_url == "https://[2001:db8:85a3::8a2e:370:7334]:4447"
	assert (
		ServiceClient("[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:4448").base_url == "https://[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:4448"
	)
	with pytest.raises(ValueError):
		ServiceClient("http://localhost:4448")

	assert ServiceClient()
	with pytest.raises(ValueError):
		assert ServiceClient().base_url

	# username / password
	client = ServiceClient("localhost")
	assert client._username is None
	assert client._password is None

	client = ServiceClient("localhost", username="", password="")
	assert client._username == ""
	assert client._password == ""

	client = ServiceClient("localhost", username="user", password="pass")
	assert client._username == "user"
	assert client._password == "pass"

	client = ServiceClient("https://usr:pas@localhost")
	assert client._username == "usr"
	assert client._password == "pas"

	with pytest.raises(ValueError, match="Different usernames supplied"):
		client = ServiceClient("https://usr:pas@localhost", username="user", password="pass")

	with pytest.raises(ValueError, match="Different usernames supplied"):
		client = ServiceClient("https://usr:pas@localhost", username="user")

	with pytest.raises(ValueError, match="Different passwords supplied"):
		client = ServiceClient("https://usr:pas@localhost", username="usr", password="pass")

	with pytest.raises(ValueError, match="Different passwords supplied"):
		client = ServiceClient("https://usr:pas@localhost", password="pass")

	client = ServiceClient("https://:pass@localhost")
	assert client._username == ""
	assert client._password == "pass"

	# verify / ca_cert_file
	assert ServiceClient("::1")._ca_cert_file is None
	assert ServiceClient("::1", ca_cert_file="cacert.pem")._ca_cert_file == Path("cacert.pem")
	assert ServiceClient("::1", ca_cert_file=Path("/x/cacert.pem"))._ca_cert_file == Path("/x/cacert.pem")

	for server_role in ("configserver", ""):
		with opsi_config({"host.server-role": server_role}):
			for mode in ServiceVerificationFlags:
				expect = mode
				if mode == ServiceVerificationFlags.OPSI_CA and server_role == "configserver":
					expect = ServiceVerificationFlags.STRICT_CHECK

				assert expect in ServiceClient("::1", ca_cert_file="ca.pem", verify=mode)._verify
				assert expect in ServiceClient("::1", ca_cert_file="ca.pem", verify=mode.value)._verify
				assert expect in ServiceClient("::1", ca_cert_file="ca.pem", verify=[mode])._verify
				assert expect in ServiceClient("::1", ca_cert_file="ca.pem", verify=[mode.value])._verify

	assert ServiceClient("::1", ca_cert_file="ca.pem", verify=ServiceVerificationFlags.STRICT_CHECK)._verify == [
		ServiceVerificationFlags.STRICT_CHECK
	]

	for mode in ServiceVerificationFlags.OPSI_CA, ServiceVerificationFlags.UIB_OPSI_CA:
		with pytest.raises(ValueError, match="ca_cert_file required"):
			ServiceClient("::1", verify=mode)
	with pytest.raises(ValueError, match="bad_mode"):
		ServiceClient("::1", verify="bad_mode")

	# session_cookie
	assert ServiceClient("::1", session_cookie="cookie=val")._session_cookie == "cookie=val"
	with pytest.raises(ValueError):
		assert ServiceClient("::1", session_cookie="cookie")

	# session_lifetime
	assert ServiceClient("::1", session_lifetime=10)._session_lifetime == 10
	assert ServiceClient("::1", session_lifetime=-3)._session_lifetime == 1

	# proxy_url
	assert ServiceClient("::1", proxy_url="system")._proxy_url == "system"
	assert ServiceClient("::1", proxy_url=None)._proxy_url is None  # type: ignore[arg-type]
	assert ServiceClient("::1", proxy_url="none")._proxy_url is None  # type: ignore[arg-type]
	assert ServiceClient("::1", proxy_url="https://proxy:1234")._proxy_url == "https://proxy:1234"

	# user_agent
	assert ServiceClient("::1")._user_agent == f"opsi-service-client/{__version__}"
	assert ServiceClient("::1", user_agent=None)._user_agent == f"opsi-service-client/{__version__}"
	assert ServiceClient("::1", user_agent="my app")._user_agent == "my app"

	# connect_timeout
	assert ServiceClient("::1", connect_timeout=123)._connect_timeout == 123.0
	assert ServiceClient("::1", connect_timeout=1.2)._connect_timeout == 1.2
	assert ServiceClient("::1", connect_timeout=-1)._connect_timeout == 0.0


def test_set_addresses() -> None:
	service_client = ServiceClient(["https://opsiserver:4447", "https://opsiserver2:4447"])
	assert service_client.base_url == "https://opsiserver:4447"

	service_client.set_addresses("localhost")
	assert service_client.base_url == "https://localhost:4447"

	service_client = ServiceClient()
	with pytest.raises(ValueError):
		assert ServiceClient().base_url
	service_client.set_addresses("localhost")
	assert service_client.base_url == "https://localhost:4447"


def test_read_write_ca_cert_file(tmpdir: Path) -> None:
	ca_cert_file = tmpdir / "ca_certs.pem"
	ca_cert1, _ = create_ca(subject={"CN": "python-opsi-common test CA 1"}, valid_days=30)
	ca_cert2, _ = create_ca(subject={"CN": "python-opsi-common test CA 2"}, valid_days=30)
	ca_cert3, _ = create_ca(subject={"CN": "python-opsi-common test CA 3"}, valid_days=30)
	service_client = ServiceClient("localhost", ca_cert_file=ca_cert_file)

	pem = as_pem(ca_cert1) + as_pem(ca_cert2) + as_pem(ca_cert3)
	ca_cert_file.write_text(pem, encoding="utf-8")
	certs = service_client.read_ca_cert_file()
	assert len(certs) == 3
	assert certs[0].subject == ca_cert1.subject
	assert certs[1].subject == ca_cert2.subject
	assert certs[2].subject == ca_cert3.subject

	pem = pem.replace("-\n-", "--")
	ca_cert_file.write_text(pem, encoding="utf-8")
	certs = service_client.read_ca_cert_file()
	assert len(certs) == 3
	assert certs[0].subject == ca_cert1.subject
	assert certs[1].subject == ca_cert2.subject
	assert certs[2].subject == ca_cert3.subject

	pem = "\r\n\r\n\r\ngarbage" + as_pem(ca_cert1) + "\ngarbage\r\n\n" + as_pem(ca_cert2) + "garbage" + as_pem(ca_cert3) + "garbage\n\n\r\n"
	ca_cert_file.write_text(pem, encoding="utf-8")
	certs = service_client.read_ca_cert_file()
	assert len(certs) == 3
	assert certs[0].subject == ca_cert1.subject
	assert certs[1].subject == ca_cert2.subject
	assert certs[2].subject == ca_cert3.subject

	ca_cert_file = tmpdir / "new" / "dir" / "ca_certs.pem"
	service_client = ServiceClient("localhost", ca_cert_file=ca_cert_file)
	service_client.write_ca_cert_file(certs)
	certs = service_client.read_ca_cert_file()
	assert len(certs) == 3
	assert certs[0].subject == ca_cert1.subject
	assert certs[1].subject == ca_cert2.subject
	assert certs[2].subject == ca_cert3.subject

	service_client.write_ca_cert_file(certs + certs + certs)
	certs = service_client.read_ca_cert_file()
	assert len(certs) == 3
	assert certs[0].subject == ca_cert1.subject
	assert certs[1].subject == ca_cert2.subject
	assert certs[2].subject == ca_cert3.subject

	class CAWriteThread(Thread):
		def __init__(self, client: ServiceClient, certs: list[x509.Certificate]) -> None:
			super().__init__(daemon=True)
			self.client = client
			self.certs = certs
			self.err: Exception | None = None

		def run(self) -> None:
			try:
				self.client.write_ca_cert_file(self.certs)
			except Exception as err:
				self.err = err

	class CAReadThread(Thread):
		def __init__(self, client: ServiceClient) -> None:
			super().__init__(daemon=True)
			self.client = client
			self.certs: list[x509.Certificate] = []
			self.err: Exception | None = None

		def run(self) -> None:
			try:
				self.certs = self.client.read_ca_cert_file()
			except Exception as err:
				self.err = err

	write_threads = [CAWriteThread(service_client, certs) for _ in range(50)]
	read_threads = [CAReadThread(service_client) for _ in range(50)]
	for idx in range(len(write_threads)):
		write_threads[idx].start()
		read_threads[idx].start()

	for idx in range(len(write_threads)):
		write_threads[idx].join()
		read_threads[idx].join()
		if write_threads[idx].err:
			print(write_threads[idx].err)
			traceback.print_tb(write_threads[idx].err.__traceback__)  # type: ignore[union-attr]
		assert not write_threads[idx].err
		if write_threads[idx].err:
			print(write_threads[idx].err)
			traceback.print_tb(write_threads[idx].err.__traceback__)  # type: ignore[union-attr]
		assert not read_threads[idx].err

	certs = service_client.read_ca_cert_file()
	assert len(certs) == 3
	assert certs[0].subject == ca_cert1.subject
	assert certs[1].subject == ca_cert2.subject
	assert certs[2].subject == ca_cert3.subject

	uib_opsi_ca = x509.load_pem_x509_certificate(UIB_OPSI_CA.encode("utf-8"))
	service_client.add_uib_opsi_ca_to_cert_file()
	certs = service_client.read_ca_cert_file()
	assert len(certs) == 4
	assert certs[0].subject == ca_cert1.subject
	assert certs[1].subject == ca_cert2.subject
	assert certs[2].subject == ca_cert3.subject
	assert certs[3].subject == uib_opsi_ca.subject

	service_client.add_uib_opsi_ca_to_cert_file()
	service_client.add_uib_opsi_ca_to_cert_file()
	service_client.add_uib_opsi_ca_to_cert_file()
	certs = service_client.read_ca_cert_file()
	assert len(certs) == 4
	assert certs[0].subject == ca_cert1.subject
	assert certs[1].subject == ca_cert2.subject
	assert certs[2].subject == ca_cert3.subject
	assert certs[3].subject == uib_opsi_ca.subject

	pem = "\r\n\r\n\r\ngarbage" + as_pem(ca_cert2) + "\ngarbage\r\n\n" + as_pem(ca_cert3) + "garbage" + as_pem(ca_cert1) + "garbage\n\n\r\n"
	ca_cert_file.write_text(pem, encoding="utf-8")
	service_client.add_uib_opsi_ca_to_cert_file()
	certs = service_client.read_ca_cert_file()
	assert len(certs) == 4


def test_get_opsi_ca_state(tmpdir: Path) -> None:
	ca_cert_file = tmpdir / "ca_certs.pem"
	service_client = ServiceClient("localhost", ca_cert_file=ca_cert_file)
	assert service_client.get_opsi_ca_state() == OpsiCaState.UNAVAILABLE

	service_client.add_uib_opsi_ca_to_cert_file()
	certs = service_client.read_ca_cert_file()
	assert len(certs) == 1
	assert service_client.get_opsi_ca_state() == OpsiCaState.UNAVAILABLE

	ca_cert, _ = create_ca(subject={"CN": "python-opsi-common test CA 1"}, valid_days=30)
	certs.append(ca_cert)
	service_client.write_ca_cert_file(certs)
	assert service_client.get_opsi_ca_state() == OpsiCaState.AVAILABLE

	class MockCertificateBuilder(x509.CertificateBuilder):
		def __init__(self, **kwargs: Any) -> None:
			kwargs["not_valid_before"] = datetime.now(tz=timezone.utc) - timedelta(days=200)
			kwargs["not_valid_after"] = datetime.now(tz=timezone.utc) - timedelta(days=100)
			print("MockCertificateBuilder", kwargs)
			super().__init__(**kwargs)

	with mock.patch("opsicommon.ssl.common.CertificateBuilder", MockCertificateBuilder):
		ca_cert, _ca_key = create_ca(subject={"CN": "python-opsi-common test CA 1"}, valid_days=100)
		assert ca_cert.not_valid_before_utc < datetime.now(tz=timezone.utc)
		assert ca_cert.not_valid_after_utc < datetime.now(tz=timezone.utc)
		certs = [ca_cert]
	service_client.write_ca_cert_file(certs)
	service_client.add_uib_opsi_ca_to_cert_file()
	assert service_client.get_opsi_ca_state() == OpsiCaState.EXPIRED


def test_verify(tmpdir: Path) -> None:
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

	print(f"UTC: {datetime.now(tz=timezone.utc)}")
	print(f"CA cert: {ca_cert.not_valid_before_utc} - {ca_cert.not_valid_after_utc}")
	print(f"server cert: {server_cert.not_valid_before_utc} - {server_cert.not_valid_after_utc}")

	with (
		opsi_config({"host.server-role": ""}),
		http_test_server(
			server_key=server_key_file,
			server_cert=server_cert_file,
			response_body=as_pem(ca_cert).encode("utf-8"),
			response_headers={"server": "opsiconfd 4.2.1.1 (uvicorn)"},
		) as server,
	):
		# strict_check
		assert not opsi_ca_file_on_client.exists()
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="strict_check") as client:
			with pytest.raises(OpsiServiceVerificationError):
				client.connect()
			with pytest.raises(OpsiServiceVerificationError):
				client.connect_messagebus()

			assert client._request(method="HEAD", path="/", verify=False).status_code == 200

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

		assert not opsi_ca_file_on_client.exists()

		# accept_all | opsi_ca
		with ServiceClient(
			f"https://127.0.0.1:{server.port}", ca_cert_file=opsi_ca_file_on_client, verify=("accept_all", "opsi_ca")
		) as client:
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

		# uib_opsi_ca (means uib_opsi_ca + opsi_ca)
		with ServiceClient(f"https://127.0.0.1:{server.port}", ca_cert_file=opsi_ca_file_on_client, verify="uib_opsi_ca") as client:
			client.connect()
			assert opsi_ca_file_on_client.read_text(encoding="utf-8") == as_pem(ca_cert) + UIB_OPSI_CA + "\n"

		# Empty client ca file => accept once
		opsi_ca_file_on_client.write_text("", encoding="utf-8")
		with ServiceClient(f"https://127.0.0.1:{server.port}", ca_cert_file=opsi_ca_file_on_client, verify="uib_opsi_ca") as client:
			client.connect()
			assert opsi_ca_file_on_client.read_text(encoding="utf-8") == as_pem(ca_cert) + UIB_OPSI_CA + "\n"

		# Only uib opsi ca in ca file => accept once
		opsi_ca_file_on_client.write_text(UIB_OPSI_CA, encoding="utf-8")
		with ServiceClient(f"https://127.0.0.1:{server.port}", ca_cert_file=opsi_ca_file_on_client, verify="uib_opsi_ca") as client:
			client.connect()
			assert opsi_ca_file_on_client.read_text(encoding="utf-8") == as_pem(ca_cert) + UIB_OPSI_CA + "\n"

		# expired
		orig_ca_cert_as_pem = as_pem(ca_cert)

		class MockCertificateBuilder(x509.CertificateBuilder):
			def __init__(self, **kwargs: Any) -> None:
				kwargs["not_valid_before"] = datetime.now(tz=timezone.utc) - timedelta(days=200)
				kwargs["not_valid_after"] = datetime.now(tz=timezone.utc) - timedelta(days=1)
				super().__init__(**kwargs)

		with mock.patch("opsicommon.ssl.common.CertificateBuilder", MockCertificateBuilder):
			ca_cert_expired, _ = create_ca(subject={"CN": "python-opsi-common test ca"}, valid_days=3, key=ca_key)
			assert ca_cert_expired.not_valid_before_utc < datetime.now(tz=timezone.utc)
			assert ca_cert_expired.not_valid_after_utc < datetime.now(tz=timezone.utc)
			opsi_ca_file_on_client.write_text(as_pem(ca_cert_expired), encoding="utf-8")

		with ServiceClient(f"https://127.0.0.1:{server.port}", ca_cert_file=opsi_ca_file_on_client, verify="opsi_ca") as client:
			with pytest.raises(OpsiServiceVerificationError, match="certificate has expired"):
				client.connect()

		with ServiceClient(
			f"https://127.0.0.1:{server.port}", ca_cert_file=opsi_ca_file_on_client, verify=["opsi_ca", "replace_expired_ca"]
		) as client:
			client.connect()
			assert opsi_ca_file_on_client.read_text(encoding="utf-8") == orig_ca_cert_as_pem


def test_cookie_handling(tmp_path: Path) -> None:
	session_cookie = "COOKIE-NAME=abc"
	with http_test_server(generate_cert=True, response_headers={"Set-Cookie": f"{session_cookie}; SameSite=Lax"}) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all") as client:
			client.get("/")
			assert client.session_cookie == session_cookie

	log_file = tmp_path / "request.log"
	session_cookie = "COOKIE-NAME=üöä"
	with http_test_server(generate_cert=True, response_headers={"server": "opsiconfd 4.2.1.0 (uvicorn)"}, log_file=log_file) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all", session_cookie=session_cookie) as client:
			client.get("/")
			assert client.session_cookie == session_cookie
			client.connect_messagebus()

			lines = log_file.read_text(encoding="utf-8").strip().split("\n")

			req1 = json.loads(lines[0])
			assert req1["method"] == "HEAD"
			assert unquote(req1["headers"].get("Cookie")) == session_cookie

			req2 = json.loads(lines[1])
			assert req2["method"] == "POST"
			assert unquote(req2["headers"].get("Cookie")) == session_cookie

			req3 = json.loads(lines[2])
			assert req3["method"] == "GET"
			assert unquote(req3["headers"].get("Cookie")) == session_cookie

			req4 = json.loads(lines[3])
			assert req4["headers"]["Upgrade"] == "websocket"
			assert unquote(req4["headers"].get("Cookie")) == session_cookie


def get_local_ipv4_address() -> str | None:
	for _interface, snics in psutil.net_if_addrs().items():
		for snic in snics:
			if snic.family != AF_INET or not snic.netmask or snic.address == "127.0.0.1":
				continue
			return snic.address
	raise RuntimeError("No local IPv4 address found")


class HTTPProxy(Thread):
	REQUEST_RE = re.compile(r"^http\s+([\d\.a-f:]+):(\d+) -> ([\d\.a-f:]+):(\d+)$")

	def __init__(self, port: int):
		super().__init__()
		self._port = port
		self._loop = asyncio.get_event_loop()
		self._should_stop = False
		self._requests: list[dict[str, str | int]] = []

	def get_and_clear_requests(self) -> list[dict[str, str | int]]:
		requests = self._requests.copy()
		self._requests = []
		return requests

	def verbose(self, msg: str) -> None:
		# http 127.0.0.1:54464 -> 172.24.0.3:55987
		# http ::1:58297 -> 192.168.109.63:58037
		print("Proxy request:", msg)
		match = self.REQUEST_RE.search(msg)
		if match:
			self._requests.append(
				{
					"client_address": match.group(1),
					"client_port": int(match.group(2)),
					"server_address": match.group(3),
					"server_port": int(match.group(4)),
				}
			)

	async def main(self) -> None:
		args: dict[str, Any] = {"rserver": [], "verbose": self.verbose}
		proxy_server = pproxy.Server(f"http://:{self._port}")
		server = proxy_server.start_server(args)
		server_task = asyncio.create_task(server)
		while not self._should_stop:
			await asyncio.sleep(0.3)
		server_task.cancel()
		await self._loop.shutdown_asyncgens()

	def run(self) -> None:
		self._loop.run_until_complete(self.main())

	def stop(self) -> None:
		self._should_stop = True


@contextmanager
def run_proxy(port: int = 8080) -> Generator[HTTPProxy, None, None]:
	proxy = HTTPProxy(port)
	proxy.daemon = True
	proxy.start()
	time.sleep(2)
	yield proxy
	proxy.stop()
	proxy.join(2)


def test_proxy(tmp_path: Path) -> None:
	local_ip = get_local_ipv4_address()
	server_log_file = tmp_path / "server-request.log"
	no_proxy_addresses = ["::1", "127.0.0.1", "ip6-localhost", "localhost"]

	def get_server_requests() -> list[dict[str, Any]]:
		if not server_log_file.exists():
			return []
		res = [json.loads(line) for line in server_log_file.read_text(encoding="utf-8").strip().split("\n")]
		server_log_file.unlink()
		return res

	proxy_port = 18181
	with run_proxy(proxy_port) as proxy_server, http_test_server(
		generate_cert=True, log_file=server_log_file, response_headers={"server": "opsiconfd 4.3.1.0 (uvicorn)"}
	) as server, mock.patch("opsicommon.client.opsiservice.ServiceClient.no_proxy_addresses", no_proxy_addresses):
		# Proxy must not be used (no_proxy_addresses)
		with mock.patch(
			"opsicommon.client.opsiservice.ServiceClient.no_proxy_addresses", ["::1", "127.0.0.1", "ip6-localhost", "localhost", local_ip]
		):
			with ServiceClient(
				f"https://{local_ip}:{server.port}", proxy_url=f"http://localhost:{server.port+1}", verify="accept_all", connect_timeout=2
			) as client:
				client.connect()
				client.connect_messagebus()

			requests = get_server_requests()
			assert requests
			assert not proxy_server.get_and_clear_requests()

		# Use no proxy, proxy from env must not be used
		proxy_env = {"http_proxy": "http://should-not-be-used", "https_proxy": "http://should-not-be-used"}
		with environment(proxy_env):
			with ServiceClient(f"https://{local_ip}:{server.port}", proxy_url=None, verify="accept_all", connect_timeout=2) as client:
				assert client.no_proxy_addresses == no_proxy_addresses
				client.connect()
				client.connect_messagebus()

			requests = get_server_requests()
			assert requests
			assert not proxy_server.get_and_clear_requests()

		# Use explicit proxy
		proxy_env = {"http_proxy": "http://should-not-be-used", "https_proxy": "https://should-not-be-used", "no_proxy": ""}
		with environment(proxy_env):
			with ServiceClient(
				f"https://{local_ip}:{server.port}", proxy_url=f"http://localhost:{proxy_port}", verify="accept_all", connect_timeout=2
			) as client:
				client.connect()
				client.messagebus.connect()

			requests = get_server_requests()
			assert requests
			assert len(proxy_server.get_and_clear_requests()) == len(requests)

			assert requests[0]["method"] == "HEAD"
			assert requests[1]["method"] == "POST"
			assert requests[2]["headers"]["Upgrade"] == "websocket"

		# Use system proxy
		proxy_env = {
			"http_proxy": f"http://localhost:{proxy_port}",
			"https_proxy": f"http://localhost:{proxy_port}",
			"no_proxy": "company.net",
		}
		with environment(proxy_env):
			with ServiceClient(f"https://{local_ip}:{server.port}", proxy_url="system", verify="accept_all", connect_timeout=2) as client:
				client.connect()
				client.connect_messagebus()

			requests = get_server_requests()
			assert requests
			assert len(proxy_server.get_and_clear_requests()) == len(requests)

			assert requests[0]["method"] == "HEAD"
			assert requests[0]["path"] == "/rpc"

			assert requests[1]["method"] == "POST"

			assert requests[2]["method"] == "GET"
			assert requests[2]["path"] == "/messagebus/v1?compression=lz4"
			assert requests[2]["headers"]["Upgrade"] == "websocket"

		# Test proxy address can't be resolved
		proxy_env = {"http_proxy": "http://will-not-resolve:991", "https_proxy": "http://will-not-resolve:991", "no_proxy": ""}
		with environment(proxy_env):
			with ServiceClient(f"https://{local_ip}:{server.port}", proxy_url="system", verify="accept_all", connect_timeout=2) as client:
				with pytest.raises(OpsiServiceConnectionError, match=".*Failed to resolve 'will-not-resolve'.*"):
					client.connect()

				match = ".*Name or service not known.*"
				if is_macos():
					match = ".*nodename nor servname provided, or not known.*"
				elif is_windows():
					match = ".*getaddrinfo failed.*"
				with pytest.raises(OpsiServiceConnectionError, match=match):
					client.messagebus.connect()

		# Bug in https://github.com/websocket-client (uses http_proxy for ssl if https_proxy is not set)
		# proxy_env = {"http_proxy": "http://will-not-resolve:991", "https_proxy": "", "no_proxy": ""}
		# with environment(proxy_env):
		# 	with ServiceClient(f"https://{local_ip}:{server.port}", proxy_url="system", verify="accept_all", connect_timeout=2) as client:
		# 		# with pytest.raises(OpsiServiceConnectionError, match=".*Failed to resolve 'will-not-resolve'.*"):
		# 		client.connect()
		# 		# with pytest.raises(OpsiServiceConnectionError, match=".*Name or service not known.*"):
		# 		client.messagebus.connect()


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
def test_server_name_handling(
	tmp_path: Path,
	server_name: str,
	expected_version: tuple,
	expected_content_type: str,
	expected_content_encoding: str | None,
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

		# get interface
		assert reqs[1]["method"] == "POST"

		# JSONRPC request
		assert reqs[2]["method"] == "POST"
		assert reqs[2]["path"] == "/rpc"
		assert reqs[2]["headers"].get("Content-Type") == expected_content_type
		assert reqs[2]["headers"].get("Content-Encoding") == expected_content_encoding

		# Close session request
		assert reqs[3]["method"] == "POST"
		if server_version and server_version >= MIN_VERSION_SESSION_API:
			assert reqs[3]["path"] == "/session/logout"
		else:
			assert reqs[3]["path"] == "/rpc"
			assert reqs[3]["request"]["method"] == "backend_exit"

		# Clear log
		log_file.write_bytes(b"")


def test_connect_disconnect() -> None:
	with log_level_stderr(9), http_test_server(generate_cert=True, response_headers={"server": "opsiconfd 4.1.0.1 (uvicorn)"}) as server:
		listener = MyConnectionListener()
		with ServiceClient() as client:
			with pytest.raises(OpsiServiceConnectionError, match="Service address undefined"):
				client.connect()
			with pytest.raises(OpsiServiceConnectionError, match="Service address undefined"):
				client.connect_messagebus()
			with pytest.raises(OpsiServiceConnectionError, match="Service address undefined"):
				client.messagebus.connect()

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
		client = ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all", connect_timeout=15.0)
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

		print("_connected", client.messagebus._connected)
		print("_should_be_connected", client.messagebus._should_be_connected)
		print("_connected_result", client.messagebus._connected_result.is_set())
		print("is_alive", client.messagebus.is_alive())

		client.connect_messagebus()
		assert client.messagebus_connected is True

		client.disconnect()
		assert client.messagebus_connected is False
		assert client.connected is False


def test_requests() -> None:
	with http_test_server(generate_cert=True, response_headers={"server": "opsiconfd 4.3.0.0 (uvicorn)"}) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all") as client:
			client.connect()

			server.response_status = (201, "reason")
			server.response_body = b"content"
			response = client.get("/")

			status_code, reason, headers, content = response
			assert status_code == server.response_status[0]
			assert reason == server.response_status[1]
			assert headers["server"] == server.response_headers["server"]  # type: ignore
			assert content == server.response_body

			assert response[0] == server.response_status[0]
			assert response[1] == server.response_status[1]
			assert response[2]["server"] == server.response_headers["server"]  # type: ignore
			assert response[3] == server.response_body

			with pytest.raises(IndexError):
				response[4]

			assert response.status_code == server.response_status[0]
			assert response.reason == server.response_status[1]
			assert response.headers["server"] == server.response_headers["server"]
			assert response.content == server.response_body


def test_raw_requests() -> None:
	with http_test_server(generate_cert=True, response_headers={"server": "opsiconfd 4.3.0.0 (uvicorn)"}) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all") as client:
			client.connect()

			server.response_status = (201, "reason")
			server.response_body = b"content"
			response = client.get("/")
			assert isinstance(response, Response)
			raw_response = client.get("/", raw_response=True)
			assert isinstance(raw_response, RequestsResponse)
			raw_response.raise_for_status()


def test_request_exceptions() -> None:
	with http_test_server(generate_cert=True, response_headers={"server": "opsiconfd 4.3.0.0 (uvicorn)"}) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all") as client:
			server.response_status = (200, "OK")
			client.connect()
			assert client.get("/")[0] == 200

			server.response_status = (500, "Internal Server Error")
			server.response_body = b"content"
			with pytest.raises(OpsiServiceError) as exc_info:
				client.get("/")
			assert exc_info.value.content == "content"
			assert exc_info.value.status_code == 500
			assert client.get("/", allow_status_codes=[500])[0] == 500

			server.response_status = (401, "Unauthorized")
			with pytest.raises(OpsiServiceAuthenticationError) as exc_info:
				client.get("/")
			assert exc_info.value.content == "content"
			assert exc_info.value.status_code == 401

			server.response_status = (403, "Forbidden")
			with pytest.raises(OpsiServicePermissionError) as exc_info:
				client.get("/")
			assert exc_info.value.content == "content"
			assert exc_info.value.status_code == 403

			server.response_status = (200, "OK")
			with pytest.raises(OpsiServiceConnectionError) as exc_info:
				client.get("/", read_timeout="FAIL")  # type: ignore[arg-type,call-overload]

			now = time.time()
			server.response_status = (503, "Unavail")
			server.response_headers["Retry-After"] = "5"
			with pytest.raises(OpsiServiceUnavailableError) as exc_info:
				client.get("/")
			assert exc_info.value.content == "content"
			assert exc_info.value.status_code == 503
			assert exc_info.value.until or 0 <= now + 7
			assert exc_info.value.until or 0 >= now + 3

			server.response_status = (200, "OK")
			del server.response_headers["Retry-After"]
			# OpsiServiceUnavailableError must persist until err.until reached
			with pytest.raises(OpsiServiceUnavailableError) as exc_info:
				client.get("/")

			time.sleep(6)
			client.get("/")

			server.response_status = (503, "Unavail")
			server.response_headers["Retry-After"] = "invalid"
			now = time.time()
			with pytest.raises(OpsiServiceUnavailableError) as exc_info:
				client.get("/")
			# 60 = default value
			assert int((exc_info.value.until or -999) - now) in (59, 60)

			client._service_unavailable = None
			server.response_headers["Retry-After"] = "-1"
			now = time.time()
			with pytest.raises(OpsiServiceUnavailableError) as exc_info:
				client.get("/")
			# 1 = min
			assert int((exc_info.value.until or -999) - now) in (0, 1)

			client._service_unavailable = None
			server.response_headers["Retry-After"] = "999999"
			now = time.time()
			with pytest.raises(OpsiServiceUnavailableError) as exc_info:
				client.get("/")
			# 7200 = max
			assert int((exc_info.value.until or -999) - now) in (7199, 7200)


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
		messages = []

		def message_received(self, message: Message) -> None:
			self.messages.append(message)

	rpc_id = 0

	def ws_connect_callback(handler: HTTPTestServerRequestHandler) -> None:
		nonlocal rpc_id
		if rpc_id == 0:
			smsg = ChannelSubscriptionEventMessage(
				sender="service:worker:test:1", channel="host:test-client.uib.local", subscribed_channels=["chan1", "chan2", "chan3"]
			)
			handler.ws_send_message(lz4.frame.compress(smsg.to_msgpack(), compression_level=0, block_linked=True))

		for _ in range(3):
			rpc_id += 1
			msg = JSONRPCResponseMessage(
				sender="service:worker:test:1", channel="host:test-client.uib.local", rpc_id=str(rpc_id), result="RESULT"
			)
			handler.ws_send_message(lz4.frame.compress(msg.to_msgpack(), compression_level=0, block_linked=True))

	with http_test_server(
		generate_cert=True, ws_connect_callback=ws_connect_callback, response_headers={"server": "opsiconfd 4.2.1.0 (uvicorn)"}
	) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all") as client:
			client.messagebus.reconnect_wait_min = 5
			client.messagebus.reconnect_wait_max = 5
			listener = MBListener()

			with listener.register(client.messagebus):
				client.connect_messagebus()
				time.sleep(3)
				assert client.messagebus._subscribed_channels == ["chan1", "chan2", "chan3"]

				rpc_id = 10
				server.restart(new_cert=True)
				time.sleep(10)
				assert client.messagebus._subscribed_channels == ["chan1", "chan2", "chan3"]

			print("messages", listener.messages)
			expected_messages = 6 + 1  # 6 * JSONRPCResponseMessage + 1 * ChannelSubscriptionEventMessage
			assert len(listener.messages) == expected_messages
			rpc_ids = [int(m.rpc_id) for m in listener.messages if hasattr(m, "rpc_id")]  # type: ignore[attr-defined]
			assert all((rpc_id in rpc_ids for rpc_id in [1, 2, 3, 11, 12, 13]))


def test_messagebus_reconnect_exception() -> None:
	class MBListener(MessagebusListener):
		next_connect_wait = []
		established = 0
		closed = 0

		def messagebus_connection_established(self, messagebus: Messagebus) -> None:
			self.established += 1

		def messagebus_connection_closed(self, messagebus: Messagebus) -> None:
			self.closed += 1
			self.next_connect_wait.append(messagebus._next_connect_wait)

	num = 0

	def ws_connect_callback(handler: HTTPTestServerRequestHandler) -> None:
		nonlocal num
		num += 1
		if num == 2:
			handler._ws_close(1013, "Maintenance mode\nRetry-After: 5")
		else:
			smsg = ChannelSubscriptionEventMessage(
				sender="service:worker:test:1", channel="host:test-client.uib.local", subscribed_channels=["chan1", "chan2", "chan3"]
			)
			handler.ws_send_message(lz4.frame.compress(smsg.to_msgpack(), compression_level=0, block_linked=True))
			if num <= 3:
				handler._ws_close()

	with http_test_server(
		generate_cert=True, ws_connect_callback=ws_connect_callback, response_headers={"server": "opsiconfd 4.2.1.0 (uvicorn)"}
	) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all") as client:
			client.messagebus.reconnect_wait_min = 1
			client.messagebus.reconnect_wait_max = 3
			listener = MBListener()

			with listener.register(client.messagebus):
				client.connect_messagebus()
				time.sleep(20)

			assert listener.established >= 3
			assert listener.closed >= 3

			# Between reconnect_wait min and max
			assert 1 <= listener.next_connect_wait[0] <= 3
			# # Between reconnect_wait min and max + retry-after
			assert 6 <= listener.next_connect_wait[1] <= 8
			# Between reconnect_wait min and max
			assert 1 <= listener.next_connect_wait[2] <= 3


def test_get() -> None:
	response_body = b"test" * 1000
	thread_count = 10 if platform.system().lower() == "linux" else 5

	class ReqThread(Thread):
		def __init__(self, client: ServiceClient) -> None:
			super().__init__(daemon=True)
			self.client = client
			self.response: tuple[int, str, dict, bytes] = (0, "", {}, b"")

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
				assert status_code == 202
				assert reason == "status"
				assert headers["x-1"] == "1"
				assert headers["x-2"] == "2"
				assert content == response_body

		client = ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all")
		with client.connection():
			(status_code, reason, headers, content) = thread.response
			assert status_code == 202


def test_timeouts() -> None:
	listener = MyConnectionListener()

	with http_test_server(generate_cert=True, response_delay=3) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port+1}", connect_timeout=4) as client:
			client.register_connection_listener(listener)
			with pytest.raises(OpsiServiceConnectionError):
				client.connect()
			assert len(listener.events) == 2
			assert listener.events[0][0] == "open"
			assert listener.events[1][0] == "failed"
			assert listener.events[1][1] is client
			assert "max retries exceeded" in str(listener.events[1][2]).lower()

		with ServiceClient(f"https://127.0.0.1:{server.port}", connect_timeout=4, verify="accept_all") as client:
			client.connect()
			start = time.time()
			with pytest.raises(OpsiServiceTimeoutError):
				client.get("/", read_timeout=2)
			assert round(time.time() - start) >= 2

			assert client.get("/", read_timeout=4)[0] == 200


def test_messagebus_ping() -> None:
	pong_count = 0

	def ws_connect_callback(handler: HTTPTestServerRequestHandler) -> None:
		handler._ws_send_message(handler._opcode_ping, b"")

	def _on_pong(messagebus: Messagebus, app: WebSocketApp, message: bytes) -> None:
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
			params: list[tuple[Any, ...] | list[Any] | None] = [
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
				client.jsonrpc("method", params=_params)

			server.restart(new_cert=True)

			client.jsonrpc("reconnect")

			reqs = [json.loads(req) for req in log_file.read_text(encoding="utf-8").strip().split("\n")]
			# connect
			assert reqs[0]["method"] == "HEAD"
			# get interface
			assert reqs[1]["method"] == "POST"
			for idx in range(len(params)):
				assert reqs[idx + 2]["path"] == "/rpc"
				assert reqs[idx + 2]["method"] == "POST"
				assert reqs[idx + 2]["request"]["method"] == "method"
				assert reqs[idx + 2]["request"]["jsonrpc"] == "2.0"
				assert reqs[idx + 2]["request"]["params"] == list(params[idx] or [])

			assert reqs[-1]["method"] == "POST"
			assert reqs[-1]["request"]["method"] == "reconnect"


def test_custom_jsonrpc_path(tmp_path: Path) -> None:
	log_file = tmp_path / "request.log"
	with http_test_server(generate_cert=True, log_file=log_file, response_headers={"server": "opsiconfd 4.2.0.0 (uvicorn)"}) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port}/opsiclientd", verify="accept_all") as client:
			client.jsonrpc("method")

			reqs = [json.loads(req) for req in log_file.read_text(encoding="utf-8").strip().split("\n")]
			# connect
			assert reqs[0]["method"] == "HEAD"
			# get interface
			assert reqs[1]["method"] == "POST"
			assert reqs[2]["method"] == "POST"
			assert reqs[2]["path"] == "/opsiclientd"


def test_jsonrpc_interface(tmp_path: Path) -> None:
	log_file = tmp_path / "request.log"
	interface: list[dict[str, Any]] = [
		{
			"name": "test_method",
			"params": ["arg1", "*arg2", "**arg3"],
			"args": ["arg1", "arg2"],
			"varargs": None,
			"keywords": "arg4",
			"defaults": ["default2"],
			"deprecated": False,
			"alternative_method": None,
			"doc": None,
			"annotations": {},
		},
		{
			"name": "backend_getInterface",
			"params": [],
			"args": ["self"],
			"varargs": None,
			"keywords": None,
			"defaults": None,
			"deprecated": False,
			"alternative_method": None,
			"doc": None,
			"annotations": {},
		},
		{
			"name": "backend_exit",
			"params": [],
			"args": ["self"],
			"varargs": None,
			"keywords": None,
			"defaults": None,
			"deprecated": False,
			"alternative_method": None,
			"doc": None,
			"annotations": {},
		},
	]
	with http_test_server(generate_cert=True, log_file=log_file, response_headers={"server": "opsiconfd 4.2.0.285 (uvicorn)"}) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all", jsonrpc_create_methods=True) as client:
			server.response_body = json.dumps({"jsonrpc": "2.0", "result": interface}).encode("utf-8")
			server.response_headers["Content-Type"] = "application/json"
			client.connect()
			assert len(client.jsonrpc_interface) == 3
			with pytest.raises(ValueError, match="Method 'invalid' not found in interface description"):
				client.jsonrpc(method="invalid", params={"arg1": "test"})
			with pytest.raises(ValueError, match="Invalid param 'invalid' for method 'test_method'"):
				client.jsonrpc(method="test_method", params={"invalid": "test"})
			client.jsonrpc(method="test_method", params={"arg1": 1})
			client.jsonrpc(method="test_method", params={"arg1": 1, "arg3": "3"})
			client.jsonrpc(method="test_method", params={"arg2": 2})
			client.jsonrpc(method="test_method", params={"arg3": "3"})
			client.test_method(1, 2, x=3, y=4)  # type: ignore[attr-defined]
			client.test_method(1, x="y")  # type: ignore[attr-defined]

			reqs = [json.loads(req) for req in log_file.read_text(encoding="utf-8").strip().split("\n")]
			assert reqs[0]["method"] == "HEAD"
			assert reqs[1]["method"] == "POST"
			assert reqs[1]["request"]["method"] == "backend_getInterface"
			assert reqs[2]["request"]["method"] == "test_method"
			assert reqs[2]["request"]["params"] == [1]
			assert reqs[3]["request"]["params"] == [1, "default2", "3"]
			assert reqs[4]["request"]["params"] == [None, 2]
			assert reqs[5]["request"]["params"] == [None, "default2", "3"]
			assert reqs[6]["request"]["params"] == [1, 2, {"x": 3, "y": 4}]
			assert reqs[7]["request"]["params"] == [1, "default2", {"x": "y"}]

			class Test:
				pass

			log_file.unlink()
			test_obj = Test()
			client.create_jsonrpc_methods(test_obj)
			test_obj.backend_getInterface()  # type: ignore[attr-defined]
			test_obj.test_method(1, x="y")  # type: ignore[attr-defined]
			test_obj.backend_exit()  # type: ignore[attr-defined]
			reqs = [json.loads(req) for req in log_file.read_text(encoding="utf-8").strip().split("\n")]
			assert reqs[0]["request"]["method"] == "test_method"
			assert reqs[1]["method"] == "POST"
			assert reqs[1]["path"] == "/session/logout"


def test_jsonrpc_objects(tmp_path: Path) -> None:
	log_file = tmp_path / "request.log"
	obj = {
		"type": "OpsiClient",
		"ident": "test-client.opsi.org",
		"id": "test-client.opsi.org",
		"hardwareAddress": "01:02:03:04:05:06",
		"inventoryNumber": "",
		"opsiHostKey": "f86aaf59a1774f39f0b21c466663ed30",
		"created": "2022-03-06 13:50:08",
		"lastSeen": "2022-03-06 13:50:08",
		"oneTimePassword": None,
	}
	with http_test_server(generate_cert=True, log_file=log_file, response_headers={"server": "opsiconfd 4.2.0.0 (uvicorn)"}) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all") as client:
			server.response_headers["Content-Type"] = "application/json"
			server.response_body = b'{"jsonrpc": "2.0", "result": []}'
			client.connect()
			server.response_headers["Content-Type"] = "application/json"
			server.response_body = json.dumps({"jsonrpc": "2.0", "result": obj}).encode("utf-8")
			res = client.jsonrpc(method="host_getObjects")
			assert res == obj
			client.jsonrpc_create_objects = True
			res = client.jsonrpc(method="host_getObjects")
			assert res == OpsiClient.fromHash(obj)


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


def test_backend_manager_and_get_service_client(tmp_path: Path) -> None:
	log_file = tmp_path / "request.log"
	interface: list[dict[str, Any]] = [
		{
			"name": "test_method",
			"params": ["arg1", "*arg2", "**arg3"],
			"args": ["arg1", "arg2"],
			"varargs": None,
			"keywords": "arg4",
			"defaults": ["default2"],
			"deprecated": False,
			"alternative_method": None,
			"doc": None,
			"annotations": {},
		},
		{
			"name": "backend_getInterface",
			"params": [],
			"args": ["self"],
			"varargs": None,
			"keywords": None,
			"defaults": None,
			"deprecated": False,
			"alternative_method": None,
			"doc": None,
			"annotations": {},
		},
	]
	with http_test_server(
		generate_cert=True,
		log_file=log_file,
		response_body=json.dumps({"jsonrpc": "2.0", "result": interface}).encode("utf-8"),
		response_headers={"server": "opsiconfd 4.3.0.0 (uvicorn)", "Content-Type": "application/json"},
	) as server:
		with opsi_config(
			{
				"host.id": "test-host.opsi.org",
				"host.key": "11111111111111111111111111111111",
				"service.url": f"https://localhost:{server.port}",
			}
		) as opsi_conf:
			with (
				mock.patch("opsicommon.client.opsiservice.CA_CERT_FILE", server.ca_cert),
				mock.patch("opsicommon.client.opsiservice.opsi_config", opsi_conf),
			):
				with catch_warnings():
					simplefilter("ignore")
					backend = BackendManager()
				backend.test_method(arg1=1, arg2=2)  # type: ignore[attr-defined]

				reqs = [json.loads(req) for req in log_file.read_text(encoding="utf-8").strip().split("\n")]

				assert reqs[0]["method"] == "HEAD"
				assert reqs[0]["path"] == "/rpc"
				encoded_auth = reqs[0]["headers"]["Authorization"][6:]  # Stripping "Basic "
				auth = base64.decodebytes(encoded_auth.encode("ascii")).decode("utf-8")
				assert auth == "test-host.opsi.org:11111111111111111111111111111111"

				assert reqs[1]["method"] == "POST"
				assert reqs[1]["path"] == "/rpc"
				assert reqs[1]["request"]["method"] == "backend_getInterface"

				assert reqs[2]["method"] == "POST"
				assert reqs[2]["path"] == "/rpc"
				assert reqs[2]["request"]["method"] == "test_method"

				backend.disconnect()
				log_file.unlink()

				with catch_warnings():
					simplefilter("ignore")
					backend = BackendManager(username="user", password="pass")
				reqs = [json.loads(req) for req in log_file.read_text(encoding="utf-8").strip().split("\n")]
				assert reqs[0]["method"] == "HEAD"
				assert reqs[0]["path"] == "/rpc"
				encoded_auth = reqs[0]["headers"]["Authorization"][6:]  # Stripping "Basic "
				auth = base64.decodebytes(encoded_auth.encode("ascii")).decode("utf-8")
				assert auth == "user:pass"
				backend.disconnect()
				log_file.unlink()

				service_client = get_service_client()
				reqs = [json.loads(req) for req in log_file.read_text(encoding="utf-8").strip().split("\n")]
				assert reqs[0]["method"] == "HEAD"
				assert reqs[0]["path"] == "/rpc"
				encoded_auth = reqs[0]["headers"]["Authorization"][6:]  # Stripping "Basic "
				auth = base64.decodebytes(encoded_auth.encode("ascii")).decode("utf-8")
				assert auth == "test-host.opsi.org:11111111111111111111111111111111"
				service_client.disconnect()
				log_file.unlink()


def test_messagebus_jsonrpc() -> None:
	delay = 0.0
	rpc_error = None

	def ws_message_callback(handler: HTTPTestServerRequestHandler, message: bytes) -> None:
		nonlocal delay
		nonlocal rpc_error
		msg = JSONRPCRequestMessage.from_msgpack(lz4.frame.decompress(message))
		time.sleep(delay)
		res = JSONRPCResponseMessage(
			sender="service:worker:test:1",
			channel="host:test-client.uib.local",
			rpc_id=msg.rpc_id,
			result=None if rpc_error else msg.params,
			error=rpc_error,
		)
		handler.ws_send_message(lz4.frame.compress(res.to_msgpack(), compression_level=0, block_linked=True))

	with http_test_server(
		generate_cert=True, ws_message_callback=ws_message_callback, response_headers={"server": "opsiconfd 4.2.1.0 (uvicorn)"}
	) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all") as client:
			messagebus = client.connect_messagebus()
			params: list[tuple[Any, ...] | list[Any] | None] = [
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
				res = messagebus.jsonrpc("test", params=_params)
				assert res == list(_params or [])

			delay = 3.0
			with mock.patch("opsicommon.client.opsiservice.RPC_TIMEOUTS", {"test": 1}):
				with pytest.raises(OpsiServiceTimeoutError):
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
		res = JSONRPCResponseMessage(
			sender="service:worker:test:1", channel="host:test-client.uib.local", rpc_id=msg.rpc_id, result=f"RESULT {msg.rpc_id}"
		)
		handler.ws_send_message(res.to_msgpack())

	with http_test_server(
		generate_cert=True, ws_message_callback=ws_message_callback, response_headers={"server": "opsiconfd 4.2.1.0 (uvicorn)"}
	) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all") as client:
			client.messagebus.compression = None
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
		def __init__(self, message_types: Iterable[MessageType | str] | None = None) -> None:
			super().__init__(message_types=message_types)
			self.messages_received: list[Message] = []
			self.expired_messages_received: list[Message] = []
			self.connection_open_calls = 0
			self.connection_established_calls = 0
			self.connection_closed_calls = 0
			self.connection_failed_calls = 0

		def messagebus_connection_open(self, messagebus: Messagebus) -> None:
			self.connection_open_calls += 1

		def messagebus_connection_established(self, messagebus: Messagebus) -> None:
			self.connection_established_calls += 1

		def messagebus_connection_closed(self, messagebus: Messagebus) -> None:
			self.connection_closed_calls += 1

		def messagebus_connection_failed(self, messagebus: Messagebus, exception: Exception) -> None:
			self.connection_failed_calls += 1

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
		now = timestamp()
		handler.ws_send_message(
			JSONRPCResponseMessage(
				id="00000000-0000-4000-8000-000000000001",
				sender="service:worker:test:1",
				channel="host:test-client.uib.local",
				rpc_id="1",
				expires=now - 1,
			).to_msgpack()
		)
		handler.ws_send_message(
			JSONRPCResponseMessage(
				id="00000000-0000-4000-8000-000000000002",
				sender="service:worker:test:2",
				channel="host:test-client.uib.local",
				rpc_id="2",
				expires=0,
			).to_msgpack()
		)
		handler.ws_send_message(
			JSONRPCResponseMessage(
				id="00000000-0000-4000-8000-000000000003", sender="service:worker:test:3", channel="host:test-client.uib.local", rpc_id="3"
			).to_msgpack()
		)
		handler.ws_send_message(b"DO NOT CRASH ON INVALID DATA")
		handler.ws_send_message(
			FileUploadResultMessage(
				id="00000000-0000-4000-8000-000000000004",
				sender="service:worker:test:1",
				channel="host:test-client.uib.local",
				file_id="bcc2b07d-badc-49b8-9ff6-6ce37884686e",
				expires=now - 1,
			).to_msgpack()
		)
		handler.ws_send_message(
			FileUploadResultMessage(
				id="00000000-0000-4000-8000-000000000005",
				sender="service:worker:test:1",
				channel="host:test-client.uib.local",
				file_id="49730998-2bfa-4ae3-b80c-bd0af20e9441",
			).to_msgpack()
		)

	with http_test_server(
		generate_cert=True, ws_connect_callback=ws_connect_callback, response_headers={"server": "opsiconfd 4.2.1.0 (uvicorn)"}
	) as server:
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all") as client:
			client.messagebus.compression = None
			with (
				listener1.register(client.messagebus),
				listener2.register(client.messagebus),
				listener3.register(client.messagebus),
				listener4.register(client.messagebus),
			):
				assert len(client.messagebus._listener) == 4
				client.messagebus.reconnect_wait_min = 2
				client.messagebus.reconnect_wait_max = 2
				client.messagebus._connect_timeout = 2
				client.connect_messagebus()
				# Receive messages for 3 seconds
				time.sleep(3)
				# Stop server
				server.stop()
				# Wait for reconnect after 2 seconds (which will fail)
				time.sleep(5)
				client.disconnect()

			assert len(client.messagebus._listener) == 0

			for listener in (listener1, listener2, listener3, listener4):
				assert listener.connection_open_calls == 2
				assert listener.connection_established_calls == 1
				assert listener.connection_closed_calls == 1
				assert listener.connection_failed_calls == 1

	# listener1 / listener3: JSONRPC_RESPONSE + FILE_UPLOAD_RESULT
	for listener in (listener1, listener3):
		assert ["00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000004"] == sorted(
			[m.id for m in listener.expired_messages_received]
		)
		assert [
			"00000000-0000-4000-8000-000000000002",
			"00000000-0000-4000-8000-000000000003",
			"00000000-0000-4000-8000-000000000005",
		] == sorted([m.id for m in listener.messages_received])

	# listener2: JSONRPC_RESPONSE
	assert ["00000000-0000-4000-8000-000000000001"] == sorted([m.id for m in listener2.expired_messages_received])
	assert [
		"00000000-0000-4000-8000-000000000002",
		"00000000-0000-4000-8000-000000000003",
	] == sorted([m.id for m in listener2.messages_received])

	# listener4: FILE_CHUNK
	assert not listener4.expired_messages_received
	assert not listener4.messages_received


def test_server_date_update() -> None:
	dt_set = None

	def mock_set_system_datetime(utc_datetime: datetime) -> None:
		nonlocal dt_set
		dt_set = utc_datetime

	with (
		mock.patch("opsicommon.client.opsiservice.set_system_datetime", mock_set_system_datetime),
		http_test_server(generate_cert=True) as server,
	):
		max_time_diff = 5
		with ServiceClient(f"https://127.0.0.1:{server.port}", verify="accept_all", max_time_diff=max_time_diff) as client:
			for hdr in "date", "x-date-unix-timestamp":
				# Difference smaller than max_time_diff => Keep time
				now = datetime.now(timezone.utc)
				server_dt = now + timedelta(seconds=max_time_diff - 3)
				if hdr == "date":
					server_dt_str = datetime.strftime(server_dt, "%a, %d %b %Y %H:%M:%S UTC")
					server.response_headers = {hdr: server_dt_str}
				else:
					server_dt_str = str(int(server_dt.timestamp()))
					server.response_headers = {hdr: server_dt_str}
				client.connect()
				assert not dt_set
				client.disconnect()
				dt_set = None

				# Difference bigger than max_time_diff => Set time
				for delta in (10, -10):
					now = datetime.now(timezone.utc)
					server_dt = now + timedelta(seconds=max_time_diff + delta)
					if hdr == "date":
						server_dt_str = datetime.strftime(server_dt, "%a, %d %b %Y %H:%M:%S UTC")
						server.response_headers = {hdr: server_dt_str}
					else:
						server_dt_str = str(int(server_dt.timestamp()))
						server.response_headers = {hdr: server_dt_str}
					client.connect()
					assert dt_set
					assert abs((dt_set - server_dt).total_seconds()) < 3
					client.disconnect()
					dt_set = None

				if hdr == "date":
					# None UTC time in header => Keep time
					now = datetime.now(timezone.utc)
					server_dt = now + timedelta(seconds=max_time_diff + 100)
					server_dt_str = datetime.strftime(server_dt, "%a, %d %b %Y %H:%M:%S GMT")
					server.response_headers = {hdr: server_dt_str}
					client.connect()
					assert not dt_set


def test_permission_error_ca_cert_file() -> None:
	load_verify_locations_orig = SSLContext.load_verify_locations
	err_count = 0

	def load_verify_locations(
		self: SSLContext,
		cafile: str | Path | None = None,
		capath: str | Path | None = None,
		cadata: str | None = None,
	) -> None:
		nonlocal err_count
		err_count += 1
		if err_count > 2:
			return load_verify_locations_orig(self, cafile, capath, cadata)
		raise OSError("Permission denied")

	with (
		mock.patch("ssl.SSLContext.load_verify_locations", load_verify_locations),
		http_test_server(generate_cert=True) as server,
	):
		with ServiceClient(f"https://localhost:{server.port}", verify="opsi_ca", ca_cert_file=server.ca_cert) as client:
			client.connect()
			client.get("/")


@pytest.mark.windows
def test_permission_error_ca_cert_file_lock() -> None:
	from opsicommon.system.windows import _lock_file, _unlock_file

	load_verify_locations_orig = SSLContext.load_verify_locations
	attempts = 0
	file_handle = None

	def load_verify_locations(
		self: SSLContext,
		cafile: str | Path | None = None,
		capath: str | Path | None = None,
		cadata: str | None = None,
	) -> None:
		nonlocal attempts
		attempts += 1
		if attempts == 2:
			assert file_handle
			_unlock_file(file_handle)
		return load_verify_locations_orig(self, cafile, capath, cadata)

	with (
		mock.patch("ssl.SSLContext.load_verify_locations", load_verify_locations),
		http_test_server(generate_cert=True) as server,
	):
		with ServiceClient(f"https://localhost:{server.port}", verify="strict_check", ca_cert_file=server.ca_cert) as client:
			assert server.ca_cert
			with open(server.ca_cert, "a+", encoding="utf-8") as file:
				file_handle = file
				_lock_file(file, exclusive=True)
				client.connect()
				assert attempts == 3
