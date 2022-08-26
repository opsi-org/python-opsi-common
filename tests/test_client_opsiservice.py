# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import time
from pathlib import Path

import pytest

from opsicommon import __version__
from opsicommon.client.opsiservice import (
	UIB_OPSI_CA,
	OpsiConnectionError,
	OpsiServiceVerificationError,
	OpsiTimeoutError,
	ServiceClient,
	ServiceVerificationModes,
)
from opsicommon.ssl import as_pem, create_ca, create_server_cert
from opsicommon.testing.helpers import http_test_server  # type: ignore[import]


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

	# ip_version
	for ip_version in ("4", "6", 4, 6, "auto"):
		client = ServiceClient("localhost", ip_version=ip_version)  # type: ignore[arg-type]
		assert client._ip_version == str(ip_version)  # pylint: disable=protected-access
	with pytest.raises(ValueError):
		ServiceClient("localhost", ip_version=8)

	assert ServiceClient("https://127.0.0.1")._ip_version == "4"  # pylint: disable=protected-access
	assert ServiceClient("https://[::1]")._ip_version == "6"  # pylint: disable=protected-access
	assert ServiceClient("::1")._ip_version == "6"  # pylint: disable=protected-access

	# proxy_url
	assert ServiceClient("::1")._user_agent == f"opsi-service-client/{__version__}"  # pylint: disable=protected-access
	assert ServiceClient("::1", user_agent=None)._user_agent == f"opsi-service-client/{__version__}"  # pylint: disable=protected-access
	assert ServiceClient("::1", user_agent="my app")._user_agent == "my app"  # pylint: disable=protected-access

	# connect_timeout
	assert ServiceClient("::1", connect_timeout=123)._connect_timeout == 123.0  # pylint: disable=protected-access
	assert ServiceClient("::1", connect_timeout=1.2)._connect_timeout == 1.2  # pylint: disable=protected-access
	assert ServiceClient("::1", connect_timeout=-1)._connect_timeout == 0.0  # pylint: disable=protected-access


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
		server_key=server_key_file, server_cert=server_cert_file, response_body=as_pem(ca_cert).encode("utf-8")
	) as server:
		# strict_check
		client = ServiceClient(f"https://localhost:{server.port}", verify="strict_check")
		with pytest.raises(OpsiServiceVerificationError):
			client.connect()

		client = ServiceClient(f"https://localhost:{server.port}", ca_cert_file=ca_cert_file, verify="strict_check")
		client.connect()

		client = ServiceClient(f"https://localhost:{server.port}", ca_cert_file=opsi_ca_file_on_client, verify="strict_check")
		with pytest.raises(OpsiServiceVerificationError):
			client.connect()

		# accept_all
		client = ServiceClient(f"https://localhost:{server.port}", ca_cert_file=None, verify="accept_all")
		client.connect()

		client = ServiceClient(f"https://localhost:{server.port}", ca_cert_file=ca_cert_file, verify="accept_all")
		client.connect()

		client = ServiceClient(f"https://localhost:{server.port}", ca_cert_file=opsi_ca_file_on_client, verify="accept_all")
		client.connect()

		assert not opsi_ca_file_on_client.exists()

		# fetch_ca
		client = ServiceClient(f"https://localhost:{server.port}", ca_cert_file=opsi_ca_file_on_client, verify="fetch_ca")
		client.connect()
		assert opsi_ca_file_on_client.read_text(encoding="utf-8") == as_pem(ca_cert)

		opsi_ca_file_on_client.write_text(as_pem(other_ca_cert), encoding="utf-8")
		client = ServiceClient(f"https://localhost:{server.port}", ca_cert_file=opsi_ca_file_on_client, verify="fetch_ca")
		with pytest.raises(OpsiServiceVerificationError):
			client.connect()

		opsi_ca_file_on_client.write_text("", encoding="utf-8")
		client.connect()
		assert opsi_ca_file_on_client.read_text(encoding="utf-8") == as_pem(ca_cert)
		assert client.get("/")[0] == 200

		# fetch_ca_trust_uib
		client = ServiceClient(f"https://localhost:{server.port}", ca_cert_file=opsi_ca_file_on_client, verify="fetch_ca_trust_uib")
		client.connect()
		assert opsi_ca_file_on_client.read_text(encoding="utf-8") == as_pem(ca_cert) + "\n" + UIB_OPSI_CA

		opsi_ca_file_on_client.write_text("", encoding="utf-8")
		client = ServiceClient(f"https://localhost:{server.port}", ca_cert_file=opsi_ca_file_on_client, verify="fetch_ca_trust_uib")
		client.connect()
		assert opsi_ca_file_on_client.read_text(encoding="utf-8") == as_pem(ca_cert) + "\n" + UIB_OPSI_CA


def test_connect_disconnect() -> None:
	with http_test_server(generate_cert=True) as server:
		client = ServiceClient(f"https://localhost:{server.port}", verify="accept_all")
		client.connect()
		assert client._connected is True  # pylint: disable=protected-access
		client.disconnect()
		assert client._connected is False  # pylint: disable=protected-access
		client.disconnect()
		assert client._connected is False  # pylint: disable=protected-access
		client.get("/")
		assert client._connected is True  # pylint: disable=protected-access
		client.disconnect()
		assert client._connected is False  # pylint: disable=protected-access


def test_get() -> None:
	with http_test_server(
		generate_cert=True, response_status=(202, "status"), response_headers={"x-1": "1", "x-2": "2"}, response_body=b"body\x01\x02\x03"
	) as server:
		client = ServiceClient(f"https://localhost:{server.port}", verify="accept_all")
		(status_code, reason, headers, content) = client.get("/")
		assert status_code == 202
		assert reason == "status"
		assert headers["x-1"] == "1"
		assert headers["x-2"] == "2"
		assert content == b"body\x01\x02\x03"


def test_timeouts() -> None:
	with http_test_server(generate_cert=True, response_delay=3) as server:
		start = time.time()
		with pytest.raises(OpsiConnectionError):
			client = ServiceClient(f"https://localhost:{server.port+1}", connect_timeout=2)
			client.connect()
			assert round(time.time() - start) == 2

		client = ServiceClient(f"https://localhost:{server.port}", connect_timeout=4, verify="accept_all")
		client.connect()
		start = time.time()
		with pytest.raises(OpsiTimeoutError):
			client.get("/", read_timeout=2)
		assert round(time.time() - start) == 2

		assert client.get("/", read_timeout=4)[0] == 200
