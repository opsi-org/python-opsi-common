# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

from pathlib import Path

import pytest

from opsicommon import __version__
from opsicommon.client.opsiservice import ServiceClient


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

	# verify_server_cert
	assert ServiceClient("::1", verify_server_cert=True)._verify_server_cert is True  # pylint: disable=protected-access
	assert ServiceClient("::1", verify_server_cert=False)._verify_server_cert is False  # pylint: disable=protected-access

	# ca_cert_file
	assert ServiceClient("::1")._ca_cert_file is None  # pylint: disable=protected-access
	assert ServiceClient("::1", ca_cert_file="cacert.pem")._ca_cert_file == "cacert.pem"  # pylint: disable=protected-access
	assert ServiceClient("::1", ca_cert_file=Path("/x/cacert.pem"))._ca_cert_file == "/x/cacert.pem"  # pylint: disable=protected-access

	# session_cookie
	assert ServiceClient("::1", session_cookie="cookie=val")._session_cookie == "cookie=val"  # pylint: disable=protected-access
	with pytest.raises(ValueError):
		assert ServiceClient("::1", session_cookie="cookie")

	# session_lifetime
	assert ServiceClient("::1", session_lifetime=10)._session_lifetime == 10  # pylint: disable=protected-access
	assert ServiceClient("::1", session_lifetime=-3)._session_lifetime == 1  # pylint: disable=protected-access

	# proxy_url
	assert ServiceClient("::1", proxy_url="system")._proxy_url == "system"  # pylint: disable=protected-access
	assert ServiceClient("::1", proxy_url=None)._proxy_url is None  # pylint: disable=protected-access
	assert ServiceClient("::1", proxy_url="https://proxy:1234")._proxy_url == "https://proxy:1234"  # pylint: disable=protected-access

	# ip_version
	for ip_version in ("4", "6", 4, 6, "auto"):
		client = ServiceClient("localhost", ip_version=ip_version)
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
