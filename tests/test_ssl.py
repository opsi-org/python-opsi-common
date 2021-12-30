# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import platform
import subprocess
import ipaddress
from unittest import mock
import pytest

from OpenSSL.crypto import X509, PKey
from opsicommon.ssl import (
	create_x590_name, as_pem, create_ca, create_server_cert,
	install_ca, load_ca, remove_ca
)

from .helpers import http_jsonrpc_server



@pytest.mark.linux
@pytest.mark.parametrize("distro_id, distro_like, expected_path, expected_cmd, exc", (
	("centos", "", "/etc/pki/ca-trust/source/anchors", "update-ca-trust", None),
	("somedist", "abc xyz rhel", "/etc/pki/ca-trust/source/anchors", "update-ca-trust", None),
	("debian", "", "/usr/local/share/ca-certificates", "update-ca-certificates", None),
	("", "ubuntu", "/usr/local/share/ca-certificates", "update-ca-certificates", None),
	("sles", "sles", "/usr/share/pki/trust/anchors", "update-ca-certificates", None),
	("suse", "", "/usr/share/pki/trust/anchors", "update-ca-certificates", None),
	("unknown", "", "", "", RuntimeError),
	("", "", "", "", RuntimeError),
	(None, None, "", "", RuntimeError)
))
def test_get_cert_path_and_cmd(distro_id, distro_like, expected_path, expected_cmd, exc):
	from opsicommon.ssl.linux import _get_cert_path_and_cmd  # pylint: disable=import-outside-toplevel

	with mock.patch('distro.id', lambda: distro_id), mock.patch('distro.like', lambda: distro_like):
		if exc:
			with pytest.raises(exc):
				_get_cert_path_and_cmd()
		else:
			assert _get_cert_path_and_cmd() == (expected_path, expected_cmd)


def test_create_x590_name():
	subject = {"emailAddress": "test@test.de"}
	x590_name = create_x590_name(subject)
	assert x590_name.emailAddress == subject["emailAddress"]
	assert x590_name.CN == "opsi"


def test_create_ca():
	subject = {
		"CN": "opsi CA",
		"OU": "opsi",
		"emailAddress": "opsi@opsi.org"
	}
	cert, key = create_ca(subject, 100)
	assert isinstance(cert, X509)
	assert isinstance(key, PKey)
	assert cert.get_subject().CN == subject["CN"]
	assert cert.get_subject().OU == subject["OU"]
	assert cert.get_subject().emailAddress == subject["emailAddress"]

	del subject["CN"]
	with pytest.raises(ValueError):
		create_ca(subject, 100)


def test_create_server_cert():
	subject = {
		"CN": "opsi CA",
		"OU": "opsi",
		"emailAddress": "opsi@opsi.org"
	}
	ca_cert, ca_key = create_ca(subject, 1000)
	kwargs = {
		"subject": {"emailAddress": "opsi@opsi.org"},
		"valid_days": 100,
		"ip_addresses": {"172.0.0.1", "::1", "192.168.1.1"},
		"hostnames": {"localhost", "opsi", "opsi.dom.tld"},
		"ca_key": ca_key,
		"ca_cert": ca_cert
	}
	with pytest.raises(ValueError) as err:
		cert, key = create_server_cert(**kwargs)
		assert "commonName missing in subject" in str(err)

	kwargs["subject"]["CN"] = "server.dom.tld"
	cert, key = create_server_cert(**kwargs)
	assert isinstance(cert, X509)
	assert isinstance(key, PKey)
	assert cert.get_subject().CN == kwargs["subject"]["CN"]

	cert_hns = set()
	cert_ips = set()
	for idx in range(cert.get_extension_count()):
		ext = cert.get_extension(idx)
		if ext.get_short_name() == b"subjectAltName":
			for alt_name in str(ext).split(","):
				alt_name = alt_name.strip()
				if alt_name.startswith("DNS:"):
					cert_hns.add(alt_name.split(":", 1)[-1].strip())
				elif alt_name.startswith(("IP:", "IP Address:")):
					addr = alt_name.split(":", 1)[-1].strip()
					addr = ipaddress.ip_address(addr)
					cert_ips.add(addr.compressed)
			break

	assert cert_hns == kwargs["hostnames"]
	assert cert_ips == kwargs["ip_addresses"]


def test_as_pem():
	subject = {
		"CN": "opsi CA",
		"OU": "opsi",
		"emailAddress": "opsi@opsi.org"
	}
	cert, key = create_ca(subject, 100)
	pem = as_pem(cert, "")
	assert pem.startswith("-----BEGIN CERTIFICATE-----")
	pem = as_pem(key, None)
	assert pem.startswith("-----BEGIN PRIVATE KEY-----")
	pem = as_pem(key, "password")
	assert pem.startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----")
	with pytest.raises(TypeError):
		as_pem(create_x590_name({}))


@pytest.mark.admin_permissions
def test_install_load_remove_ca():
	subject_name = "python-opsi-common test ca"
	ca_cert, _ca_key = create_ca({"CN": subject_name}, 3)
	install_ca(ca_cert)
	try:
		ca_cert = load_ca(subject_name)
		assert ca_cert
		assert ca_cert.get_subject().CN == subject_name
	finally:
		remove_ca(subject_name)
	ca_cert = load_ca(subject_name)
	assert ca_cert is None
	# Remove not existing ca
	remove_ca(subject_name)


@pytest.mark.admin_permissions
def test_wget(tmpdir):  # pylint: disable=redefined-outer-name, unused-argument
	ca_cert, ca_key = create_ca({"CN": "python-opsi-common test ca"}, 3)
	kwargs = {
		"subject": {"CN": "python-opsi-common test server cert"},
		"valid_days": 3,
		"ip_addresses": {"172.0.0.1", "::1"},
		"hostnames": {"localhost", "ip6-localhost"},
		"ca_key": ca_key,
		"ca_cert": ca_cert
	}
	cert, key = create_server_cert(**kwargs)

	server_cert = tmpdir / "server_cert.pem"
	server_key = tmpdir / "server_key.pem"
	server_cert.write_text(as_pem(cert), encoding="utf-8")
	server_key.write_text(as_pem(key), encoding="utf-8")

	with http_jsonrpc_server(server_key=server_key, server_cert=server_cert) as server:
		install_ca(ca_cert)
		try:
			if platform.system().lower() == "windows":
				assert subprocess.call([
					"powershell", "-ExecutionPolicy", "Bypass", "-Command" f"Invoke-WebRequest https://127.0.0.1:{server.port}"
				]) == 0
			else:
				assert subprocess.call(["wget", f"https://127.0.0.1:{server.port}", "-O-"]) == 0
		finally:
			remove_ca(ca_cert.get_subject().CN)
			if platform.system().lower() == "windows":
				assert subprocess.call([
					"powershell", "-ExecutionPolicy", "Bypass", "-Command" f"Invoke-WebRequest https://127.0.0.1:{server.port}"
				]) == 1
			else:
				assert subprocess.call(["wget", f"https://127.0.0.1:{server.port}", "-O-"]) == 5
