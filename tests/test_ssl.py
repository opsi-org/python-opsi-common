# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import ipaddress
import platform
import subprocess
from pathlib import Path
from typing import Any, Optional, Type
from unittest import mock

import pytest
from OpenSSL.crypto import X509, X509Store, X509StoreContext, PKey  # type: ignore[import]

from opsicommon.ssl import (
	as_pem,
	create_ca,
	create_server_cert,
	create_x590_name,
	install_ca,
	load_ca,
	remove_ca,
)
from opsicommon.testing.helpers import http_test_server  # type: ignore[import]


@pytest.mark.linux
@pytest.mark.parametrize(
	"distro_id, distro_like, expected_path, expected_cmd, exc",
	(
		("centos", "", "/etc/pki/ca-trust/source/anchors", "update-ca-trust", None),
		("somedist", "abc xyz rhel", "/etc/pki/ca-trust/source/anchors", "update-ca-trust", None),
		("debian", "", "/usr/local/share/ca-certificates", "update-ca-certificates", None),
		("", "ubuntu", "/usr/local/share/ca-certificates", "update-ca-certificates", None),
		("sles", "sles", "/usr/share/pki/trust/anchors", "update-ca-certificates", None),
		("suse", "", "/usr/share/pki/trust/anchors", "update-ca-certificates", None),
		("unknown", "", "", "", RuntimeError),
		("", "", "", "", RuntimeError),
		(None, None, "", "", RuntimeError),
	),
)
def test_get_cert_path_and_cmd(
	distro_id: str, distro_like: str, expected_path: str, expected_cmd: str, exc: Optional[Type[Exception]]
) -> None:
	from opsicommon.ssl.linux import (  # pylint: disable=import-outside-toplevel
		_get_cert_path_and_cmd,
	)

	with mock.patch("distro.id", lambda: distro_id), mock.patch("distro.like", lambda: distro_like):
		if exc:
			with pytest.raises(exc):
				_get_cert_path_and_cmd()
		else:
			assert _get_cert_path_and_cmd() == (expected_path, expected_cmd)


def test_create_x590_name() -> None:
	subject: dict[str, str | None] = {"emailAddress": "test@test.de"}
	x590_name = create_x590_name(subject)
	assert x590_name.emailAddress == subject["emailAddress"]
	assert x590_name.CN == "opsi"


def test_create_ca() -> None:
	subject = {"CN": "opsi CA", "OU": "opsi", "emailAddress": "opsi@opsi.org"}
	ca_cert, ca_key = create_ca(subject, 100)
	assert isinstance(ca_cert, X509)
	assert isinstance(ca_key, PKey)
	assert ca_cert.get_subject().CN == subject["CN"]
	assert ca_cert.get_subject().OU == subject["OU"]
	assert ca_cert.get_subject().emailAddress == subject["emailAddress"]

	permitted_domains = [".mycompany.com", "mycompany.org", "localhost"]
	ca_cert, ca_key = create_ca(subject, 100, permitted_domains=permitted_domains)

	name_constraints = [
		ca_cert.get_extension(idx)
		for idx in range(ca_cert.get_extension_count())
		if ca_cert.get_extension(idx).get_short_name() == b"nameConstraints"
	][0]
	assert name_constraints.get_critical() == 1
	assert name_constraints.get_data() == b"02\xa000\x10\x82\x0e.mycompany.com0\x0f\x82\rmycompany.org0\x0b\x82\tlocalhost"

	for domain in permitted_domains[:-1] + ["other.tld"]:
		kwargs: dict[str, Any] = {
			"subject": {"emailAddress": f"opsi@{domain}", "CN": f"server.{domain}"},
			"valid_days": 100,
			"ip_addresses": {"172.0.0.1", "::1", "192.168.1.1"},
			"hostnames": {f"server.{domain}", "localhost"},
			"ca_key": ca_key,
			"ca_cert": ca_cert,
		}
		srv_cert, _srv_key = create_server_cert(**kwargs)
		store = X509Store()
		store.add_cert(ca_cert)
		store_ctx = X509StoreContext(store, srv_cert)
		if domain in permitted_domains:
			store_ctx.verify_certificate()
		else:
			with pytest.raises(Exception, match="permitted subtree violation"):
				store_ctx.verify_certificate()

	del subject["CN"]
	with pytest.raises(ValueError):
		create_ca(subject, 100)


def test_create_server_cert() -> None:
	subject = {"CN": "opsi CA", "OU": "opsi", "emailAddress": "opsi@opsi.org"}
	ca_cert, ca_key = create_ca(subject, 1000)
	kwargs: dict[str, Any] = {
		"subject": {"emailAddress": "opsi@opsi.org"},
		"valid_days": 100,
		"ip_addresses": {"172.0.0.1", "::1", "192.168.1.1"},
		"hostnames": {"localhost", "opsi", "opsi.dom.tld"},
		"ca_key": ca_key,
		"ca_cert": ca_cert,
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
					ip_addr = ipaddress.ip_address(addr)
					cert_ips.add(ip_addr.compressed)
			break

	assert cert_hns == kwargs["hostnames"]
	assert cert_ips == kwargs["ip_addresses"]


def test_as_pem() -> None:
	subject = {"CN": "opsi CA", "OU": "opsi", "emailAddress": "opsi@opsi.org"}
	cert, key = create_ca(subject, 100)
	pem = as_pem(cert, "")
	assert pem.startswith("-----BEGIN CERTIFICATE-----")
	pem = as_pem(key, None)
	assert pem.startswith("-----BEGIN PRIVATE KEY-----")
	pem = as_pem(key, "password")
	assert pem.startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----")
	with pytest.raises(TypeError):
		as_pem(create_x590_name({}))  # type: ignore[arg-type]


@pytest.mark.admin_permissions
def test_install_load_remove_ca() -> None:
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


# TODO: darwin
@pytest.mark.linux
@pytest.mark.windows
@pytest.mark.admin_permissions
def test_wget(tmp_path: Path) -> None:  # pylint: disable=redefined-outer-name, unused-argument
	ca_cert, ca_key = create_ca({"CN": "python-opsi-common test ca"}, 3)
	kwargs: dict[str, Any] = {
		"subject": {"CN": "python-opsi-common test server cert"},
		"valid_days": 3,
		"ip_addresses": {"172.0.0.1", "::1"},
		"hostnames": {"localhost", "ip6-localhost"},
		"ca_key": ca_key,
		"ca_cert": ca_cert,
	}
	cert, key = create_server_cert(**kwargs)

	server_cert = tmp_path / "server_cert.pem"
	server_key = tmp_path / "server_key.pem"
	server_cert.write_text(as_pem(cert), encoding="utf-8")
	server_key.write_text(as_pem(key), encoding="utf-8")

	with http_test_server(server_key=server_key, server_cert=server_cert) as server:
		install_ca(ca_cert)
		try:
			if platform.system().lower() == "windows":
				assert (
					subprocess.call(
						[
							"powershell",
							"-ExecutionPolicy",
							"Bypass",
							"-Command",
							f"Invoke-WebRequest -UseBasicParsing https://localhost:{server.port}",
						]
					)
					== 0
				)
			else:
				assert subprocess.call(["wget", f"https://localhost:{server.port}", "-O-"]) == 0
		finally:
			remove_ca(ca_cert.get_subject().CN)
			if platform.system().lower() == "windows":
				assert (
					subprocess.call(
						[
							"powershell",
							"-ExecutionPolicy",
							"Bypass",
							"-Command",
							f"Invoke-WebRequest -UseBasicParsing https://localhost:{server.port}",
						]
					)
					== 1
				)
			else:
				assert subprocess.call(["wget", f"https://localhost:{server.port}", "-O-"]) == 5
