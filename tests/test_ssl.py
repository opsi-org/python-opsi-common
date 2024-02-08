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
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import verification

from opsicommon.ssl import (
	as_pem,
	create_ca,
	create_server_cert,
	create_x509_name,
	install_ca,
	is_self_signed,
	load_ca,
	remove_ca,
	x509_name_from_dict,
	x509_name_to_dict,
)
from opsicommon.ssl.common import subject_to_dict
from opsicommon.testing.helpers import http_test_server  # type: ignore[import]


def test_x509_name_to_dict() -> None:
	x509_name = x509.Name(
		[
			x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "DE"),
			x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "RLP"),
			x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Mainz"),
			x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "uib GmbH"),
			x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, "opsi"),
			x509.NameAttribute(x509.NameOID.COMMON_NAME, "opsicn"),
			x509.NameAttribute(x509.NameOID.EMAIL_ADDRESS, "info@opsi.org"),
		]
	)
	subject: dict[str, str | None] = {
		"C": "DE",
		"ST": "RLP",
		"L": "Mainz",
		"O": "uib GmbH",
		"OU": "opsi",
		"CN": "opsicn",
		"emailAddress": "info@opsi.org",
	}
	assert x509_name_to_dict(x509_name) == subject
	with pytest.deprecated_call():
		assert subject_to_dict(x509_name) == subject
	assert create_x509_name(subject) == x509_name


def test_create_x509_name() -> None:
	subject: dict[str, str | None] = {"emailAddress": "test@test.de"}
	x509_name = create_x509_name(subject)
	assert x509_name.get_attributes_for_oid(x509.NameOID.EMAIL_ADDRESS)[0].value == subject["emailAddress"]
	assert x509_name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "opsi"

	subject = {"emailAddress": None, "CN": "opsi"}
	x509_name = create_x509_name(subject)
	assert not x509_name.get_attributes_for_oid(x509.NameOID.EMAIL_ADDRESS)
	assert x509_name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "opsi"


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
	from opsicommon.ssl.linux import (
		_get_cert_path_and_cmd,
	)

	with mock.patch("distro.id", lambda: distro_id), mock.patch("distro.like", lambda: distro_like):
		if exc:
			with pytest.raises(exc):
				_get_cert_path_and_cmd()
		else:
			assert _get_cert_path_and_cmd() == (expected_path, expected_cmd)


# pyright: reportMissingModuleSource=false
def test_create_ca() -> None:
	subject_dict: dict[str, str | None] = {"commonName": "opsi CA", "OU": "opsi", "emailAddress": "opsi@opsi.org"}
	subject = x509_name_from_dict(subject_dict)
	ca_cert, ca_key = create_ca(subject=subject, valid_days=100)
	assert isinstance(ca_cert, x509.Certificate)
	assert isinstance(ca_key, rsa.RSAPrivateKey)
	assert ca_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == subject_dict["commonName"]
	assert ca_cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value == subject_dict["OU"]
	assert ca_cert.subject.get_attributes_for_oid(x509.NameOID.EMAIL_ADDRESS)[0].value == subject_dict["emailAddress"]

	permitted_domains = [".mycompany.com", "mycompany.org", "localhost"]
	ca_cert, ca_key = create_ca(subject=subject, valid_days=100, permitted_domains=permitted_domains)

	name_constraints = [extension for extension in ca_cert.extensions if extension.oid == x509.OID_NAME_CONSTRAINTS][0]
	assert name_constraints.critical
	assert name_constraints.value.permitted_subtrees[0].value == "mycompany.com"
	assert name_constraints.value.permitted_subtrees[1].value == "mycompany.org"
	assert name_constraints.value.permitted_subtrees[2].value == "localhost"

	try:
		from OpenSSL.crypto import (  # type: ignore[import-untyped]
			FILETYPE_ASN1,
			X509,
			dump_certificate,
		)

		openssl_x509 = X509.from_cryptography(ca_cert)
		assert ca_cert.fingerprint(hashes.SHA1()).hex().upper() == openssl_x509.digest("sha1").decode("ascii").replace(":", "")
		assert dump_certificate(FILETYPE_ASN1, openssl_x509) == ca_cert.public_bytes(encoding=serialization.Encoding.DER)
	except ImportError:
		pass

	for domain in ["mycompany.com", "sub.mycompany.com", "mycompany.org", "localhost", "other.tld"]:
		kwargs: dict[str, Any] = {
			"subject": {"emailAddress": f"opsi@{domain}", "CN": f"server.{domain}"},
			"valid_days": 100,
			"ip_addresses": {"172.0.0.1", "::1", "192.168.1.1"},
			"hostnames": {f"server.{domain}", "localhost"},
			"ca_key": ca_key,
			"ca_cert": ca_cert,
		}
		srv_cert, _srv_key = create_server_cert(**kwargs)
		store = verification.Store([ca_cert])
		builder = verification.PolicyBuilder().store(store)

		verifier = builder.build_server_verifier(x509.DNSName(list(kwargs["hostnames"])[0]))
		if domain in "other.tld":
			with pytest.raises(Exception, match="no permitted name constraints matched SAN"):
				verifier.verify(srv_cert, [])
		else:
			verifier.verify(srv_cert, [])

	subject_dict["commonName"] = None
	subject = x509_name_from_dict(subject_dict)
	with pytest.raises(ValueError):
		create_ca(subject=subject, valid_days=100)


def test_create_intermediate_ca() -> None:
	ca_subject = {"CN": "ACME Root CA", "emailAddress": "ca@acme.org"}
	(ca_crt, ca_key) = create_ca(subject=ca_subject, valid_days=1000)

	intermediate_ca_subject = {"CN": "ACME Intermediate CA", "emailAddress": "ca@opsi.org"}
	(intermediate_ca_crt, _intermediate_ca_key) = create_ca(subject=intermediate_ca_subject, valid_days=500, ca_key=ca_key, ca_cert=ca_crt)

	assert is_self_signed(ca_crt)
	assert not is_self_signed(intermediate_ca_crt)

	assert ca_crt.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == ca_subject["CN"]
	assert intermediate_ca_crt.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == ca_subject["CN"]
	assert intermediate_ca_crt.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == intermediate_ca_subject["CN"]


def test_create_server_cert() -> None:
	subject = {"CN": "opsi CA", "OU": "opsi", "emailAddress": "opsi@opsi.org"}
	ca_cert, ca_key = create_ca(subject=subject, valid_days=1000)
	kwargs: dict[str, Any] = {
		"subject": {"emailAddress": "opsi@opsi.org"},
		"valid_days": 100,
		"ip_addresses": {"172.0.0.1", "::1", ipaddress.ip_address("192.168.1.1")},
		"hostnames": {"localhost", "opsi", "opsi.dom.tld"},
		"ca_key": ca_key,
		"ca_cert": ca_cert,
	}
	with pytest.raises(ValueError) as err:
		cert, key = create_server_cert(**kwargs)
	assert "commonName missing in subject" in str(err)

	kwargs["subject"]["CN"] = "server.dom.tld"
	cert, key = create_server_cert(**kwargs)
	assert isinstance(cert, x509.Certificate)
	assert isinstance(key, rsa.RSAPrivateKey)
	assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == kwargs["subject"]["CN"]

	alt_names = [extension for extension in cert.extensions if extension.oid == x509.OID_SUBJECT_ALTERNATIVE_NAME][0]
	assert not alt_names.critical
	assert alt_names.value.get_values_for_type(x509.DNSName) == list(kwargs["hostnames"])
	assert alt_names.value.get_values_for_type(x509.IPAddress) == list(ipaddress.ip_address(ip) for ip in kwargs["ip_addresses"])


def test_as_pem() -> None:
	subject = {"CN": "opsi CA", "OU": "opsi", "emailAddress": "opsi@opsi.org"}
	cert, key = create_ca(subject=subject, valid_days=100)
	pem = as_pem(cert, "")
	assert pem.startswith("-----BEGIN CERTIFICATE-----")
	pem = as_pem(key, None)
	assert pem.startswith("-----BEGIN PRIVATE KEY-----")
	pem = as_pem(key, "password")
	assert pem.startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----")
	with pytest.raises(TypeError):
		as_pem(create_x509_name({}))  # type: ignore[arg-type]


@pytest.mark.admin_permissions
def test_install_load_remove_ca() -> None:
	subject_name = "python-opsi-common test ca"
	ca_cert, _ca_key = create_ca(subject={"CN": subject_name}, valid_days=3)
	install_ca(ca_cert)
	try:
		loaded_ca_cert = load_ca(subject_name)
		assert loaded_ca_cert
		assert loaded_ca_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == subject_name
	finally:
		remove_ca(subject_name)
	loaded_ca_cert = load_ca(subject_name)
	assert loaded_ca_cert is None
	# Remove not existing ca
	remove_ca(subject_name)


# TODO: darwin
@pytest.mark.linux
@pytest.mark.windows
@pytest.mark.admin_permissions
def test_wget(tmp_path: Path) -> None:
	ca_cert, ca_key = create_ca(subject={"CN": "python-opsi-common test ca"}, valid_days=3)
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
			common_name = ca_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
			if not isinstance(common_name, str):
				common_name = common_name.decode("utf-8")
			remove_ca(common_name)
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
