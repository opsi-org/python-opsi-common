# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
ssl
"""

import random
from typing import Tuple, Union

from OpenSSL.crypto import (  # type: ignore[import]
	FILETYPE_PEM,
	TYPE_RSA,
	X509,
	PKey,
	X509Extension,
	X509Name,
	dump_certificate,
	dump_privatekey,
)

from opsicommon.logging import get_logger

PRIVATE_KEY_CIPHER = "DES3"

logger = get_logger("opsicommon.general")


def as_pem(cert_or_key: Union[X509, PKey], passphrase=None):
	if isinstance(cert_or_key, X509):
		return dump_certificate(FILETYPE_PEM, cert_or_key).decode("ascii")
	if isinstance(cert_or_key, PKey):
		return dump_privatekey(
			FILETYPE_PEM,
			cert_or_key,
			cipher=None if passphrase is None else PRIVATE_KEY_CIPHER,
			passphrase=None if passphrase is None else passphrase.encode("utf-8"),
		).decode("ascii")
	raise TypeError(f"Invalid type: {cert_or_key}")


def create_x590_name(subject: dict = None) -> X509Name:
	subj = {"C": "DE", "ST": "RP", "L": "MAINZ", "O": "uib", "OU": "opsi", "CN": "opsi", "emailAddress": "info@opsi.org"}
	subj.update(subject or {})

	x509_name = X509Name(X509().get_subject())
	x509_name.countryName = subj.get("countryName", subj.get("C"))
	x509_name.stateOrProvinceName = subj.get("stateOrProvinceName", subj.get("ST"))
	x509_name.localityName = subj.get("localityName", subj.get("L"))
	x509_name.organizationName = subj.get("organizationName", subj.get("O"))
	x509_name.organizationalUnitName = subj.get("organizationalUnitName", subj.get("OU"))
	x509_name.commonName = subj.get("commonName", subj.get("CN"))
	x509_name.emailAddress = subj.get("emailAddress")

	return x509_name


def create_ca(subject: dict, valid_days: int, key: PKey = None) -> Tuple[X509, PKey]:
	common_name = subject.get("commonName", subject.get("CN"))
	if not common_name:
		raise ValueError("commonName missing in subject")

	if not key:
		logger.notice("Creating CA keypair")
		key = PKey()
		key.generate_key(TYPE_RSA, 4096)

	ca_cert = X509()
	ca_cert.set_version(2)
	random_number = random.getrandbits(32)
	serial_number = int.from_bytes(f"{common_name}-{random_number}".encode(), byteorder="big")
	ca_cert.set_serial_number(serial_number)
	ca_cert.gmtime_adj_notBefore(0)
	ca_cert.gmtime_adj_notAfter(valid_days * 60 * 60 * 24)

	ca_cert.set_version(2)
	ca_cert.set_pubkey(key)

	ca_subject = create_x590_name(subject)

	ca_cert.set_issuer(ca_subject)
	ca_cert.set_subject(ca_subject)
	ca_cert.add_extensions(
		[X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_cert), X509Extension(b"basicConstraints", True, b"CA:TRUE")]
	)
	ca_cert.sign(key, "sha256")

	return (ca_cert, key)


def create_server_cert(  # pylint: disable=too-many-arguments
	subject: dict, valid_days: int, ip_addresses: set, hostnames: set, ca_key: X509, ca_cert: PKey, key: PKey = None
) -> Tuple[X509, PKey]:
	common_name = subject.get("commonName", subject.get("CN"))
	if not common_name:
		raise ValueError("commonName missing in subject")

	if not key:
		logger.info("Creating server key pair")
		key = PKey()
		key.generate_key(TYPE_RSA, 4096)

	# Chrome requires CN from Subject also as Subject Alt
	hostnames.add(common_name)
	hns = ", ".join([f"DNS:{str(hn).strip()}" for hn in hostnames])
	ips = ", ".join([f"IP:{str(ip).strip()}" for ip in ip_addresses])
	alt_names = ""
	if hns:
		alt_names += hns
	if ips:
		if alt_names:
			alt_names += ", "
		alt_names += ips

	cert = X509()
	cert.set_version(2)

	srv_subject = create_x590_name(subject)
	cert.set_subject(srv_subject)

	random_number = random.getrandbits(32)
	serial_number = int.from_bytes(f"{common_name}-{random_number}".encode(), byteorder="big")
	cert.set_serial_number(serial_number)
	cert.gmtime_adj_notBefore(0)
	cert.gmtime_adj_notAfter(valid_days * 60 * 60 * 24)
	cert.set_issuer(ca_cert.get_subject())
	cert.set_subject(srv_subject)

	cert.add_extensions(
		[
			X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_cert),
			X509Extension(b"basicConstraints", True, b"CA:FALSE"),
			X509Extension(b"keyUsage", True, b"nonRepudiation, digitalSignature, keyEncipherment"),
			X509Extension(b"extendedKeyUsage", False, b"serverAuth, clientAuth, codeSigning, emailProtection"),
		]
	)
	if alt_names:
		cert.add_extensions([X509Extension(b"subjectAltName", False, alt_names.encode("utf-8"))])
	cert.set_pubkey(key)
	cert.sign(ca_key, "sha256")

	return (cert, key)
