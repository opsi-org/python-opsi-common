# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
ssl
"""

import random
from typing import Dict, Optional, Tuple, Union

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
CA_KEY_BITS = 4096
SERVER_KEY_BITS = 4096

logger = get_logger("opsicommon.general")


def subject_to_dict(subject: X509Name) -> dict[str, str]:
	return {
		"C": subject.C,
		"ST": subject.ST,
		"L": subject.L,
		"O": subject.O,
		"OU": subject.OU,
		"CN": subject.CN,
		"emailAddress": subject.emailAddress,
	}


def as_pem(cert_or_key: Union[X509, PKey], passphrase: Optional[str] = None) -> str:
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


def create_x590_name(subject: Optional[Dict[str, Optional[str]]] = None) -> X509Name:
	subj: Dict[str, Optional[str]] = {
		"C": "DE",
		"ST": "RP",
		"L": "MAINZ",
		"O": "uib",
		"OU": "opsi",
		"CN": "opsi",
		"emailAddress": "info@opsi.org",
	}
	subj.update(subject or {})

	x509_name = X509Name(X509().get_subject())
	x509_name.countryName = subj.get("countryName", subj.get("C"))  # type: ignore[assignment]
	x509_name.stateOrProvinceName = subj.get("stateOrProvinceName", subj.get("ST"))  # type: ignore[assignment]
	x509_name.localityName = subj.get("localityName", subj.get("L"))  # type: ignore[assignment]
	x509_name.organizationName = subj.get("organizationName", subj.get("O"))  # type: ignore[assignment]
	x509_name.organizationalUnitName = subj.get("organizationalUnitName", subj.get("OU"))  # type: ignore[assignment]
	x509_name.commonName = subj.get("commonName", subj.get("CN"))  # type: ignore[assignment]
	x509_name.emailAddress = subj.get("emailAddress")  # type: ignore[assignment]

	return x509_name


def create_ca(
	subject: dict,
	valid_days: int,
	key: Optional[PKey] = None,
	bits: int = CA_KEY_BITS,
	permitted_domains: list[str] | set[str] | tuple[str] | None = None,
) -> Tuple[X509, PKey]:
	common_name = subject.get("commonName", subject.get("CN"))
	if not common_name:
		raise ValueError("commonName missing in subject")

	if not key:
		logger.notice("Creating CA keypair")
		key = PKey()
		key.generate_key(TYPE_RSA, bits)

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
	extensions = [
		X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_cert),
		# The CA must not issue intermediate CA certificates (pathlen=0)
		X509Extension(b"basicConstraints", True, b"CA:true, pathlen:0"),
		X509Extension(b"keyUsage", True, b"digitalSignature, cRLSign, keyCertSign"),
	]
	if permitted_domains:
		# https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.10
		# When the constraint begins with a period, it MAY be
		# expanded with one or more labels.  That is, the constraint
		# ".example.com" is satisfied by both host.example.com and
		# my.host.example.com.  However, the constraint ".example.com" is not
		# satisfied by "example.com".

		# The name constraints extension is a multi-valued extension.
		# The name should begin with the word permitted or excluded followed by a ;.
		# The rest of the name and the value follows the syntax of subjectAltName
		# except email:copy is not supported and the IP form should consist of
		# an IP addresses and subnet mask separated by a /.

		permitted = ", ".join([f"permitted;DNS:{dom}" for dom in permitted_domains])
		extensions.append(X509Extension(b"nameConstraints", True, permitted.encode("utf-8")))

	ca_cert.add_extensions(extensions)
	ca_cert.sign(key, "sha256")

	return (ca_cert, key)


def create_server_cert(  # pylint: disable=too-many-arguments,too-many-locals
	subject: dict,
	valid_days: int,
	ip_addresses: set,
	hostnames: set,
	ca_key: PKey,
	ca_cert: X509,
	key: Optional[PKey] = None,
	bits: int = SERVER_KEY_BITS,
) -> Tuple[X509, PKey]:
	common_name = subject.get("commonName", subject.get("CN"))
	if not common_name:
		raise ValueError("commonName missing in subject")

	if not key:
		logger.info("Creating server key pair")
		key = PKey()
		key.generate_key(TYPE_RSA, bits)

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
			X509Extension(b"basicConstraints", True, b"CA:false"),
			X509Extension(b"keyUsage", True, b"nonRepudiation, digitalSignature, keyEncipherment"),
			X509Extension(b"extendedKeyUsage", False, b"serverAuth, clientAuth, codeSigning, emailProtection"),
		]
	)
	if alt_names:
		cert.add_extensions([X509Extension(b"subjectAltName", False, alt_names.encode("utf-8"))])
	cert.set_pubkey(key)
	cert.sign(ca_key, "sha256")

	return (cert, key)
