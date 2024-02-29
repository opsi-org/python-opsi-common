# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
ssl
"""

from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import CertificateBuilder
from typing_extensions import deprecated

from opsicommon.logging import get_logger

PRIVATE_KEY_CIPHER = "DES3"
CA_KEY_BITS = 4096
SERVER_KEY_BITS = 4096

logger = get_logger("opsicommon.general")


def x509_name_to_dict(x509_name: x509.Name) -> dict[str, str]:
	subject = {}
	for attr, oid in {
		"C": x509.NameOID.COUNTRY_NAME,
		"ST": x509.NameOID.STATE_OR_PROVINCE_NAME,
		"L": x509.NameOID.LOCALITY_NAME,
		"O": x509.NameOID.ORGANIZATION_NAME,
		"OU": x509.NameOID.ORGANIZATIONAL_UNIT_NAME,
		"CN": x509.NameOID.COMMON_NAME,
		"emailAddress": x509.NameOID.EMAIL_ADDRESS,
	}.items():
		attrs = x509_name.get_attributes_for_oid(oid)
		if not attrs or not attrs[0].value:
			continue
		subject[attr] = attrs[0].value if isinstance(attrs[0].value, str) else attrs[0].value.decode("utf-8")
	return subject


@deprecated("Use x509_name_to_dict instead")
def subject_to_dict(subject: x509.Name) -> dict[str, str]:
	return x509_name_to_dict(subject)


def x509_name_from_dict(subject: dict[str, str | None]) -> x509.Name:
	name_attributes = []
	if val := subject.get("countryName") or subject.get("C"):
		name_attributes.append(x509.NameAttribute(x509.NameOID.COUNTRY_NAME, val))
	if val := subject.get("stateOrProvinceName") or subject.get("ST"):
		name_attributes.append(x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, val))
	if val := subject.get("localityName") or subject.get("L"):
		name_attributes.append(x509.NameAttribute(x509.NameOID.LOCALITY_NAME, val))
	if val := subject.get("organizationName") or subject.get("O"):
		name_attributes.append(x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, val))
	if val := subject.get("organizationalUnitName") or subject.get("OU"):
		name_attributes.append(x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, val))
	if val := subject.get("commonName") or subject.get("CN"):
		name_attributes.append(x509.NameAttribute(x509.NameOID.COMMON_NAME, val))
	if val := subject.get("emailAddress"):
		name_attributes.append(x509.NameAttribute(x509.NameOID.EMAIL_ADDRESS, val))
	return x509.Name(name_attributes)


def create_x509_name(subject: dict[str, str | None] | None = None) -> x509.Name:
	subj: dict[str, str | None] = {
		"C": "DE",
		"ST": "RP",
		"L": "MAINZ",
		"O": "uib",
		"OU": "opsi",
		"CN": "opsi",
		"emailAddress": "info@opsi.org",
	}
	subj.update(subject or {})
	return x509_name_from_dict(subj)


def as_pem(cert_or_key: x509.Certificate | rsa.RSAPrivateKey, passphrase: str | None = None) -> str:
	if isinstance(cert_or_key, x509.Certificate):
		if passphrase:
			raise ValueError("Passphrase not supported for certificates")
		return cert_or_key.public_bytes(encoding=serialization.Encoding.PEM).decode("ascii")
	if isinstance(cert_or_key, rsa.RSAPrivateKey):
		return cert_or_key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.PKCS8,
			encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
			if passphrase
			else serialization.NoEncryption(),
		).decode("ascii")
	raise TypeError(f"Invalid type: {cert_or_key}")


def load_key(key_file: str | Path, passphrase: str | None = None) -> rsa.RSAPrivateKey:
	if not isinstance(key_file, Path):
		key_file = Path(key_file)
	try:
		private_key = serialization.load_pem_private_key(
			key_file.read_text(encoding="utf-8").encode("utf-8"), password=passphrase.encode("utf-8") if passphrase else None
		)
		if not isinstance(private_key, rsa.RSAPrivateKey):
			raise ValueError(f"Not a RSA private key, but {private_key.__class__.__name__}")
		return private_key
	except ValueError as err:
		raise RuntimeError(f"Failed to load private key from '{key_file}': {err}") from err


def is_self_signed(ca_cert: x509.Certificate) -> bool:
	return ca_cert.issuer == ca_cert.subject


def create_ca(
	*,
	subject: x509.Name | dict[str, str],
	valid_days: int,
	key: rsa.RSAPrivateKey | None = None,
	bits: int = CA_KEY_BITS,
	permitted_domains: list[str] | set[str] | tuple[str] | None = None,
	ca_key: rsa.RSAPrivateKey | None = None,
	ca_cert: x509.Certificate | None = None,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
	if not isinstance(subject, x509.Name):
		subject = x509_name_from_dict(cast(dict[str, str | None], subject))

	cn_attr = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
	if not cn_attr or not cn_attr[0].value:
		raise ValueError("commonName missing in subject")

	if not key:
		logger.notice("Creating CA keypair")
		key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
	if not ca_key:
		# Self signed
		ca_key = key

	builder = CertificateBuilder(
		issuer_name=ca_cert.subject if ca_cert else subject,
		subject_name=subject,
		public_key=key.public_key(),
		serial_number=x509.random_serial_number(),
		not_valid_before=datetime.now(tz=timezone.utc),
		not_valid_after=datetime.now(tz=timezone.utc) + timedelta(days=valid_days),
	)
	builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
	builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
	# The CA must not issue intermediate CA certificates (pathlen=0)
	builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
	builder = builder.add_extension(
		x509.KeyUsage(
			digital_signature=True,
			content_commitment=False,
			key_encipherment=False,
			data_encipherment=False,
			key_agreement=False,
			key_cert_sign=True,
			crl_sign=True,
			encipher_only=False,
			decipher_only=False,
		),
		critical=True,
	)
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

		# python cryprography does not support name constraints
		# starting with "." on validation (malformed DNS name constraint: .mycompany.com)
		# stripping the leading "." for now
		builder = builder.add_extension(
			x509.NameConstraints(permitted_subtrees=[x509.DNSName(dom.lstrip(".")) for dom in permitted_domains], excluded_subtrees=None),
			critical=True,
		)
	return (builder.sign(ca_key, hashes.SHA256()), key)


def create_server_cert(
	*,
	subject: x509.Name | dict[str, str],
	valid_days: int,
	ip_addresses: set,
	hostnames: set,
	ca_key: rsa.RSAPrivateKey,
	ca_cert: x509.Certificate,
	key: rsa.RSAPrivateKey | None = None,
	bits: int = SERVER_KEY_BITS,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
	if not isinstance(subject, x509.Name):
		subject = x509_name_from_dict(cast(dict[str, str | None], subject))

	cn_attr = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
	if not cn_attr or not cn_attr[0].value:
		raise ValueError("commonName missing in subject")

	if not key:
		logger.info("Creating server key pair")
		key = rsa.generate_private_key(public_exponent=65537, key_size=bits)

	# Chrome requires CN from Subject also as Subject Alt
	hostnames.add(cn_attr[0].value)
	alt_names = [x509.DNSName(hn) for hn in hostnames] + [x509.IPAddress(ip_address(ip)) for ip in ip_addresses]

	builder = CertificateBuilder(
		issuer_name=ca_cert.subject,
		subject_name=subject,
		public_key=key.public_key(),
		serial_number=x509.random_serial_number(),
		not_valid_before=datetime.now(tz=timezone.utc),
		not_valid_after=datetime.now(tz=timezone.utc) + timedelta(days=valid_days),
	)
	builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
	builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
	builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
	builder = builder.add_extension(
		x509.KeyUsage(
			digital_signature=True,
			content_commitment=True,
			key_encipherment=True,
			data_encipherment=False,
			key_agreement=False,
			key_cert_sign=False,
			crl_sign=False,
			encipher_only=False,
			decipher_only=False,
		),
		critical=True,
	)
	builder = builder.add_extension(
		x509.ExtendedKeyUsage([x509.OID_SERVER_AUTH, x509.OID_CLIENT_AUTH, x509.OID_CODE_SIGNING, x509.OID_EMAIL_PROTECTION]),
		critical=False,
	)

	if alt_names:
		builder = builder.add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
	return (builder.sign(ca_key, hashes.SHA256()), key)
