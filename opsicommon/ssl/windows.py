# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

# pyright: reportMissingImports=false
import ctypes
from contextlib import contextmanager
from typing import Any, Generator

import pywintypes  # type: ignore[import]
import win32crypt  # type: ignore[import]
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from opsicommon.logging import get_logger

crypt32 = ctypes.WinDLL("crypt32.dll")  # type: ignore[attr-defined]

__all__ = ("install_ca", "load_cas", "load_ca", "remove_ca")

# lpszStoreProvider
CERT_STORE_PROV_SYSTEM = 0x0000000A

# dwFlags
CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000
CERT_STORE_OPEN_EXISTING_FLAG = 0x00004000
CERT_CLOSE_STORE_FORCE_FLAG = 0x00000001

# cert encoding flags.
CRYPT_ASN_ENCODING = 0x00000001
CRYPT_NDR_ENCODING = 0x00000002
X509_ASN_ENCODING = 0x00000001
X509_NDR_ENCODING = 0x00000002
PKCS_7_ASN_ENCODING = 0x00010000
PKCS_7_NDR_ENCODING = 0x00020000
PKCS_7_OR_X509_ASN_ENCODING = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING

# Add certificate/CRL, encoded, context or element disposition values.
CERT_STORE_ADD_NEW = 1
CERT_STORE_ADD_USE_EXISTING = 2
CERT_STORE_ADD_REPLACE_EXISTING = 3
CERT_STORE_ADD_ALWAYS = 4
CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES = 5
CERT_STORE_ADD_NEWER = 6
CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES = 7

CERT_FIND_SUBJECT_STR = 0x00080007
CERT_FIND_SUBJECT_NAME = 0x00020007
CERT_FIND_SHA1_HASH = 0x10000
CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
CERT_NAME_FRIENDLY_DISPLAY_TYPE = 5

# Specifies the name of the X.509 certificate store to open. Valid values include the following:

# - AddressBook: Certificate store for other users.
# - AuthRoot: Certificate store for third-party certification authorities (CAs).
# - CertificationAuthority: Certificate store for intermediate certification authorities (CAs).
# - Disallowed: Certificate store for revoked certificates.
# - My: Certificate store for personal certificates.
# - Root: Certificate store for trusted root certification authorities (CAs).
# - TrustedPeople: Certificate store for directly trusted people and resources.
# - TrustedPublisher: Certificate store for directly trusted publishers.

# The default is My.

logger = get_logger("opsicommon.general")


@contextmanager
def _open_cert_store(
	store_name: str,
	ctype: bool = False,
	force_close: bool = False,
) -> Generator[Any, None, None]:  # should be _win32typing.PyCERTSTORE if present
	_open = win32crypt.CertOpenStore
	if ctype:
		_open = crypt32.CertOpenStore

	store = _open(CERT_STORE_PROV_SYSTEM, 0, None, CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG, store_name)
	try:
		yield store
	finally:
		# flags are deprecated
		try:
			if ctype:
				crypt32.CertCloseStore(store)
			else:
				store.CertCloseStore()
		except pywintypes.error as err:
			if err.winerror != -2146885617:  # CRYPT_E_PENDING_CLOSE
				raise


def install_ca(ca_cert: x509.Certificate) -> None:
	store_name = "Root"
	common_name = ca_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
	if not isinstance(common_name, str):
		common_name = common_name.decode("utf-8")

	logger.info("Installing CA '%s' into '%s' store", common_name, store_name)

	with _open_cert_store(store_name) as store:
		store.CertAddEncodedCertificateToStore(
			X509_ASN_ENCODING, ca_cert.public_bytes(encoding=serialization.Encoding.DER), CERT_STORE_ADD_REPLACE_EXISTING
		)


def load_cas(subject_name: str) -> Generator[x509.Certificate, None, None]:
	store_name = "Root"
	logger.debug("Trying to find %s in certificate store", subject_name)
	with _open_cert_store(store_name, force_close=False) as store:
		for certificate in store.CertEnumCertificatesInStore():
			# logger.trace("checking certificate %s", certificate.SerialNumber)	# ASN1 encoded integer
			try:
				ca_cert = x509.load_der_x509_certificate(data=certificate.CertEncoded)
			except ValueError as err:
				logger.warning("Failed to load certificate because of illegal values: %s", err)
				continue
			try:
				common_name = ca_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
			except IndexError:
				continue
			if not isinstance(common_name, str):
				common_name = common_name.decode("utf-8")
			logger.trace("Checking certificate %s", common_name)
			if common_name == subject_name:
				logger.debug("Found matching CA %s", subject_name)
				yield ca_cert


def load_ca(subject_name: str) -> x509.Certificate | None:
	try:
		return next(load_cas(subject_name))
	except StopIteration:
		logger.notice("Did not find CA %r", subject_name)
		return None


def remove_ca(subject_name: str, sha1_fingerprint: str | None = None) -> bool:
	if sha1_fingerprint:
		sha1_fingerprint = sha1_fingerprint.upper()

	store_name = "Root"
	removed = 0
	with _open_cert_store(store_name, force_close=False) as store:
		for certificate in store.CertEnumCertificatesInStore():
			ca_cert = x509.load_der_x509_certificate(data=certificate.CertEncoded)
			try:
				common_name = ca_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
			except IndexError:
				continue
			if not isinstance(common_name, str):
				common_name = common_name.decode("utf-8")
			logger.trace("Checking certificate %s", common_name)
			if common_name != subject_name:
				continue
			if sha1_fingerprint:
				ca_fingerprint = ca_cert.fingerprint(hashes.SHA1()).hex().upper()
				if ca_fingerprint != sha1_fingerprint:
					continue
			certificate.CertDeleteCertificateFromStore()
			removed += 1

	if not removed:
		logger.info("CA '%s' (%s) not found, nothing to remove", subject_name, sha1_fingerprint)
		return False

	return True
