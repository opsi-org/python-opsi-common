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

import pywintypes  # type: ignore[import] # pylint: disable=import-error
import win32crypt  # type: ignore[import] # pylint: disable=import-error
from OpenSSL import crypto  # type: ignore[import]

from opsicommon.logging import get_logger

crypt32 = ctypes.WinDLL("crypt32.dll")  # type: ignore[attr-defined]

__all__ = ("install_ca", "load_ca", "remove_ca")

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
	store_name: str, ctype: bool = False, force_close: bool = False  # pylint: disable=unused-argument
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


def install_ca(ca_cert: crypto.X509) -> None:
	store_name = "Root"

	logger.info("Installing CA '%s' into '%s' store", ca_cert.get_subject().CN, store_name)

	with _open_cert_store(store_name) as store:
		store.CertAddEncodedCertificateToStore(
			X509_ASN_ENCODING, crypto.dump_certificate(crypto.FILETYPE_ASN1, ca_cert), CERT_STORE_ADD_REPLACE_EXISTING
		)


def load_ca(subject_name: str) -> crypto.X509 | None:
	store_name = "Root"
	logger.debug("Trying to find %s in certificate store", subject_name)
	with _open_cert_store(store_name, force_close=False) as store:
		for certificate in store.CertEnumCertificatesInStore():
			# logger.trace("checking certificate %s", certificate.SerialNumber)	# ASN1 encoded integer
			ca_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, certificate.CertEncoded)
			logger.trace("checking certificate %s", ca_cert.get_subject().CN)
			if ca_cert.get_subject().CN == subject_name:
				logger.debug("Found matching ca %s", subject_name)
				return ca_cert
	logger.debug("Did not find ca")
	return None


def remove_ca(subject_name: str) -> bool:
	store_name = "Root"
	removed = 0
	with _open_cert_store(store_name, ctype=True) as store:
		while True:
			p_cert_ctx = crypt32.CertFindCertificateInStore(
				store,
				X509_ASN_ENCODING,
				0,
				CERT_FIND_SUBJECT_STR,  # Searches for a certificate that contains the specified subject name string
				subject_name,
				None,
			)
			if p_cert_ctx == 0:
				break

			cbsize = crypt32.CertGetNameStringW(p_cert_ctx, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, None, None, 0)
			buf = ctypes.create_unicode_buffer(cbsize)
			cbsize = crypt32.CertGetNameStringW(p_cert_ctx, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, None, buf, cbsize)
			logger.info("Removing CA '%s' (%s) from '%s' store", subject_name, buf.value, store_name)
			crypt32.CertDeleteCertificateFromStore(p_cert_ctx)
			crypt32.CertFreeCertificateContext(p_cert_ctx)
			removed += 1
			if removed >= 25:
				raise RuntimeError(f"Stop loop after removing {removed} certficates")

	if not removed:
		# Cert not found
		logger.info("CA '%s' not found in store '%s', nothing to remove", subject_name, store_name)
		return False

	return True
