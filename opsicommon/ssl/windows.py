# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

from contextlib import contextmanager
# pyright: reportMissingImports=false
import ctypes
import win32crypt # pylint: disable=import-error
from OpenSSL import crypto

from opsicommon.logging import logger

crypt32 = ctypes.WinDLL('crypt32.dll')

__all__ = ["install_ca", "remove_ca"]

# lpszStoreProvider
CERT_STORE_PROV_SYSTEM = 0x0000000A

# dwFlags
CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000
CERT_STORE_OPEN_EXISTING_FLAG = 0x00004000
CERT_CLOSE_STORE_FORCE_FLAG = 0x00000001

# cert encoding flags.
CRYPT_ASN_ENCODING= 0x00000001
CRYPT_NDR_ENCODING= 0x00000002
X509_ASN_ENCODING= 0x00000001
X509_NDR_ENCODING= 0x00000002
PKCS_7_ASN_ENCODING= 0x00010000
PKCS_7_NDR_ENCODING= 0x00020000
PKCS_7_OR_X509_ASN_ENCODING= (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

# Add certificate/CRL, encoded, context or element disposition values.
CERT_STORE_ADD_NEW= 1
CERT_STORE_ADD_USE_EXISTING= 2
CERT_STORE_ADD_REPLACE_EXISTING= 3
CERT_STORE_ADD_ALWAYS= 4
CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES = 5
CERT_STORE_ADD_NEWER= 6
CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES= 7

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

@contextmanager
def _open_cert_store(store_name: str, ctype: bool = False):
	_open = win32crypt.CertOpenStore
	if ctype:
		_open = crypt32.CertOpenStore

	store = _open(
		CERT_STORE_PROV_SYSTEM,
		0,
		None,
		CERT_SYSTEM_STORE_LOCAL_MACHINE|CERT_STORE_OPEN_EXISTING_FLAG,
		store_name
	)
	try:
		yield store
	finally:
		if ctype:
			crypt32.CertCloseStore(store, CERT_CLOSE_STORE_FORCE_FLAG)
		else:
			store.CertCloseStore(CERT_CLOSE_STORE_FORCE_FLAG)


def install_ca(ca_cert: crypto.X509):
	store_name = "Root"

	logger.info("Installing CA '%s' into '%s' store", ca_cert.get_subject().CN, store_name)

	with _open_cert_store(store_name) as store:
		store.CertAddEncodedCertificateToStore(
			X509_ASN_ENCODING,
			crypto.dump_certificate(crypto.FILETYPE_ASN1, ca_cert),
			CERT_STORE_ADD_REPLACE_EXISTING
		)


def remove_ca(subject_name: str) -> bool:
	store_name = "Root"
	with _open_cert_store(store_name, ctype=True) as store:
		p_cert_ctx = crypt32.CertFindCertificateInStore(
			store,
			X509_ASN_ENCODING,
			0,
			CERT_FIND_SUBJECT_STR, # Searches for a certificate that contains the specified subject name string
			subject_name,
			None
		)
		if p_cert_ctx == 0:
			# Cert not found
			logger.info(
				"CA '%s' not found in store '%s', nothing to remove",
				subject_name, store_name
			)
			return False

		cbsize = crypt32.CertGetNameStringW(
			p_cert_ctx, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, None, None, 0
		)
		buf = ctypes.create_unicode_buffer(cbsize)
		cbsize = crypt32.CertGetNameStringW(
			p_cert_ctx, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, None, buf, cbsize
		)
		logger.info(
			"Removing CA '%s' (%s) from '%s' store",
			subject_name, buf.value, store_name
		)
		crypt32.CertDeleteCertificateFromStore(p_cert_ctx)
		crypt32.CertFreeCertificateContext(p_cert_ctx)
		return True
