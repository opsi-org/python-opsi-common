# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import os
import tempfile

from OpenSSL import crypto
from OPSI.System import execute

from opsicommon.logging import logger

__all__ = ["install_ca", "remove_ca"]


def install_ca(ca_cert: crypto.X509):
	logger.info("Installing CA '%s' into system store", ca_cert.get_subject().CN)

	pem_file = tempfile.NamedTemporaryFile(mode="wb", delete=False, encoding="ascii")
	pem_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))
	pem_file.close()
	try:
		execute(f'security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "{pem_file.name}"')
	finally:
		os.remove(pem_file.name)


def remove_ca(subject_name: str) -> bool:

	pem = execute(f'security find-certificate -p -c "{subject_name}" /Library/Keychains/System.keychain').strip()
	if not pem:
		logger.info("CA '%s' not found, nothing to remove", subject_name)
		return

	logger.info("Removing CA '%s'", subject_name)
	pem_file = tempfile.NamedTemporaryFile(mode="wb", delete=False, encoding="ascii")
	pem_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, pem))
	pem_file.close()
	try:
		execute(f'security remove-trusted-cert -d "{pem_file.name}"')
	finally:
		os.remove(pem_file.name)
