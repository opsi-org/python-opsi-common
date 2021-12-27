# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import os
import tempfile
import subprocess

from OpenSSL import crypto

from opsicommon.logging import logger

__all__ = ["install_ca", "load_ca", "remove_ca"]


def install_ca(ca_cert: crypto.X509):
	logger.info("Installing CA '%s' into system store", ca_cert.get_subject().CN)

	pem_file = tempfile.NamedTemporaryFile(mode="wb", delete=False)  # pylint: disable=consider-using-with
	pem_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))
	pem_file.close()
	try:
		subprocess.check_call([
			"security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", pem_file.name
		], shell=False)
	finally:
		os.remove(pem_file.name)


def load_ca(subject_name: str) -> crypto.X509:
	pem = subprocess.check_output([
		"security", "find-certificate", "-p", "-c", subject_name, "/Library/Keychains/System.keychain"
	], shell=False)
	if not pem or not pem.strip():
		logger.notice("did not find certificate %s", subject_name)
		return None
	return crypto.load_certificate(crypto.FILETYPE_PEM, pem.strip().decode("utf-8"))


def remove_ca(subject_name: str) -> bool:
	ca_cert = load_ca(subject_name)
	if not ca_cert:
		logger.info("CA '%s' not found, nothing to remove", subject_name)
		return

	logger.info("Removing CA '%s'", subject_name)
	pem_file = tempfile.NamedTemporaryFile(mode="wb", delete=False)  # pylint: disable=consider-using-with
	pem_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))
	pem_file.close()
	try:
		subprocess.check_call(["security", "remove-trusted-cert", "-d", pem_file.name], shell=False)
	finally:
		os.remove(pem_file.name)
