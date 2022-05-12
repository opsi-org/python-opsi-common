# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import os
import subprocess
import tempfile

from OpenSSL import crypto  # type: ignore[import]

from opsicommon.logging import get_logger

__all__ = ["install_ca", "load_ca", "remove_ca"]


logger = get_logger("opsicommon.general")


def install_ca(ca_cert: crypto.X509):
	logger.info("Installing CA '%s' into system store", ca_cert.get_subject().CN)

	pem_file = tempfile.NamedTemporaryFile(mode="wb", delete=False)  # pylint: disable=consider-using-with
	pem_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))
	pem_file.close()
	try:
		subprocess.check_call(
			["security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", pem_file.name],
			shell=False,
		)
	finally:
		os.remove(pem_file.name)


def load_ca(subject_name: str) -> crypto.X509:
	try:
		pem = subprocess.check_output(
			["security", "find-certificate", "-p", "-c", subject_name, "/Library/Keychains/System.keychain"],
			shell=False,
			stderr=subprocess.STDOUT,
		)
	except subprocess.CalledProcessError as err:
		if "could not be found" in err.output.decode():
			pem = None
		else:
			raise
	if not pem or not pem.strip():
		logger.notice("did not find certificate %s", subject_name)
		return None
	return crypto.load_certificate(crypto.FILETYPE_PEM, pem.strip().decode("utf-8"))


def remove_ca(subject_name: str) -> bool:
	ca_cert = load_ca(subject_name)
	if not ca_cert:
		logger.info("CA '%s' not found, nothing to remove", subject_name)
		return False

	removed_sha1_hash = None
	while ca_cert:
		logger.info("Removing CA '%s'", subject_name)
		sha1_hash = ca_cert.digest("sha1").decode("ascii").replace(":", "")
		if removed_sha1_hash and sha1_hash == removed_sha1_hash:
			raise RuntimeError(f"Failed to remove certficate {removed_sha1_hash}")
		subprocess.check_call(["security", "delete-certificate", "-Z", sha1_hash, "/Library/Keychains/System.keychain", "-t"], shell=False)
		removed_sha1_hash = sha1_hash
		ca_cert = load_ca(subject_name)
	return True
