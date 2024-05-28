# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import os
import re
import subprocess
import tempfile
from contextlib import contextmanager
from typing import Generator

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from opsicommon.logging import get_logger
from opsicommon.utils import execute

__all__ = ("install_ca", "load_cas", "load_ca", "remove_ca")


logger = get_logger("opsicommon.general")


@contextmanager
def security_authorization() -> Generator[None, None, None]:
	try:  # Allow to make changes to certificate settings
		execute(["security", "authorizationdb", "write", "com.apple.trust-settings.admin", "allow"])
		yield
	finally:  # Disallow to make changes to certificate settings
		execute(["security", "authorizationdb", "remove", "com.apple.trust-settings.admin"])


def install_ca(ca_cert: x509.Certificate) -> None:
	logger.info("Installing CA '%s' into system store", ca_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value)

	pem_file = tempfile.NamedTemporaryFile(mode="wb", delete=False)
	pem_file.write(ca_cert.public_bytes(encoding=serialization.Encoding.PEM))
	pem_file.close()
	try:
		with security_authorization():
			execute(["security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", pem_file.name])
	finally:
		os.remove(pem_file.name)


def load_cas(subject_name: str) -> Generator[x509.Certificate, None, None]:
	try:
		pem = subprocess.check_output(
			["security", "find-certificate", "-a", "-p", "-c", subject_name, "/Library/Keychains/System.keychain"],
			shell=False,
			stderr=subprocess.STDOUT,
			text=True,
		)
	except subprocess.CalledProcessError as err:
		if "could not be found" in err.output.decode():
			return
		raise
	for cert_match in re.finditer(r"(-+BEGIN CERTIFICATE-+.*?-+END CERTIFICATE-+)", pem, re.DOTALL):
		try:
			yield x509.load_pem_x509_certificate(cert_match.group(1).encode("utf-8"))
		except Exception as err:
			logger.error("Failed to load certificate: %s", err)


def load_ca(subject_name: str) -> x509.Certificate | None:
	try:
		return next(load_cas(subject_name))
	except StopIteration:
		logger.notice("Did not find CA %r", subject_name)
		return None


def remove_ca(subject_name: str, sha1_fingerprint: str | None = None) -> bool:
	if sha1_fingerprint:
		sha1_fingerprint = sha1_fingerprint.upper()

	remove_cas = []
	for ca_cert in load_cas(subject_name):
		ca_fingerprint = ca_cert.fingerprint(hashes.SHA1()).hex().upper()
		if not sha1_fingerprint or ca_fingerprint == sha1_fingerprint:
			remove_cas.append(ca_fingerprint)

	if not remove_cas:
		logger.info("CA '%s' (%s) not found, nothing to remove", subject_name, sha1_fingerprint)
		return False

	with security_authorization():
		for ca_fingerprint in remove_cas:
			logger.info("Removing CA '%s' (%s)", subject_name, ca_fingerprint)
			execute(["security", "delete-certificate", "-Z", ca_fingerprint, "/Library/Keychains/System.keychain", "-t"])

	return True
