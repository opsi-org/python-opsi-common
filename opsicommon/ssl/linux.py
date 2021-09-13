# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import os
from OpenSSL import crypto

from OPSI.System import (
	execute, isCentOS, isDebian, isOpenSUSE, isRHEL, isSLES, isUbuntu
)

from opsicommon.logging import logger

__all__ = ["install_ca", "remove_ca"]


def _get_cert_path_and_cmd():
	if isCentOS() or isRHEL():
		# /usr/share/pki/ca-trust-source/anchors/
		return("/etc/pki/ca-trust/source/anchors", "update-ca-trust")
	if isDebian() or isUbuntu():
		return("/usr/local/share/ca-certificates", "update-ca-certificates")
	if isOpenSUSE() or isSLES():
		return("/usr/share/pki/trust/anchors", "update-ca-certificates")

	logger.error("Failed to set system cert path")
	raise RuntimeError("Failed to set system cert path")


def install_ca(ca_cert: crypto.X509):
	system_cert_path, cmd = _get_cert_path_and_cmd()

	logger.info("Installing CA '%s' into system store", ca_cert.get_subject().CN)

	cert_file = os.path.join(
		system_cert_path,
		f"{ca_cert.get_subject().CN.replace(' ', '_')}.crt"
	)
	with open(cert_file, "wb") as file:
		file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))

	output = execute(cmd)
	logger.debug("Output of '%s': %s", cmd, output)


def remove_ca(subject_name: str) -> bool:
	system_cert_path, cmd = _get_cert_path_and_cmd()
	removed = 0
	for entry in os.listdir(system_cert_path):
		filename = os.path.join(system_cert_path, entry)
		ca = None
		with open(filename, "rb") as file:
			try:
				ca = crypto.load_certificate(crypto.FILETYPE_PEM, file.read())
			except crypto.Error:
				continue
		if ca.get_subject().CN == subject_name:
			logger.info("Removing CA '%s' (%s)", subject_name, filename)
			os.remove(filename)
			removed += 1

	if removed:
		output = execute(cmd)
		logger.debug("Output of '%s': %s", cmd, output)
	else:
		logger.info(
			"CA '%s' not found in '%s', nothing to remove",
			subject_name, system_cert_path
		)
