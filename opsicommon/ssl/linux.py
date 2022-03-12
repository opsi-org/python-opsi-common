# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import os
import subprocess

import distro
from OpenSSL import crypto

from opsicommon.logging import logger

__all__ = ["install_ca", "load_ca", "remove_ca"]


def _get_cert_path_and_cmd():
	dist = {distro.id()}
	for name in (distro.like() or "").split(" "):
		if name:
			dist.add(name)
	if "centos" in dist or "rhel" in dist:
		# /usr/share/pki/ca-trust-source/anchors/
		return ("/etc/pki/ca-trust/source/anchors", "update-ca-trust")
	if "debian" in dist or "ubuntu" in dist:
		return ("/usr/local/share/ca-certificates", "update-ca-certificates")
	if "sles" in dist or "suse" in dist:
		return ("/usr/share/pki/trust/anchors", "update-ca-certificates")

	logger.error("Failed to set system cert path on distro '%s', like: %s", distro.id(), distro.like())
	raise RuntimeError(f"Failed to set system cert path on distro '{distro.id()}', like: {distro.like()}")


def install_ca(ca_cert: crypto.X509):
	system_cert_path, cmd = _get_cert_path_and_cmd()

	logger.info("Installing CA '%s' into system store", ca_cert.get_subject().CN)

	cert_file = os.path.join(system_cert_path, f"{ca_cert.get_subject().CN.replace(' ', '_')}.crt")
	with open(cert_file, "wb") as file:
		file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))

	output = subprocess.check_output([cmd], shell=False)
	logger.debug("Output of '%s': %s", cmd, output)


def load_ca(subject_name: str) -> crypto.X509:
	system_cert_path, _cmd = _get_cert_path_and_cmd()
	if os.path.exists(system_cert_path):
		for root, _dirs, files in os.walk(system_cert_path):
			for entry in files:
				with open(os.path.join(root, entry), "rb") as file:
					try:
						ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, file.read())
						if ca_cert.get_subject().CN == subject_name:
							return ca_cert
					except crypto.Error:
						continue
	return None


def remove_ca(subject_name: str) -> bool:
	system_cert_path, cmd = _get_cert_path_and_cmd()
	removed = 0
	if os.path.exists(system_cert_path):
		for root, _dirs, files in os.walk(system_cert_path):
			for entry in files:
				filename = os.path.join(root, entry)
				with open(filename, "rb") as file:
					try:
						ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, file.read())
						if ca_cert.get_subject().CN == subject_name:
							logger.info("Removing CA '%s' (%s)", subject_name, filename)
							os.remove(filename)
							removed += 1
					except crypto.Error:
						continue

	if not removed:
		logger.info("CA '%s' not found in '%s', nothing to remove", subject_name, system_cert_path)
		return False

	output = subprocess.check_output([cmd], shell=False)
	logger.debug("Output of '%s': %s", cmd, output)
	return True
