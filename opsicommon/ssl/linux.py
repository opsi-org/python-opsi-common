# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import os
from typing import Generator, Tuple

import distro
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from opsicommon.logging import get_logger
from opsicommon.utils import execute

__all__ = ("install_ca", "load_cas", "load_ca", "remove_ca")


logger = get_logger("opsicommon.general")


def _get_cert_path_and_cmd() -> Tuple[str, str]:
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
	if "oracle" in dist:
		return ("usr/share/pki/ca-trust-source/anchors", "update-ca-trust")

	logger.error("Failed to set system cert path on distro '%s', like: %s", distro.id(), distro.like())
	raise RuntimeError(f"Failed to set system cert path on distro '{distro.id()}', like: {distro.like()}")


def install_ca(ca_cert: x509.Certificate) -> None:
	system_cert_path, cmd = _get_cert_path_and_cmd()
	common_name = ca_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
	if not isinstance(common_name, str):
		common_name = common_name.decode("utf-8")
	logger.info("Installing CA '%s' into system store", common_name)

	cert_file = os.path.join(system_cert_path, f"{common_name.replace(' ', '_')}.crt")
	with open(cert_file, "wb") as file:
		file.write(ca_cert.public_bytes(encoding=serialization.Encoding.PEM))

	execute([cmd])


def load_cas(subject_name: str) -> Generator[x509.Certificate, None, None]:
	system_cert_path, _cmd = _get_cert_path_and_cmd()
	if os.path.exists(system_cert_path):
		for root, _dirs, files in os.walk(system_cert_path):
			for entry in files:
				with open(os.path.join(root, entry), "rb") as file:
					try:
						ca_cert = x509.load_pem_x509_certificate(data=file.read())
						common_name = ca_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
						if not isinstance(common_name, str):
							common_name = common_name.decode("utf-8")
						if common_name == subject_name:
							yield ca_cert
					except ValueError:
						continue


def load_ca(subject_name: str) -> x509.Certificate | None:
	try:
		return next(load_cas(subject_name))
	except StopIteration:
		logger.notice("Did not find CA %r", subject_name)
		return None


def remove_ca(subject_name: str, sha1_fingerprint: str | None = None) -> bool:
	if sha1_fingerprint:
		sha1_fingerprint = sha1_fingerprint.upper()

	system_cert_path, cmd = _get_cert_path_and_cmd()
	removed = 0
	if os.path.exists(system_cert_path):
		for root, _dirs, files in os.walk(system_cert_path):
			for entry in files:
				filename = os.path.join(root, entry)
				with open(filename, "rb") as file:
					try:
						ca_cert = x509.load_pem_x509_certificate(data=file.read())
						if ca_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == subject_name:
							if sha1_fingerprint and sha1_fingerprint != ca_cert.fingerprint(hashes.SHA1()).hex().upper():
								continue
							logger.info("Removing CA '%s' (%s)", subject_name, filename)
							os.remove(filename)
							removed += 1
					except ValueError:
						continue

	if not removed:
		logger.info("CA '%s' not found in '%s', nothing to remove", subject_name, system_cert_path)
		return False

	execute([cmd])
	return True
