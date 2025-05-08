# opsicommon is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2025 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0-only

"""
This file is part of opsi - https://www.opsi.org
"""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Generator

import distro
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from opsicommon.logging import get_logger
from opsicommon.utils import execute

__all__ = ("install_ca", "load_cas", "load_ca", "remove_ca")


logger = get_logger("opsicommon.general")


@dataclass
class SystemCACertInfo:
	ca_cert_path: Path
	ca_cert_update_cmd: list[str]
	custom_ca_certs_path: Path


def get_system_ca_cert_info() -> SystemCACertInfo:
	dist = {distro.id()}
	for name in (distro.like() or "").split(" "):
		if name:
			dist.add(name)

	if "centos" in dist or "rhel" in dist:
		ca_cert_path = Path("/etc/pki/tls/certs/ca-bundle.crt")
		ca_cert_path_alt = Path("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
		if not ca_cert_path.exists() and ca_cert_path_alt.exists():
			ca_cert_path = ca_cert_path_alt

		custom_ca_certs_path = Path("/etc/pki/ca-trust/source/anchors")
		custom_ca_certs_path_alt = Path("/usr/share/pki/ca-trust-source/anchors")
		if not custom_ca_certs_path.exists() and custom_ca_certs_path_alt.exists():
			custom_ca_certs_path = custom_ca_certs_path_alt

		info = SystemCACertInfo(
			ca_cert_path=ca_cert_path,
			ca_cert_update_cmd=["update-ca-trust"],
			custom_ca_certs_path=custom_ca_certs_path,
		)
	elif "debian" in dist or "ubuntu" in dist:
		info = SystemCACertInfo(
			ca_cert_path=Path("/etc/ssl/certs/ca-certificates.crt"),
			ca_cert_update_cmd=["update-ca-certificates"],
			custom_ca_certs_path=Path("/usr/local/share/ca-certificates"),
		)
	elif "sles" in dist or "suse" in dist:
		info = SystemCACertInfo(
			ca_cert_path=Path("/etc/ssl/ca-bundle.pem"),
			ca_cert_update_cmd=["update-ca-certificates"],
			custom_ca_certs_path=Path("/usr/share/pki/trust/anchors"),
		)
	elif "oracle" in dist:
		info = SystemCACertInfo(
			ca_cert_path=Path("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"),
			ca_cert_update_cmd=["update-ca-trust"],
			custom_ca_certs_path=Path("/usr/share/pki/ca-trust-source/anchors"),
		)
	else:
		logger.error("Failed to set system cert path on distro '%s', like: %s", distro.id(), distro.like())
		raise RuntimeError(f"Failed to set system cert path on distro '{distro.id()}', like: {distro.like()}")

	if not info.ca_cert_path.exists():
		logger.warning("CA cert path %s does not exist on distro '%s', like: %s", info.ca_cert_path, distro.id(), distro.like())
	if not info.custom_ca_certs_path.exists():
		logger.warning(
			"Custom CA cert path %s does not exist on distro '%s', like: %s", info.custom_ca_certs_path, distro.id(), distro.like()
		)
	return info


def install_ca(ca_cert: x509.Certificate) -> None:
	info = get_system_ca_cert_info()
	common_name = ca_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
	if not isinstance(common_name, str):
		common_name = common_name.decode("utf-8")
	logger.info("Installing CA '%s' into system store (%s)", common_name, info.custom_ca_certs_path)

	cert_file = info.custom_ca_certs_path / f"{common_name.replace(' ', '_')}.crt"
	cert_file.write_bytes(ca_cert.public_bytes(encoding=serialization.Encoding.PEM))
	execute(info.ca_cert_update_cmd)


def load_cas(subject_name: str) -> Generator[x509.Certificate, None, None]:
	cert_info = get_system_ca_cert_info()
	if not cert_info.custom_ca_certs_path.exists():
		return

	for root, _dirs, files in os.walk(cert_info.custom_ca_certs_path):
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

	info = get_system_ca_cert_info()
	removed = 0
	if info.custom_ca_certs_path.exists():
		for root, _dirs, files in os.walk(info.custom_ca_certs_path):
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
		logger.info("CA '%s' (%s) not found, nothing to remove", subject_name, sha1_fingerprint)
		return False

	execute(info.ca_cert_update_cmd)
	return True
