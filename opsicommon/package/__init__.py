# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
opsi package class and associated methods
"""

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

import tomlkit

from opsicommon.logging import get_logger
from opsicommon.objects import Product, ProductDependency, ProductProperty
from opsicommon.package.archive import ArchiveProgressListener, create_archive, extract_archive
from opsicommon.package.control_file_handling import (
	create_package_dependencies,
	create_product,
	create_product_dependencies,
	create_product_properties,
	dictify_product,
	dictify_product_dependencies,
	dictify_product_properties,
)
from opsicommon.package.legacy_control_file import LegacyControlFile
from opsicommon.utils import compare_versions, make_temp_dir

EXCLUDE_DIRS_ON_PACK_REGEX = re.compile(r"(^\.svn$)|(^\.git$)")
EXCLUDE_FILES_ON_PACK_REGEX = re.compile(r"(~$)|(^[Tt]humbs\.db$)|(^\.[Dd][Ss]_[Ss]tore$)")
logger = get_logger("opsicommon.package")


@dataclass(slots=True, kw_only=True)
class PackageDependency:
	package: str
	version: str | None = None
	condition: str | None = None


class OpsiPackage:
	"""
	Basic class for opsi packages.
	"""

	def __init__(self, package_archive: Path | None = None, temp_dir: Path | None = None) -> None:
		self.product: Product
		self.product_properties: list[ProductProperty] = []
		self.product_dependencies: list[ProductDependency] = []
		self.package_dependencies: list[PackageDependency] = []
		self.changelog: str = ""
		self.temp_dir: Path | None = temp_dir
		if package_archive:
			self.from_package_archive(package_archive)

	def set_package_dependencies_from_json(self, json_string: str) -> None:
		self.package_dependencies = [
			PackageDependency(package=str(pdep["package"]), version=pdep.get("version"), condition=pdep.get("condition"))
			for pdep in create_package_dependencies(json.loads(json_string))
		]

	def get_package_dependencies_as_json(self) -> str:
		return json.dumps([asdict(pdep) for pdep in self.package_dependencies])

	def extract_package_archive(
		self, package_archive: Path, destination: Path, *, new_product_id: str | None = None, custom_separated: bool = False
	) -> None:
		"""
		Extact `package_archive` to `destination`.
		If `new_product_id` is supplied, the control file will be patched accordingly.
		If `custom_separated` is `True` the custom archives will be extracted to custom named directories.
		If `custom_separated` is `False` the archives will be extracted in a combined folder.
		"""
		with make_temp_dir(self.temp_dir) as temp_dir:
			logger.debug("Extracting archive %s", package_archive)
			extract_archive(package_archive, temp_dir)
			# Extract <OPSI|CLIENT_DATA|SERVER_DATA>.<custom> after <OPSI|CLIENT_DATA|SERVER_DATA>
			# If data is extracted into the same folder custom archive has precedence.
			for archive in sorted(temp_dir.iterdir(), key=lambda a: len(a.name.split("."))):
				folder_name = archive.name
				if custom_separated:
					while folder_name.endswith((".zstd", ".gz", ".bz2", ".cpio", ".tar")):
						folder_name = folder_name.rsplit(".", 1)[0]
				else:
					# Same folder for CLIENT_DATA and CLIENT_DATA.<custom>
					folder_name = archive.name.split(".", 1)[0]
				extract_archive(archive, destination / folder_name)

		control_file = self.find_and_parse_control_file(destination)
		if new_product_id:
			self.product.setId(new_product_id)
			self.generate_control_file(control_file)

	def from_package_archive(self, package_archive: Path) -> None:
		with make_temp_dir(self.temp_dir) as temp_dir:
			logger.debug("Extracting archive %s", package_archive)
			extract_archive(package_archive, temp_dir, file_pattern="OPSI.*")
			archives = list(temp_dir.glob("OPSI.*"))
			if len(archives) == 0:
				raise RuntimeError(f"No OPSI archive '{package_archive}'")

			# Extract custom last
			for archive in sorted(archives, key=lambda a: len(a.name.split("."))):
				extract_archive(archive, temp_dir, file_pattern="control*")  # or OPSI? difference tar and cpio

			self.find_and_parse_control_file(temp_dir)

	def compare_with_legacy_control_file(self, control):
		opsi_package = OpsiPackage()
		opsi_package.parse_control_file_legacy(control)
		if opsi_package.product.version is not None and self.product.version is not None:
			if compare_versions(opsi_package.product.version, ">", self.product.version):
				raise RuntimeError("Legacy control file is newer. Please update the control file.")

	def find_and_parse_control_file(self, search_dir: Path) -> Path:
		opsi_dirs = []
		for _dir in search_dir.glob("OPSI*"):
			if _dir.is_dir() and _dir.name == "OPSI" or _dir.name.startswith("OPSI."):
				opsi_dirs.append(_dir)

		# Sort custom first
		for _dir in [search_dir] + sorted(opsi_dirs, reverse=True):
			control_toml = _dir / "control.toml"
			if control_toml.exists():
				self.parse_control_file(control_toml)
				control = _dir / "control"
				if control.exists():
					self.compare_with_legacy_control_file(control)
				return control_toml

		# Sort custom first
		for _dir in [search_dir] + sorted(opsi_dirs, reverse=True):
			control = _dir / "control"
			if control.exists():
				self.parse_control_file_legacy(control)
				return control

		raise RuntimeError("No control file found.")

	def parse_control_file_legacy(self, control_file: Path) -> None:
		legacy_control_file = LegacyControlFile(control_file)
		if not isinstance(legacy_control_file.product, Product):
			raise ValueError("Could not extract product information from legacy control file.")
		self.product = legacy_control_file.product
		self.product_properties = legacy_control_file.productProperties
		self.product_dependencies = legacy_control_file.productDependencies
		self.package_dependencies = [
			PackageDependency(package=str(pdep["package"]), version=pdep.get("version"), condition=pdep.get("condition"))
			for pdep in legacy_control_file.packageDependencies
		]
		if self.product.changelog:
			self.changelog = self.product.changelog

	def package_archive_name(self) -> str:
		return f"{self.product.id}_{self.product.productVersion}-{self.product.packageVersion}.opsi"

	def generate_control_file_legacy(self, control_file: Path) -> None:
		legacy_control_file = LegacyControlFile()
		legacy_control_file.product = self.product
		legacy_control_file.productDependencies = self.product_dependencies
		legacy_control_file.productProperties = self.product_properties
		legacy_control_file.packageDependencies = [asdict(pdep) for pdep in self.package_dependencies]
		legacy_control_file.generate_control_file(control_file)

	def parse_control_file(self, control_file: Path) -> None:
		if control_file.suffix != ".toml":
			self.parse_control_file_legacy(control_file)
			return

		data_dict = tomlkit.loads(control_file.read_text()).unwrap()
		# changelog key in changelog section... better idea?
		self.changelog = data_dict.get("changelog", {}).get("changelog")
		self.product = create_product(data_dict)
		self.package_dependencies = [
			PackageDependency(package=str(pdep["package"]), version=pdep.get("version"), condition=pdep.get("condition"))
			for pdep in create_package_dependencies(data_dict["Package"].get("depends", []))
		]
		self.product_dependencies = create_product_dependencies(
			data_dict["Product"]["id"],
			data_dict["Product"]["version"],
			data_dict["Package"]["version"],
			data_dict.get("ProductDependency", []),
		)
		self.product_properties = create_product_properties(
			data_dict["Product"]["id"],
			data_dict["Product"]["version"],
			data_dict["Package"]["version"],
			data_dict.get("ProductProperty", []),
		)

	def generate_control_file(self, control_file: Path) -> None:
		if control_file.suffix != ".toml":
			self.generate_control_file_legacy(control_file)
			return

		data_dict = tomlkit.document()

		def _remove_none_values(dictionary: dict) -> dict:
			result = {}
			for key, value in dictionary.items():
				if value:
					result[key] = value
			return result

		data_dict["Package"] = {
			"version": self.product.getPackageVersion(),
			"depends": [_remove_none_values(asdict(pdep)) for pdep in self.package_dependencies],
		}
		data_dict["Product"] = dictify_product(self.product)
		if self.product_properties:
			data_dict["ProductProperty"] = dictify_product_properties(self.product_properties)
		if self.product_dependencies:
			data_dict["ProductDependency"] = dictify_product_dependencies(self.product_dependencies)
		if self.product.getChangelog() is not None:
			(control_file.parent / "changelog.txt").write_text(self.changelog.strip(), encoding="utf-8")
		control_file.write_text(tomlkit.dumps(data_dict))

	# compression zstd, gz or bz2
	def create_package_archive(
		self,
		base_dir: Path,
		compression: Literal["zstd", "bz2", "gz"] = "zstd",
		destination: Path | None = None,
		dereference: bool = False,
		use_dirs: list[Path] | None = None,
		progress_listener: ArchiveProgressListener | None = None,
	) -> Path:
		archives = []
		dirs = use_dirs or [base_dir / "CLIENT_DATA", base_dir / "SERVER_DATA", base_dir / "OPSI"]

		# Prefer OPSI.<custom>
		opsi_dirs = [d for d in sorted(dirs, reverse=True) if d.name.startswith("OPSI")]
		if not opsi_dirs:
			raise ValueError(f"No OPSI directory in '{[d.name for d in dirs]}'")
		opsi_dir = opsi_dirs[0]

		if not opsi_dir.exists():
			raise FileNotFoundError(f"Did not find OPSI directory '{opsi_dir}'")

		self.find_and_parse_control_file(opsi_dir)

		with make_temp_dir(self.temp_dir) as temp_dir:
			for _dir in dirs:
				dir_type = _dir.name.split(".", 1)[0]
				if dir_type not in ("OPSI", "CLIENT_DATA", "SERVER_DATA"):
					logger.warning("Skipping invalid directory '%s'", _dir)

				if not _dir.exists():
					logger.info("Directory '%s' does not exist", _dir)
					continue

				file_list = [
					file
					for file in _dir.iterdir()
					if not EXCLUDE_DIRS_ON_PACK_REGEX.match(file.name) and not EXCLUDE_FILES_ON_PACK_REGEX.match(file.name)
				]

				if not file_list and dir_type in ("CLIENT_DATA", "SERVER_DATA"):
					logger.debug("Skipping empty dir '%s'", _dir)
					continue

				filename = temp_dir / f"{_dir.name}.tar.{compression}"
				logger.info("Creating archive %s", filename)
				create_archive(
					filename,
					file_list,
					base_dir=_dir,
					compression=compression,
					dereference=dereference,
					progress_listener=progress_listener,
				)
				# TODO: progress tracking
				archives.append(filename)

			destination = (destination or Path()).absolute()
			package_archive = destination / self.package_archive_name()
			logger.info("Creating archive %s", package_archive.absolute())
			create_archive(package_archive, archives, temp_dir)
		return package_archive
