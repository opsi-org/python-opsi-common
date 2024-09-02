# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
opsi package class and associated methods
"""

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal, cast

import tomlkit

from opsicommon.logging import get_logger
from opsicommon.objects import Product, ProductDependency, ProductProperty
from opsicommon.package.archive import (
	ArchiveFile,
	ArchiveProgress,
	ArchiveProgressListener,
	create_archive,
	extract_archive,
	get_archive_files,
)
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

PACKAGE_DIR_TYPES = Literal["OPSI", "CLIENT_DATA", "SERVER_DATA"]

logger = get_logger("opsicommon.package")


def package_data_from_archive(archive: Path) -> dict[str, str]:
	"""
	Extracts product id, product version and package version from a package archive.
	"""
	parts = archive.stem.split("_")
	return {
		"id": "_".join(parts[:-1]),
		"productVersion": parts[-1].split("-")[0],
		"packageVersion": parts[-1].split("-")[1],
	}


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
		self,
		package_archive: Path,
		destination: Path,
		*,
		new_product_id: str | None = None,
		custom_separated: bool = False,
		progress_listener: ArchiveProgressListener | None = None,
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
				extract_archive(
					archive,
					destination / folder_name,
					progress_listener=progress_listener,
				)

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

	def compare_version_with_control_file(self, control_file: Path, condition: Literal["==", "=", "<", "<=", ">", ">="]) -> bool:
		opsi_package = OpsiPackage()
		if control_file.suffix == ".toml":
			opsi_package.parse_control_file(control_file)
		else:
			opsi_package.parse_control_file_legacy(control_file)

		if not opsi_package.product.version or not self.product.version:
			raise ValueError("Version information for comparison is missing")

		return compare_versions(opsi_package.product.version, condition, self.product.version)

	def find_and_parse_control_file(self, search_dir: Path) -> Path:
		opsi_dirs = []
		for _dir in search_dir.glob("OPSI*"):
			if _dir.is_dir() and (_dir.name == "OPSI" or _dir.name.startswith("OPSI.")):
				opsi_dirs.append(_dir)

		# Sort custom first
		for _dir in [search_dir] + sorted(opsi_dirs, reverse=True):
			control_toml = _dir / "control.toml"
			control = _dir / "control"
			if control_toml.exists():
				self.parse_control_file(control_toml)
				if control.exists() and self.compare_version_with_control_file(control, ">"):
					raise RuntimeError("Control file is newer. Please update the control.toml file.")
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

	def package_archive_name(self, custom_name: str | None = None) -> str:
		if custom_name:
			return f"{self.product.id}_{self.product.productVersion}-{self.product.packageVersion}~{custom_name}.opsi"
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

	def get_dirs(self, base_dir: Path, custom_name: str | None, custom_only: bool) -> dict[PACKAGE_DIR_TYPES, list[Path]]:
		"""
		Returning a dictionary containing directory types as keys and a list of directory paths as values.
		The order of the paths matters, because custom dirs have precedence.
		"""
		if custom_only and not custom_name:
			raise ValueError("custom_only requires custom_name to be set.")

		dirs: dict[PACKAGE_DIR_TYPES, list[Path]] = {}
		custom_dirs = 0
		possible_control_dirs = []
		dir_names_found = []
		for extension in (f".{custom_name}", ""):
			possible_control_dirs.append(f"OPSI{extension}")
			for dir_type_str in ("OPSI", "CLIENT_DATA", "SERVER_DATA"):
				dir_path = base_dir / f"{dir_type_str}{extension}"
				if dir_path.is_dir():
					dir_type = cast(PACKAGE_DIR_TYPES, dir_type_str)
					dir_names_found.append(dir_path.name)
					cur_dir_paths = dirs.get(dir_type, [])
					if not extension and custom_only:
						# With custom only the default CLIENT_DATA and SERVER_DATA directories are skipped
						# The default OPSI directory must only be used if no custom directory is found
						if cur_dir_paths or dir_type_str != "OPSI":
							continue
					dirs[dir_type] = cur_dir_paths + [dir_path]
					if extension:
						custom_dirs += 1

		if custom_name and not custom_dirs:
			raise RuntimeError(
				f"No directories matching custom name '{custom_name}' found in '{base_dir}', available directories: {dir_names_found}"
			)

		if not dirs.get("OPSI"):
			custom_dir_text = " and ".join(possible_control_dirs)
			raise RuntimeError(f"{custom_dir_text} directory not found in '{base_dir}', available directories: {dir_names_found}")

		return dirs

	# compression zstd, gz or bz2
	def create_package_archive(
		self,
		base_dir: Path,
		*,
		compression: Literal["zstd", "bz2", "gz"] = "zstd",
		destination: Path | None = None,
		dereference: bool = False,
		custom_name: str | None = None,
		custom_only: bool = False,
		progress_listener: ArchiveProgressListener | None = None,
		overwrite: bool = True,
		create_missing_legacy_control_file: bool = True,
		create_missing_toml_control_file: bool = False,
	) -> Path:
		dirs = self.get_dirs(base_dir, custom_name, custom_only)
		opsi_dir = dirs["OPSI"][0]
		primary_control_file = self.find_and_parse_control_file(opsi_dir)

		destination = (destination or Path()).absolute()
		package_archive = destination / self.package_archive_name(custom_name)
		if not overwrite and package_archive.exists():
			raise FileExistsError(f"Package archive '{package_archive}' already exists.")

		primary_is_toml = primary_control_file.suffix == ".toml"
		secondary_control_file = primary_control_file.parent / ("control" if primary_is_toml else "control.toml")
		if (
			secondary_control_file.exists()  # Update existing control file
			or (primary_is_toml and create_missing_legacy_control_file)  # Create missing legacy control file
			or (not primary_is_toml and create_missing_toml_control_file)  # Create missing toml control file
		):
			logger.info("Creating '%s'", secondary_control_file)
			generate_func = self.generate_control_file_legacy if primary_is_toml else self.generate_control_file
			generate_func(secondary_control_file)

		class ProgressAdapter(ArchiveProgressListener):
			def __init__(self, progress_listener: ArchiveProgressListener) -> None:
				self.progress_listener = progress_listener
				self.progresses: dict[int, ArchiveProgress] = {}
				self.overall_progress = ArchiveProgress()
				self.total: int | None = None

			def _update_overall_progress(self) -> None:
				self.overall_progress.total = self.total if self.total is not None else sum(p.total for p in self.progresses.values())
				self.overall_progress.set_completed(sum(p.completed for p in self.progresses.values()))
				self.progress_listener.progress_changed(self.overall_progress)

			def set_total(self, total: int | None, fire_event: bool = True) -> None:
				self.total = total
				if fire_event:
					self._update_overall_progress()

			def progress_changed(self, progress: ArchiveProgress) -> None:
				progress_id = id(progress)
				if progress_id not in self.progresses:
					self.progresses[progress_id] = progress
				self._update_overall_progress()

		archives = []
		files_by_archive_name: dict[str, list[ArchiveFile]] = {}
		for dir_type, dir_paths in dirs.items():
			for dir_path in dir_paths:
				archive_files = list(get_archive_files(dir_path, follow_symlinks=not dereference))
				if not archive_files and dir_type in ("CLIENT_DATA", "SERVER_DATA"):
					logger.debug("Skipping empty dir '%s'", dir_path)
					continue
				files_by_archive_name[dir_path.name] = archive_files

		progress_adapter: ProgressAdapter | None = None
		if progress_listener:
			progress_adapter = ProgressAdapter(progress_listener)
			total_size = sum(f.size for fs in files_by_archive_name.values() for f in fs)
			progress_adapter.set_total(total_size * 2)  # Estimated

		with make_temp_dir(self.temp_dir) as temp_dir:
			for dir_name, files in files_by_archive_name.items():
				archive = temp_dir / f"{dir_name}.tar.{compression}"
				logger.info("Creating archive '%s'", archive)
				create_archive(
					archive,
					files,
					compression=compression,
					dereference=dereference,
					progress_listener=progress_adapter,
				)
				archives.append(ArchiveFile(path=archive, size=archive.stat().st_size, archive_path=Path("/") / archive.name))

			logger.info("Creating archive '%s'", package_archive.absolute())
			if progress_adapter:
				progress_adapter.set_total(None, False)
			create_archive(package_archive, archives, progress_listener=progress_adapter)

		return package_archive
