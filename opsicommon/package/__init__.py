"""
opsi package class and associated methods
"""

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

import tomlkit

from opsicommon.logging import get_logger
from opsicommon.objects import Product, ProductDependency, ProductProperty
from opsicommon.package.archive import (
	create_archive_universal,
	extract_archive_universal,
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
from opsicommon.utils import make_temp_dir

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

	def extract_package_archive(self, package_archive: Path, destination: Path, new_product_id: str | None = None) -> None:
		with make_temp_dir(self.temp_dir) as temp_dir:
			logger.debug("Extracting archive %s", package_archive)
			extract_archive_universal(package_archive, temp_dir)
			for archive in temp_dir.iterdir():
				archive_name = archive.name
				while archive_name.endswith((".zstd", ".gz", ".bz2", ".cpio", ".tar")):
					archive_name = ".".join(archive_name.split(".")[:-1])  # allow CLIENT_DATA.custom
				extract_archive_universal(archive, destination / archive_name)
		control_file = self.find_and_parse_control_file(destination / archive_name)
		if new_product_id:
			self.product.setId(new_product_id)
			self.generate_control_file(control_file)

	def from_package_archive(self, package_archive: Path) -> None:
		with make_temp_dir(self.temp_dir) as temp_dir:
			logger.debug("Extracting archive %s", package_archive)
			extract_archive_universal(package_archive, temp_dir, file_pattern="OPSI.*")
			content = list(temp_dir.glob("OPSI.*"))
			if len(content) == 0:
				raise RuntimeError(f"No OPSI directory in archive '{package_archive}'")
			if len(content) > 1:
				raise RuntimeError(f"Multiple OPSI directories in archive '{package_archive}'.")
			extract_archive_universal(content[0], temp_dir, file_pattern="control*")  # or OPSI? difference tar and cpio
			self.find_and_parse_control_file(temp_dir)

	def find_and_parse_control_file(self, base_dir: Path) -> Path:
		content = list(base_dir.rglob("control*"))
		for path in (base_dir / "control.toml", base_dir / "OPSI" / "control.toml"):
			if path in content:
				self.parse_control_file(path)
				return path
		for path in (base_dir / "control", base_dir / "OPSI" / "control"):
			if path in content:
				self.parse_control_file_legacy(path)
				return path
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
		data_dict["Package"] = {
			"version": self.product.getPackageVersion(),
			"depends": [asdict(pdep) for pdep in self.package_dependencies],
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
	def create_package_archive(  # pylint: disable=too-many-arguments
		self,
		base_dir: Path,
		compression: Literal["zstd", "bz2", "gz"] = "zstd",
		destination: Path | None = None,
		dereference: bool = False,
		use_dirs: list[Path] | None = None,
	) -> Path:
		self.find_and_parse_control_file(base_dir)

		archives = []
		dirs = use_dirs or [base_dir / "CLIENT_DATA", base_dir / "SERVER_DATA", base_dir / "OPSI"]
		if not (base_dir / "OPSI").exists():
			raise FileNotFoundError(f"Did not find OPSI directory at '{base_dir}'")

		with make_temp_dir(self.temp_dir) as temp_dir:
			for _dir in dirs:
				if not _dir.exists():
					logger.info("Directory '%s' does not exist", _dir)
					continue
				file_list = [  # TODO: behaviour for symlinks
					file
					for file in _dir.iterdir()
					if not EXCLUDE_DIRS_ON_PACK_REGEX.match(file.name) and not EXCLUDE_FILES_ON_PACK_REGEX.match(file.name)
				]
				# TODO: SERVER_DATA stuff - restrict to only /tftpboot?
				# TODO: what is the right instance to enforce this?
				# if _dir.name == "SERVER_DATA":
				# 	# Never change permissions of existing directories in / ???
				# 	tmp = []
				# 	for file in fileList:
				# 		if str(file).find(os.sep) == -1:
				# 			logger.info("Skipping dir '%s'", file)
				# 			continue
				# 		tmp.append(file)
				# 	fileList = tmp

				if not file_list and _dir.name not in ("CLIENT_DATA", "OPSI"):
					logger.debug("Skipping empty dir '%s'", _dir)
					continue
				filename = temp_dir / f"{_dir.name}.tar.{compression}"
				logger.info("Creating archive %s", filename)
				create_archive_universal(filename, file_list, base_dir=_dir, compression=compression, dereference=dereference)
				# TODO: progress tracking
				archives.append(filename)

			destination = (destination or Path()).absolute()
			package_archive = destination / self.package_archive_name()
			logger.info("Creating archive %s", package_archive.absolute())
			create_archive_universal(package_archive, archives, temp_dir)
		return package_archive
