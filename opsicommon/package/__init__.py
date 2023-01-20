"""
opsi package class and associated methods
"""

import re
import tempfile
from pathlib import Path

import tomlkit

from opsicommon.logging import logger
from opsicommon.objects import Product, ProductDependency, ProductProperty
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
from opsicommon.package.serialization import deserialize, serialize

EXCLUDE_DIRS_ON_PACK_REGEX = re.compile(r"(^\.svn$)|(^\.git$)")
EXCLUDE_FILES_ON_PACK_REGEX = re.compile(r"(~$)|(^[Tt]humbs\.db$)|(^\.[Dd][Ss]_[Ss]tore$)")


class OpsiPackage:
	"""
	Basic class for opsi packages.
	"""

	@classmethod
	def extract_package_archive(cls, package_archive: Path, destination: Path) -> None:
		with tempfile.TemporaryDirectory() as temp_dir_name:
			temp_dir = Path(temp_dir_name)
			logger.debug("Deserializing archive %s", package_archive)
			deserialize(package_archive, temp_dir)
			for archive in temp_dir.iterdir():
				deserialize(archive, destination / archive.name.split(".")[0])

	def __init__(self, package_archive: Path | None = None) -> None:
		self.product: Product
		self.product_properties: list[ProductProperty] = []
		self.product_dependencies: list[ProductDependency] = []
		self.package_dependencies: list[dict[str, str | None]] = []
		self.changelog: str = ""
		if package_archive:
			self.from_package_archive(package_archive)

	def from_package_archive(self, package_archive: Path) -> None:
		with tempfile.TemporaryDirectory() as temp_dir_name:
			temp_dir = Path(temp_dir_name)
			logger.debug("Deserializing archive %s", package_archive)
			deserialize(package_archive, temp_dir, file_pattern="OPSI.*")
			content = list(temp_dir.glob("OPSI.*"))
			if len(content) == 0:
				raise RuntimeError(f"No OPSI directory in archive '{package_archive}'")
			if len(content) > 1:
				raise RuntimeError(f"Multiple OPSI directories in archive '{package_archive}'.")
			deserialize(content[0], temp_dir, file_pattern="control*")
			self.find_and_parse_control_file(temp_dir)

	def find_and_parse_control_file(self, base_dir: Path) -> None:
		content = list(base_dir.rglob("control*"))
		for path in (base_dir / "control.toml", base_dir / "OPSI" / "control.toml"):
			if path in content:
				self.parse_control_file(path)
				return
		for path in (base_dir / "control", base_dir / "OPSI" / "control"):
			if path in content:
				self.parse_control_file_legacy(path)
				return
		raise RuntimeError("No control file found.")

	def parse_control_file_legacy(self, control_file: Path) -> None:
		legacy_control_file = LegacyControlFile(control_file)
		if not isinstance(legacy_control_file.product, Product):
			raise ValueError("Could not extract Product information from old control file.")
		self.product = legacy_control_file.product
		self.product_properties = legacy_control_file.productProperties
		self.product_dependencies = legacy_control_file.productDependencies
		self.package_dependencies = legacy_control_file.packageDependencies

	def generate_control_file_legacy(self, control_file: Path) -> None:
		legacy_control_file = LegacyControlFile()
		legacy_control_file.product = self.product
		legacy_control_file.productDependencies = self.product_dependencies
		legacy_control_file.productProperties = self.product_properties
		legacy_control_file.packageDependencies = self.package_dependencies
		legacy_control_file.generate_control_file(control_file)

	def parse_control_file(self, control_file: Path) -> None:
		data_dict = tomlkit.loads(control_file.read_text()).unwrap()
		# changelog key in changelog section... better idea?
		self.changelog = data_dict.get("changelog", {}).get("changelog")
		self.product = create_product(data_dict)
		self.package_dependencies = create_package_dependencies(data_dict["Package"].get("depends", []))
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

	def generate_control_file(self, control_file: Path) -> None:  # IDEA: assert .toml here? or only specify dir?
		data_dict = tomlkit.document()
		data_dict["Package"] = {
			"version": self.product.getPackageVersion(),
			"depends": self.package_dependencies,
		}
		data_dict["Product"] = dictify_product(self.product)
		if self.product_properties:
			data_dict["ProductProperty"] = dictify_product_properties(self.product_properties)
		if self.product_dependencies:
			data_dict["ProductDependency"] = dictify_product_dependencies(self.product_dependencies)
		if self.product.getChangelog() is not None:
			(control_file.parent / "changelog.txt").write_text(self.changelog.strip(), encoding="utf-8")
		control_file.write_text(tomlkit.dumps(data_dict))

	# compression zstd or bz2
	def create_package_archive(self, base_dir: Path, compression: str = "zstd", destination: Path = Path()) -> Path:
		self.find_and_parse_control_file(base_dir)

		archives = []
		dirs = [base_dir / "CLIENT_DATA", base_dir / "SERVER_DATA", base_dir / "OPSI"]
		if not (base_dir / "OPSI").exists():
			raise FileNotFoundError(f"Did not find OPSI directory at {base_dir}")
		# TODO: option to follow symlinks.

		with tempfile.TemporaryDirectory() as temp_dir_name:
			temp_dir = Path(temp_dir_name)
			# TODO: customName stuff?
			"""
			if self.customName:
				found = False
				for i, currentDir in enumerate(dirs):
					customDir = f"{currentDir}.{self.customName}"
					if os.path.exists(os.path.join(self.packageSourceDir, customDir)):
						found = True
						if self.customOnly:
							dirs[i] = customDir
						else:
							dirs.append(customDir)
				if not found:
					raise RuntimeError(f"No custom dirs found for '{self.customName}'")
			"""
			for _dir in dirs:
				if not _dir.exists():
					logger.info("Directory '%s' does not exist", _dir)
					continue
				file_list = [  # TODO: behaviour for symlinks
					file
					for file in _dir.iterdir()
					if not EXCLUDE_DIRS_ON_PACK_REGEX.match(file.name) and not EXCLUDE_FILES_ON_PACK_REGEX.match(file.name)
				]
				# TODO: SERVER_DATA stuff
				"""
				if _dir.startswith("SERVER_DATA"):
					# Never change permissions of existing directories in /
					tmp = []
					for file in fileList:
						if file.find(os.sep) == -1:
							logger.info("Skipping dir '%s'", file)
							continue
						tmp.append(file)

					fileList = tmp
				"""
				if not file_list:
					logger.debug("Skipping empty dir '%s'", _dir)
					continue
				filename = temp_dir / f"{_dir.name}.tar.{compression}"
				logger.info("Creating archive %s", filename)
				serialize(filename, [_dir], base_dir, compression=compression)
				# TODO: progress tracking
				archives.append(filename)

			package_archive = destination / f"{self.product.id}_{self.product.productVersion}-{self.product.packageVersion}.opsi"
			logger.info("Creating archive %s", package_archive)
			serialize(package_archive, archives, temp_dir)
		return package_archive
