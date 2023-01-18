"""
opsi package class and associated methods
"""

import re
import subprocess
import tempfile
from pathlib import Path
from typing import Generator, Optional

import magicfile as magic  # type: ignore[import]
import packaging.version
import tomlkit

from opsicommon.logging import logger
from opsicommon.objects import Product, ProductDependency, ProductProperty
from opsicommon.package.control_file_handling import (
	create_package_dependencies,
	create_product,
	create_product_dependencies,
	create_product_properties,
)
from opsicommon.package.legacy_control_file import LegacyControlFile

CPIO_COMMAND = "cpio -u --extract --quiet --no-preserve-owner --no-absolute-filenames"
TAR_COMMAND = "tar xf - --wildcards"
EXCLUDE_DIRS_ON_PACK_REGEX = re.compile(r"(^\.svn$)|(^\.git$)")
EXCLUDE_FILES_ON_PACK_REGEX = re.compile(r"(~$)|(^[Tt]humbs\.db$)|(^\.[Dd][Ss]_[Ss]tore$)")


def pigz_available() -> bool:
	try:  # TODO: check if configured to use pigz? in opsiconf
		pigz_version = subprocess.check_output("pigz --version", shell=True).decode("utf-8")
		if packaging.version.parse(pigz_version) < packaging.version.parse("2.2.3"):
			raise ValueError("pigz too old")
		return True
	except (subprocess.CalledProcessError, ValueError):
		return False


def deserialize_command(archive: Path, destination: Path, file_pattern: Optional[str] = None) -> str:
	# Look for cpio and tar in last or second last position (for compressed archives like .tar.gz)
	# It is assumed that the deserialize command gets data via stdin in an uncompressed way
	if archive.suffixes and ".cpio" in archive.suffixes[-2:]:
		cmd = f"{CPIO_COMMAND} --directory {destination}"
	elif archive.suffixes and ".tar" in archive.suffixes[-2:]:
		cmd = f"{TAR_COMMAND} --directory {destination}"
	else:
		magic_string = magic.from_file(str(archive))
		if "cpio archive" in magic_string:
			cmd = f"{CPIO_COMMAND} --directory {destination}"
		elif "tar archive" in magic_string:
			cmd = f"{TAR_COMMAND} --directory {destination}"
		else:
			raise TypeError(f"Archive to deserialize must be 'tar' or 'cpio', found: {magic_string}")
	if file_pattern:
		cmd += f" '{file_pattern}'"
	return cmd


def extract_command(archive: Path) -> str:
	if archive.suffix in (".gzip", ".gz"):
		if pigz_available():
			cmd = f"pigz --stdout --decompress '{archive}'"
		else:
			cmd = f"zcat --stdout --decompress '{archive}'"
	elif archive.suffix in (".bzip2", "bz2"):
		cmd = f"bzcat --stdout --decompress '{archive}'"
	elif archive.suffix == ".zstd":
		try:
			subprocess.check_call("zstdcat --version", shell=True)
		except subprocess.CalledProcessError as error:
			raise RuntimeError("Zstd not available.") from error
		cmd = f"zstdcat --stdout --decompress '{archive}'"
	else:
		raise RuntimeError(f"Unknown compression of file '{archive}'")
	return cmd


# Warning: this is specific for linux!
def deserialize(archive: Path, destination: Path, file_pattern: Optional[str] = None) -> None:
	if archive.suffixes and archive.suffixes[-1] in ("zst", ".gz", ".bzip2"):
		create_input = extract_command(archive)
	else:
		create_input = f"cat {archive}"
	process_archive = deserialize_command(archive, destination, file_pattern=file_pattern)
	subprocess.check_call(f"{create_input} | {process_archive}", shell=True)


class OpsiPackage:
	"""
	Basic class for opsi packages.
	"""

	def __init__(self, package_archive: Optional[Path] = None) -> None:
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
		content = list(base_dir.iterdir())  # IDEA: glob for specific patterns?
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

	# compression zstd or bz2
	def create_package_archive(self, base_dir: Path, compression: str = "zstd") -> Path:
		self.find_and_parse_control_file(base_dir)

		archives = []
		dirs = [base_dir / "CLIENT_DATA", base_dir / "SERVER_DATA", base_dir / "OPSI"]
		if not (base_dir / "OPSI").exists():
			raise FileNotFoundError(f"Did not find OPSI directory at {base_dir}")
		dereference = False  # do not follow symlinks by default.

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
					logger.notice("Skipping empty dir '%s'", _dir)
					continue
				filename = temp_dir / f"{_dir.name}.tar.{compression}"
				archive = Archive(filename, format=self.format, compression=self.compression, progressSubject=progressSubject)
				# TODO: progress tracking
				logger.info("Creating archive %s", filename)
				archive.create(fileList=fileList, baseDir=os.path.join(self.packageSourceDir, _dir), dereference=dereference)
				archives.append(filename)

			archive = Archive(self.packageFile, format=self.format, compression=None, progressSubject=progressSubject)
			logger.info("Creating archive %s", archive)
			archive.create(fileList=archives, baseDir=self.tmpPackDir)
			return archive.getFilename()
