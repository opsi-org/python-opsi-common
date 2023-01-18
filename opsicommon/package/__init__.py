"""
opsi package class and associated methods
"""

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
def deserialize(archive: Path, destination: Path, file_pattern: Optional[str] = None) -> Generator[Path, None, None]:
	if archive.suffixes and archive.suffixes[-1] in ("zst", ".gz", ".bzip2"):
		create_input = extract_command(archive)
	else:
		create_input = f"cat {archive}"
	process_archive = deserialize_command(archive, destination, file_pattern=file_pattern)
	subprocess.check_call(f"{create_input} | {process_archive}", shell=True)
	return destination.glob(file_pattern or "*")


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
			content = list(deserialize(package_archive, temp_dir, file_pattern="OPSI.*"))
			if len(content) == 0:
				raise RuntimeError(f"No OPSI directory in archive '{package_archive}'")
			if len(content) > 1:
				raise RuntimeError(f"Multiple OPSI directories in archive '{package_archive}'.")
			content = list(deserialize(content[0], temp_dir, file_pattern="control*"))
			if temp_dir / "control.toml" in content:
				self.parse_control_file(temp_dir / "control.toml")
			elif temp_dir / "control" in content:
				self.parse_control_file_legacy(temp_dir / "control")
			else:
				raise RuntimeError(f"No control file in package archive '{package_archive}'")

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
