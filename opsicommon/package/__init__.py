"""
opsi package class and associated methods
"""

import subprocess
import tempfile
from pathlib import Path
from typing import Any, Generator, Optional

import magicfile as magic  # type: ignore[import]
import packaging.version
import tomlkit

from opsicommon.logging import logger
from opsicommon.objects import (
	BoolProductProperty,
	LocalbootProduct,
	NetbootProduct,
	Product,
	ProductDependency,
	ProductProperty,
	UnicodeProductProperty,
)
from opsicommon.package.legacy_control_file import LegacyControlFile
from opsicommon.types import forceDictList

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


def create_package_dependencies(pdeps: list[dict[str, str | None]]) -> list[dict[str, str | None]]:
	result = []
	for pdep in forceDictList(pdeps):
		if not pdep.get('package'):
			raise ValueError(f"No package given: {pdep}")
		if not pdep.get('version'):
			pdep['version'] = None
			pdep['condition'] = None
		else:
			if not pdep.get('condition'):
				pdep['condition'] = '='
			if pdep['condition'] not in ('=', '<', '<=', '>', '>='):
				raise ValueError(f"Bad condition string '{pdep['condition']}' in package dependency")
		result.append(pdep)
	return result


def create_product_dependencies(pid: str, prod_v: str, pack_v: str, pdeps: list[dict[str, str]]) -> list[ProductDependency]:
	result = []
	for dep in pdeps:
		dependency = ProductDependency(
			pid,
			prod_v,
			pack_v,
			dep["action"],
			dep["requiredProduct"],
			requiredProductVersion=dep.get("requiredProductVersion"),
			requiredPackageVersion=dep.get("requiredPackageVersion"),
			requiredAction=dep.get("requiredAction", "setup"),
			requiredInstallationStatus=dep.get("requiredStatus", "installed"),
			requirementType=dep.get("requirementType", "before"),
		)
		result.append(dependency)
	return result


def create_product_properties(pid: str, prod_v: str, pack_v: str, props: list[dict[str, Any]]) -> list[ProductProperty]:
	result = []
	for prop in props:
		pp_class: type = UnicodeProductProperty
		p_type = str(prop.get("type", "")).lower()
		kwargs: dict[str, Any] = {
			"productId": pid,
			"productVersion": prod_v,
			"packageVersion": pack_v,
			"propertyId": prop.get("name", ""),
			"description": prop.get("description", ""),
			"defaultValues": prop.get("default", []),
		}
		if p_type in ("boolproductproperty", "bool"):
			pp_class = BoolProductProperty
		elif p_type in ("unicodeproductproperty", "unicode", ""):
			kwargs.update({
				"possibleValues": prop.get("values", []),
				"editable": [prop.get("editable", not prop.get("values", []))],
				"multiValue": prop.get("multivalue"),
			})
		else:
			raise ValueError(f"Error in control file: unknown product property type '{prop.get('type')}'")
		result.append(pp_class(**kwargs))
		result[-1].setDefaults()
	return result


def create_product(data_dict: dict[str, Any]) -> Product:
	kwargs: dict[str, Any] = data_dict["Product"].copy()
	if data_dict.get("windows"):
		kwargs["windowsSoftwareIds"] = data_dict.get("windows", {}).get("softwareids", [])
	kwargs["productClassIds"] = data_dict["Product"].get("productClasses")  # But WHY??
	kwargs["changelog"] = data_dict.get("changelog", {}).get("changelog")
	for key in ("id", "version", "type", "productClasses"):
		if key in kwargs:
			kwargs.pop(key)
	print(kwargs)
	if data_dict["Product"]["type"] in ("netboot", "NetbootProduct"):
		return NetbootProduct(data_dict["Product"]["id"], data_dict["Product"]["version"], data_dict["Package"]["version"], **kwargs)
	if data_dict["Product"]["type"] in ("localboot", "LocalbootProduct"):
		return LocalbootProduct(data_dict["Product"]["id"], data_dict["Product"]["version"], data_dict["Package"]["version"], **kwargs)
	raise RuntimeError(f"Unknown opsi package type {data_dict['Product']['type']}")


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
			data_dict.get("ProductDependency", [])
		)
		self.product_properties = create_product_properties(
			data_dict["Product"]["id"],
			data_dict["Product"]["version"],
			data_dict["Package"]["version"],
			data_dict.get("ProductProperty", [])
		)
