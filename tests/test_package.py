"""
tests for opsicommon.package
"""

import shutil
import tempfile
from pathlib import Path

import pytest

from opsicommon.objects import NetbootProduct
from opsicommon.package import OpsiPackage

TEST_DATA = Path("tests") / "data" / "package"


def print_info(package: OpsiPackage) -> None:
	print(package.product)
	print(package.product_properties)
	print(package.product_dependencies)
	print(package.package_dependencies)


@pytest.mark.linux
def test_load_control_toml() -> None:
	package = OpsiPackage()
	package.parse_control_file(TEST_DATA / "control.toml")
	print_info(package)
	assert package.product
	assert package.product.id == "prod-1750"
	assert package.product.name == "Control file with path"
	assert package.product.productVersion == "1.0"
	assert package.product.packageVersion == "1"
	assert len(package.product_properties) == 2
	for prop in package.product_properties:
		if prop.propertyId == "adminaccounts":
			assert prop.description == "Windows account(s) to provision as administrators."
			assert prop.multiValue is False
			assert prop.editable is True
			assert prop.defaultValues == ["Administrator"]
			assert prop.possibleValues
			assert set(prop.possibleValues) == {"Administrator", "domain.local\\Administrator", "BUILTIN\\ADMINISTRATORS"}
		elif prop.propertyId != "target_path":
			raise ValueError(f"Did not expect proeprtyId {prop.propertyId}")

	assert len(package.product_dependencies) == 1
	assert package.product_dependencies[0].productAction == "setup"
	assert package.product_dependencies[0].requiredProductId == "l-system-update"
	assert package.product_dependencies[0].requiredAction == "setup"
	assert package.product_dependencies[0].requirementType == "before"


@pytest.mark.linux
@pytest.mark.parametrize(
	"product_type, form",
	(
		("localboot", "legacy"),
		("localboot", "new"),
		("netboot", "legacy"),
		("netboot", "new"),
	),
)
def test_load_package(product_type: str, form: str) -> None:
	package = OpsiPackage(TEST_DATA / f"{product_type}_{form}_42.0-1337.opsi")
	print_info(package)
	assert package.product.id == f"{product_type}_{form}"
	assert package.product.name == f"{product_type} {form}"
	assert package.product.description == f"this is a {product_type} {form} test package"
	assert package.product.advice == "use the new one"
	assert package.product.productVersion == "42.0"
	assert package.product.packageVersion == "1337"
	assert not package.product.licenseRequired
	assert package.product.priority == 0
	if isinstance(package.product, NetbootProduct):
		assert package.product.pxeConfigTemplate == "install3264"
	assert len(package.product_properties) == 2
	for prop in package.product_properties:
		if prop.propertyId == "propname":
			assert prop.description == "this is a dummy property"
			assert prop.multiValue is False
			assert prop.editable is True
			assert prop.defaultValues == ["a"]
			assert prop.possibleValues
			assert set(prop.possibleValues) == {"a", "b"}
		elif prop.propertyId == "boolprop":
			assert prop.description == "this is a bool property"
			assert prop.multiValue is False
			assert prop.editable is False
			assert prop.defaultValues == [False]
			assert prop.possibleValues
			assert set(prop.possibleValues) == {True, False}
		else:
			raise ValueError(f"Did not expect proeprtyId {prop.propertyId}")
	assert len(package.product_dependencies) == 1
	assert package.product_dependencies[0].productAction == "setup"
	assert package.product_dependencies[0].requiredProductId == "hwaudit"
	assert package.product_dependencies[0].requiredAction == "setup"
	assert package.product_dependencies[0].requiredInstallationStatus == "installed"
	assert package.product_dependencies[0].requirementType == "before"


@pytest.mark.linux
def test_extract_package() -> None:
	with tempfile.TemporaryDirectory() as temp_dir_name:
		temp_dir = Path(temp_dir_name)
		OpsiPackage.extract_package_archive(TEST_DATA / "localboot_legacy_42.0-1337.opsi", temp_dir)
		contents = list(temp_dir.rglob("*"))
	for _file in (
		temp_dir / "OPSI" / "control",
		temp_dir / "OPSI" / "preinst",
		temp_dir / "OPSI" / "postinst",
		temp_dir / "CLIENT_DATA" / "setup.opsiscript",
	):
		assert _file in contents


@pytest.mark.linux
@pytest.mark.parametrize(
	"compression",
	("zstd", "bzip2"),
)
def test_create_package(compression: str) -> None:
	package = OpsiPackage()
	with tempfile.TemporaryDirectory() as temp_dir_name:
		temp_dir = Path(temp_dir_name)
		for _dir in (temp_dir / "OPSI", temp_dir / "CLIENT_DATA", temp_dir / "SERVER_DATA"):
			_dir.mkdir()
			shutil.copy(TEST_DATA / "control.toml", _dir)
		package_archive = package.create_package_archive(temp_dir, compression=compression, destination=temp_dir)
		with tempfile.TemporaryDirectory() as result_dir_name:
			result_dir = Path(result_dir_name)
			OpsiPackage.extract_package_archive(package_archive, result_dir)
			result_contents = list((_dir.relative_to(result_dir) for _dir in result_dir.rglob("*")))
			for part in ("OPSI", "CLIENT_DATA", "SERVER_DATA"):
				assert (temp_dir / part).relative_to(temp_dir) in result_contents
