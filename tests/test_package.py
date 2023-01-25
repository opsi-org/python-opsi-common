"""
tests for opsicommon.package
"""

from pathlib import Path
from shutil import copy

import pytest

from opsicommon.objects import NetbootProduct
from opsicommon.package import OpsiPackage
from opsicommon.utils import make_temp_dir

TEST_DATA = Path("tests") / "data" / "package"


def print_info(package: OpsiPackage) -> None:
	print(package.product)
	print(package.product_properties)
	print(package.product_dependencies)
	print(package.package_dependencies)


@pytest.mark.parametrize(
	"form",
	("legacy", "new"),
)
def test_load_control(form: str) -> None:
	package = OpsiPackage()
	if form == "legacy":
		package.parse_control_file_legacy(TEST_DATA / "control")
	elif form == "new":
		package.parse_control_file(TEST_DATA / "control.toml")
	print_info(package)
	assert package.product.id == "localboot_new"
	assert package.product.name == "localboot new"
	assert package.product.description == "this is a localboot new test package"
	assert package.product.advice == "use the new one"
	assert package.product.productVersion == "42.0"
	assert package.product.packageVersion == "1337"
	assert not package.product.licenseRequired
	assert package.product.priority == 0
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
			raise ValueError(f"Did not expect propertyId {prop.propertyId}")
	assert len(package.product_dependencies) == 1
	assert package.product_dependencies[0].productAction == "setup"
	assert package.product_dependencies[0].requiredProductId == "hwaudit"
	assert package.product_dependencies[0].requiredAction == "setup"
	assert package.product_dependencies[0].requiredInstallationStatus == "installed"
	assert package.product_dependencies[0].requirementType == "before"


@pytest.mark.parametrize(
	("source", "destination"),
	(
		("legacy", "legacy"),
		("legacy", "new"),
		("new", "legacy"),
		("new", "new"),
	),
)
def test_generate_control(source: str, destination: str) -> None:
	package = OpsiPackage()
	if source == "new":
		control_file = TEST_DATA / "control.toml"
		package.parse_control_file(control_file)
	elif source == "legacy":
		control_file = TEST_DATA / "control"
		package.parse_control_file_legacy(control_file)
	with make_temp_dir() as temp_dir:
		if destination == "new":
			package.generate_control_file(temp_dir / "control.toml")
		elif destination == "legacy":
			package.generate_control_file_legacy(temp_dir / "control")
		regenerated_package = OpsiPackage()
		if destination == "new":
			regenerated_package.parse_control_file(temp_dir / "control.toml")
		elif destination == "legacy":
			regenerated_package.parse_control_file_legacy(temp_dir / "control")
	assert package.product == regenerated_package.product
	assert package.package_dependencies == regenerated_package.package_dependencies
	assert package.product_dependencies == regenerated_package.product_dependencies
	assert package.product_properties == regenerated_package.product_properties


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
			raise ValueError(f"Did not expect propertyId {prop.propertyId}")
	assert len(package.product_dependencies) == 1
	assert package.product_dependencies[0].productAction == "setup"
	assert package.product_dependencies[0].requiredProductId == "hwaudit"
	assert package.product_dependencies[0].requiredAction == "setup"
	assert package.product_dependencies[0].requiredInstallationStatus == "installed"
	assert package.product_dependencies[0].requirementType == "before"


@pytest.mark.linux
@pytest.mark.parametrize(
	"new_product_id",
	(None, "newproductid"),
)
def test_extract_package(new_product_id: str | None) -> None:
	with make_temp_dir() as temp_dir:
		OpsiPackage().extract_package_archive(TEST_DATA / "localboot_legacy_42.0-1337.opsi", temp_dir, new_product_id=new_product_id)
		contents = list(temp_dir.rglob("*"))
		for _file in (
			temp_dir / "OPSI" / "control",
			temp_dir / "OPSI" / "preinst",
			temp_dir / "OPSI" / "postinst",
			temp_dir / "CLIENT_DATA" / "setup.opsiscript",
		):
			assert _file in contents
			result = OpsiPackage()
			result.find_and_parse_control_file(temp_dir)
			assert result.product.id == "newproductid" if new_product_id else "localboot_legacy"


@pytest.mark.linux
@pytest.mark.parametrize(
	"compression",
	("zstd", "bzip2"),
)
def test_create_package(compression: str) -> None:
	package = OpsiPackage()
	test_data = TEST_DATA / "control.toml"
	with make_temp_dir() as temp_dir:
		for _dir in (temp_dir / "OPSI", temp_dir / "CLIENT_DATA", temp_dir / "SERVER_DATA"):
			_dir.mkdir()
			copy(test_data, _dir)
		package_archive = package.create_package_archive(temp_dir, compression=compression, destination=temp_dir)
		with make_temp_dir() as result_dir:
			OpsiPackage().extract_package_archive(package_archive, result_dir)
			result_contents = list((_dir.relative_to(result_dir) for _dir in result_dir.rglob("*")))
			for part in ("OPSI", "CLIENT_DATA", "SERVER_DATA"):
				assert (temp_dir / part).relative_to(temp_dir) in result_contents
