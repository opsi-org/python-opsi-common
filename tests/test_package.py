"""
tests for opsicommon.package
"""

from os import symlink
from pathlib import Path
from shutil import copy
from typing import Literal

import pytest

from opsicommon.objects import NetbootProduct
from opsicommon.package import OpsiPackage
from opsicommon.package.associated_files import (
	create_package_content_file,
	create_package_md5_file,
	create_package_zsync_file,
)
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


@pytest.mark.parametrize(
	"compression",
	("zstd", "bz2"),
)
def test_create_package(compression: Literal["zstd", "bz2"]) -> None:
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
			print(result_contents)
			for part in ("OPSI", "CLIENT_DATA", "SERVER_DATA"):
				assert (temp_dir / part).relative_to(temp_dir) in result_contents
				assert (temp_dir / part / "control.toml").relative_to(temp_dir) in result_contents


@pytest.mark.linux
@pytest.mark.parametrize(
	"dereference",
	(False, True),
)
def test_create_package_link_handing(dereference: bool) -> None:
	package = OpsiPackage()
	test_data = TEST_DATA / "control.toml"
	with make_temp_dir() as temp_dir:
		for _dir in (temp_dir / "OPSI", temp_dir / "CLIENT_DATA", temp_dir / "SERVER_DATA"):
			_dir.mkdir()
			copy(test_data, _dir)
		symlink(temp_dir / "CLIENT_DATA" / "control.toml", temp_dir / "CLIENT_DATA" / "control.link")
		symlink(Path("/etc/hostname"), temp_dir / "CLIENT_DATA" / "link_pointing_outside")
		package_archive = package.create_package_archive(temp_dir, destination=temp_dir, dereference=dereference)
		with make_temp_dir() as result_dir:
			OpsiPackage().extract_package_archive(package_archive, result_dir)
			if dereference:
				assert not (result_dir / "CLIENT_DATA" / "control.link").is_symlink()
				assert not (result_dir / "CLIENT_DATA" / "link_pointing_outside").is_symlink()
			else:
				assert (result_dir / "CLIENT_DATA" / "control.link").is_symlink()
				assert (result_dir / "CLIENT_DATA" / "link_pointing_outside").is_symlink()


def test_create_package_content_file() -> None:
	test_data = TEST_DATA / "control.toml"
	with make_temp_dir() as temp_dir:
		(temp_dir / "testpackage").mkdir()
		copy(test_data, temp_dir / "testpackage")
		(temp_dir / "testpackage" / "testdir").mkdir()
		copy(test_data, temp_dir / "testpackage" / "testdir")
		content_file = create_package_content_file(temp_dir / "testpackage")
		result = content_file.read_text(encoding="utf-8")
	for entry in (
		"d 'testdir' 0",
		"f 'control.toml' 1132 f96f9b2343dceec972682b06f43cd1e7",
		"f 'testdir/control.toml' 1132 f96f9b2343dceec972682b06f43cd1e7",
	):
		assert entry in result


def test_create_package_md5_file() -> None:
	with make_temp_dir() as temp_dir:
		result = temp_dir / "localboot_new_42.0-1337.opsi.md5"
		create_package_md5_file(TEST_DATA / "localboot_new_42.0-1337.opsi", filename=result)
		assert result.read_text(encoding="utf-8") == "d99057288026298443f4b9ce8b490d7e"


@pytest.mark.linux
def test_create_package_zsync_file() -> None:
	with make_temp_dir() as temp_dir:
		zsync_file = temp_dir / "localboot_new_42.0-1337.opsi.zsync"
		create_package_zsync_file(TEST_DATA / "localboot_new_42.0-1337.opsi", filename=zsync_file)
		result = zsync_file.read_bytes()
		for entry in (
			b"zsync: 0.6.2",
			b"Filename: localboot_new_42.0-1337.opsi",
			b"Blocksize: 2048",
			b"Length: 2048",
			b"Hash-Lengths: 1,2,4",
			b"URL: localboot_new_42.0-1337.opsi",
			b"SHA-1: 6faa32a67e5aead76f736013299ddf8de9a016db",
			b"\x84\xae\x8c/\xb2\x99",
		):
			assert entry in result


def test_extract_package_tar_zstd() -> None:
	with make_temp_dir() as temp_dir:
		OpsiPackage().extract_package_archive(TEST_DATA / "tar_zstd_packaged_42.0-1337.opsi", temp_dir)
		contents = list(temp_dir.rglob("*"))
		print(contents)
		for _file in (
			temp_dir / "OPSI" / "control.toml",
			temp_dir / "CLIENT_DATA" / "control.toml",
		):
			assert _file in contents
			result = OpsiPackage()
			result.find_and_parse_control_file(temp_dir)
			assert result.product.id == "localboot_new"


def test_load_package_tar_zstd() -> None:
	package = OpsiPackage(TEST_DATA / "tar_zstd_packaged_42.0-1337.opsi")
	print_info(package)
	assert package.product.id == "localboot_new"
