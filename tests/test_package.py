# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
tests for opsicommon.package
"""

from os import symlink
from pathlib import Path
from shutil import copy
from typing import Literal

import pytest

from opsicommon.objects import NetbootProduct
from opsicommon.package import OpsiPackage, PackageDependency
from opsicommon.package.associated_files import (
	create_package_content_file,
	create_package_md5_file,
	create_package_zsync_file,
)
from opsicommon.package.control_file_handling import create_product_dependencies
from opsicommon.utils import make_temp_dir

TEST_DATA = Path("tests") / "data" / "package"


def print_info(package: OpsiPackage) -> None:
	print(package.product)
	print(package.product_properties)
	print(package.product_dependencies)
	print(package.package_dependencies)


def test_find_and_parse_control_file() -> None:
	control = TEST_DATA / "control"
	control_toml = TEST_DATA / "control.toml"
	test_package = OpsiPackage()
	with make_temp_dir() as temp_dir:
		copy(control, temp_dir / "control")
		assert test_package.find_and_parse_control_file(temp_dir) == temp_dir / "control"

	with make_temp_dir() as temp_dir:
		copy(control_toml, temp_dir / "control.toml")
		assert test_package.find_and_parse_control_file(temp_dir) == temp_dir / "control.toml"

	with make_temp_dir() as temp_dir:
		copy(control, temp_dir / "control")
		copy(control_toml, temp_dir / "control.toml")
		assert test_package.find_and_parse_control_file(temp_dir) == temp_dir / "control.toml"

	with make_temp_dir() as temp_dir:
		opsi_dir = temp_dir / "OPSI"
		opsi_dir.mkdir()
		copy(control, opsi_dir / "control")
		assert test_package.find_and_parse_control_file(temp_dir) == opsi_dir / "control"

	with make_temp_dir() as temp_dir:
		opsi_dir = temp_dir / "OPSI"
		opsi_custom_dir = temp_dir / "OPSI.custom"
		opsi_dir.mkdir()
		opsi_custom_dir.mkdir()
		copy(control, opsi_dir / "control")
		copy(control_toml, opsi_custom_dir / "control.toml")
		assert test_package.find_and_parse_control_file(temp_dir) == opsi_custom_dir / "control.toml"

	# Prefer toml over custom
	with make_temp_dir() as temp_dir:
		opsi_dir = temp_dir / "OPSI"
		opsi_custom_dir = temp_dir / "OPSI.test"
		opsi_dir.mkdir()
		opsi_custom_dir.mkdir()
		copy(control_toml, opsi_dir / "control.toml")
		copy(control, opsi_custom_dir / "control")
		assert test_package.find_and_parse_control_file(temp_dir) == opsi_dir / "control.toml"


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

	assert len(package.product_dependencies) == 2

	assert package.product_dependencies[0].productAction == "setup"
	assert package.product_dependencies[0].requiredProductId == "hwaudit"
	assert package.product_dependencies[0].requiredInstallationStatus == "installed"
	assert package.product_dependencies[0].requirementType == "before"
	assert package.product_dependencies[0].requiredAction is None

	assert package.product_dependencies[1].productAction == "setup"
	assert package.product_dependencies[1].requiredProductId == "swaudit"
	assert package.product_dependencies[1].requiredInstallationStatus is None
	assert package.product_dependencies[1].requirementType == "after"
	assert package.product_dependencies[1].requiredAction == "setup"


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


def test_control_multiline_description() -> None:
	package = OpsiPackage()
	package.parse_control_file(TEST_DATA / "control.toml")
	package.product.description = "This is a\nmultiline description."
	package.product.advice = "A\n\nmultiline advice."
	with make_temp_dir() as temp_dir:
		package.generate_control_file(temp_dir / "control.toml")
		result = (temp_dir / "control.toml").read_text(encoding="utf-8")
		print(result)
		for string in ('description = """This is a', 'multiline description."""', 'advice = """A', "", 'multiline advice."""'):
			assert string in result.splitlines()


def test_control_multiline_description_property() -> None:
	package = OpsiPackage()
	package.parse_control_file(TEST_DATA / "control.toml")
	package.product_properties[0].description = "This is a\nmultiline description."
	with make_temp_dir() as temp_dir:
		package.generate_control_file(temp_dir / "control.toml")
		result = (temp_dir / "control.toml").read_text(encoding="utf-8")
		print(result)
		for string in ('description = """This is a', 'multiline description."""'):
			assert string in result.splitlines()


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
	assert package.product_dependencies[0].requirementType == "before"


@pytest.mark.linux
@pytest.mark.parametrize(
	"new_product_id",
	(None, "newproductid"),
)
def test_extract_package_localboot(new_product_id: str | None) -> None:
	with make_temp_dir() as temp_dir:
		test_package = OpsiPackage()
		test_package.extract_package_archive(TEST_DATA / "localboot_legacy_42.0-1337.opsi", temp_dir, new_product_id=new_product_id)
		assert test_package.product.getId() == (new_product_id or "localboot_legacy")
		contents = list(temp_dir.rglob("*"))
		for _file in (
			temp_dir / "OPSI" / "control",
			temp_dir / "OPSI" / "preinst",
			temp_dir / "OPSI" / "postinst",
			temp_dir / "CLIENT_DATA" / "setup.opsiscript",
		):
			assert _file in contents
		result = OpsiPackage()
		result.find_and_parse_control_file(temp_dir / "OPSI")
		assert result.product.getId() == (new_product_id or "localboot_legacy")


@pytest.mark.linux
def test_extract_package_memtest() -> None:
	with make_temp_dir() as temp_dir:
		test_package = OpsiPackage()
		test_package.extract_package_archive(TEST_DATA / "memtest86_cpio_6.20-1.opsi", temp_dir)
		assert test_package.product.getId() == "memtest86"
		contents = sorted(temp_dir.rglob("*"))
		assert contents == [
			Path(temp_dir) / "CLIENT_DATA",
			Path(temp_dir) / "CLIENT_DATA/setup.py",
			Path(temp_dir) / "OPSI",
			Path(temp_dir) / "OPSI/control",
			Path(temp_dir) / "OPSI/postinst",
			Path(temp_dir) / "OPSI/preinst",
			Path(temp_dir) / "SERVER_DATA",
			Path(temp_dir) / "SERVER_DATA/tmp",
			Path(temp_dir) / "SERVER_DATA/tmp/memtest",
			Path(temp_dir) / "SERVER_DATA/tmp/memtest/cfg",
			Path(temp_dir) / "SERVER_DATA/tmp/memtest/cfg/memtest86",
			Path(temp_dir) / "SERVER_DATA/tmp/memtest/cfg/memtest86.efi",
			Path(temp_dir) / "SERVER_DATA/tmp/memtest/cfg/memtest86.v43",
			Path(temp_dir) / "SERVER_DATA/tmp/memtest/memtest64.bin",
			Path(temp_dir) / "SERVER_DATA/tmp/memtest/memtest64.efi",
		]


@pytest.mark.parametrize(
	"compression",
	("zstd", "bz2", "gz"),
)
def test_create_package(compression: Literal["zstd", "bz2", "gz"]) -> None:
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


@pytest.mark.parametrize("custom_only", (True, False))
def test_create_package_custom(custom_only: bool) -> None:  # pylint: disable=too-many-statements
	package = OpsiPackage()
	control = TEST_DATA / "control.toml"
	with make_temp_dir() as temp_dir:
		opsi_dir = temp_dir / "OPSI"
		opsi_dir_custom = temp_dir / "OPSI.custom"
		client_dir = temp_dir / "CLIENT_DATA"
		client_dir_custom = temp_dir / "CLIENT_DATA.custom"
		dirs = [opsi_dir, opsi_dir_custom, client_dir, client_dir_custom]
		for _dir in dirs:
			_dir.mkdir()
		data = control.read_text(encoding="utf-8")
		(opsi_dir / "control.toml").write_text(data.replace("priority = 0", "priority = 10"), encoding="utf-8")
		(opsi_dir_custom / "control.toml").write_text(data.replace("priority = 0", "priority = 20"), encoding="utf-8")
		(client_dir / "testfile1").write_text("MAIN1", encoding="utf-8")
		(client_dir / "testfile2").write_text("MAIN2", encoding="utf-8")
		(client_dir / "testfile3").write_text("MAIN3", encoding="utf-8")
		(client_dir_custom / "testfile2").write_text("CUSTOM2", encoding="utf-8")
		(client_dir_custom / "testfile4").write_text("CUSTOM4", encoding="utf-8")

		if custom_only:
			dirs = [opsi_dir_custom, client_dir_custom]
		package_archive = package.create_package_archive(temp_dir, destination=temp_dir, use_dirs=dirs)

		with make_temp_dir() as result_dir:
			# Test from_package_archive()
			pkg = OpsiPackage()
			pkg.from_package_archive(package_archive)
			# Test custom priority
			assert pkg.product.priority == 20

			# Test extract_package_archive(custom_separated=False)
			pkg = OpsiPackage()
			pkg.extract_package_archive(package_archive, result_dir, custom_separated=False)

			# Test custom priority
			assert pkg.product.priority == 20
			if custom_only:
				assert not (result_dir / "CLIENT_DATA" / "testfile1").exists()
			else:
				assert (result_dir / "CLIENT_DATA" / "testfile1").read_text(encoding="utf-8") == "MAIN1"
			assert (result_dir / "CLIENT_DATA" / "testfile2").read_text(encoding="utf-8") == "CUSTOM2"
			if custom_only:
				assert not (result_dir / "CLIENT_DATA" / "testfile3").exists()
			else:
				assert (result_dir / "CLIENT_DATA" / "testfile3").read_text(encoding="utf-8") == "MAIN3"
			assert (result_dir / "CLIENT_DATA" / "testfile4").read_text(encoding="utf-8") == "CUSTOM4"

		with make_temp_dir() as result_dir:
			# Test extract_package_archive(custom_separated=True)
			pkg = OpsiPackage()
			pkg.extract_package_archive(package_archive, result_dir, custom_separated=True)

			files = [f.name for f in (result_dir / "CLIENT_DATA.custom").iterdir()]
			assert sorted(files) == ["testfile2", "testfile4"]
			assert (result_dir / "CLIENT_DATA.custom" / "testfile2").read_text(encoding="utf-8") == "CUSTOM2"
			assert (result_dir / "CLIENT_DATA.custom" / "testfile4").read_text(encoding="utf-8") == "CUSTOM4"

			files = [f.name for f in (result_dir / "OPSI.custom").iterdir()]
			assert sorted(files) == ["control.toml"]
			assert "priority = 20" in (result_dir / "OPSI.custom" / "control.toml").read_text(encoding="utf-8")

			if not custom_only:
				files = [f.name for f in (result_dir / "CLIENT_DATA").iterdir()]
				assert sorted(files) == ["testfile1", "testfile2", "testfile3"]
				assert (result_dir / "CLIENT_DATA" / "testfile1").read_text(encoding="utf-8") == "MAIN1"
				assert (result_dir / "CLIENT_DATA" / "testfile2").read_text(encoding="utf-8") == "MAIN2"
				assert (result_dir / "CLIENT_DATA" / "testfile3").read_text(encoding="utf-8") == "MAIN3"

				files = [f.name for f in (result_dir / "OPSI").iterdir()]
				assert sorted(files) == ["control.toml"]
				assert "priority = 10" in (result_dir / "OPSI" / "control.toml").read_text(encoding="utf-8")


def test_create_package_empty() -> None:
	package = OpsiPackage()
	test_data = TEST_DATA / "control.toml"
	with make_temp_dir() as temp_dir:
		(temp_dir / "OPSI").mkdir()
		(temp_dir / "CLIENT_DATA").mkdir()
		copy(test_data, temp_dir / "OPSI")
		# print(list(temp_dir.rglob("*")))
		# print(list(temp_dir.rglob("control*")))
		package_archive = package.create_package_archive(temp_dir, destination=temp_dir)
		assert package_archive.exists()
		with make_temp_dir() as result_dir:
			OpsiPackage().extract_package_archive(package_archive, result_dir)
			result_contents = list((_dir.relative_to(result_dir) for _dir in result_dir.rglob("*")))
			assert (temp_dir / "OPSI").relative_to(temp_dir) in result_contents


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
		"d 'testdir'",
		"f 'control.toml'",  # md5sums and sizes are different on windows??
		"f 'testdir",  # followed by /control.toml or \\control.toml ...
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
			result.find_and_parse_control_file(temp_dir / "OPSI")
			assert result.product.id == "localboot_new"


def test_load_package_tar_zstd() -> None:
	package = OpsiPackage(TEST_DATA / "tar_zstd_packaged_42.0-1337.opsi")
	print_info(package)
	assert package.product.id == "localboot_new"


@pytest.mark.parametrize(
	"dep_args, result_dict",
	(
		(
			[
				"testid",
				"1.0",
				"1",
				[
					{
						"action": "once",
						"requiredProduct": "otherid",
						"requiredAction": "always",
					}
				],
			],
			{
				"type": "ProductDependency",
				"packageVersion": "1",
				"productAction": "once",
				"productId": "testid",
				"productVersion": "1.0",
				"requiredProductId": "otherid",
				"requiredProductVersion": None,
				"requiredPackageVersion": None,
				"requiredAction": "always",
				"requiredInstallationStatus": None,
				"requirementType": "before",
			},
		),
		(
			[
				"testid",
				"1.0",
				"1",
				[
					{
						"action": "setup",
						"requiredProduct": "otherid",
						"requiredProductVersion": "1.0",
						"requiredPackageVersion": "1",
						"requiredStatus": "installed",
						"requirementType": "before",
					}
				],
			],
			{
				"type": "ProductDependency",
				"packageVersion": "1",
				"productVersion": "1.0",
				"productAction": "setup",
				"productId": "testid",
				"requiredProductId": "otherid",
				"requiredProductVersion": "1.0",
				"requiredPackageVersion": "1",
				"requiredAction": None,
				"requiredInstallationStatus": "installed",
				"requirementType": "before",
			},
		),
	),
)
def test_create_product_dependencies(dep_args: list[str | list[dict[str, str]]], result_dict: dict[str, str | None]) -> None:
	result = create_product_dependencies(*dep_args)  # type: ignore
	assert result[0].to_hash() == result_dict


@pytest.mark.parametrize(
	"json_string, package_dependencies",
	(
		(
			'[{"package": "mshotfix", "version": "202301-1", "condition": ">="}]',
			[PackageDependency(package="mshotfix", version="202301-1", condition=">=")],
		),
		(
			'[{"package": "mshotfix", "version": "202301-1"}]',
			[PackageDependency(package="mshotfix", version="202301-1", condition="=")],
		),
		(
			'[{"package": "mshotfix", "condition": ">="}]',
			[PackageDependency(package="mshotfix")],
		),
		(
			'[{"package": "mshotfix"}]',
			[PackageDependency(package="mshotfix")],
		),
		(
			'{"package": "mshotfix"}',  # no list brackets
			[PackageDependency(package="mshotfix")],
		),
		(
			'[{"package": "mshotfix", "version": null, "condition": null}]',
			[PackageDependency(package="mshotfix")],
		),
		(
			'[{"package": "mshotfix"}, {"package": "hwaudit"}]',
			[PackageDependency(package="mshotfix"), PackageDependency(package="hwaudit")],
		),
	),
)
def test_set_package_dependencies_from_json(json_string: str, package_dependencies: list[PackageDependency]) -> None:
	package = OpsiPackage()
	package.set_package_dependencies_from_json(json_string)
	assert package.package_dependencies == package_dependencies


@pytest.mark.parametrize(
	"package_dependencies, json_string",
	(
		(
			[PackageDependency(package="mshotfix", version="202301-1", condition=">=")],
			'[{"package": "mshotfix", "version": "202301-1", "condition": ">="}]',
		),
		(
			[PackageDependency(package="mshotfix")],
			'[{"package": "mshotfix", "version": null, "condition": null}]',
		),
		(
			[PackageDependency(package="mshotfix"), PackageDependency(package="hwaudit")],
			'[{"package": "mshotfix", "version": null, "condition": null}, {"package": "hwaudit", "version": null, "condition": null}]',
		),
	),
)
def test_get_package_dependencies_as_json(package_dependencies: list[PackageDependency], json_string: str) -> None:
	package = OpsiPackage()
	package.package_dependencies = package_dependencies
	assert package.get_package_dependencies_as_json() == json_string
