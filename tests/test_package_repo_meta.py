# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
tests for opsicommon.package.repo_meta
"""

import shutil
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import pytest
import zstandard
from msgspec import json, msgpack

from opsicommon.objects import ProductDependency
from opsicommon.package import PackageDependency
from opsicommon.package.repo_meta import (
	RepoMetaMetadataFileType,
	RepoMetaPackage,
	RepoMetaPackageCollection,
	RepoMetaPackageCompatibility,
	RepoMetaPackageDependency,
	RepoMetaProductDependency,
)
from opsicommon.types import Architecture, OperatingSystem

TEST_REPO = Path() / "tests/data/repo_meta"


def read_metafile(file: Path) -> dict:
	bdata = file.read_bytes()
	if ".zstd" in file.suffixes:
		decompressor = zstandard.ZstdDecompressor()
		bdata = decompressor.decompress(bdata)
	data = msgpack.decode(bdata) if ".msgpack" in file.suffixes else json.decode(bdata)
	return data


def test_repo_meta_metadata_file_type() -> None:
	assert RepoMetaMetadataFileType("packages") == RepoMetaMetadataFileType.PACKAGES
	assert RepoMetaMetadataFileType("custom") == RepoMetaMetadataFileType.CUSTOM
	with pytest.raises(ValueError):
		RepoMetaMetadataFileType("unknown")


def test_repo_meta_package_compatibility() -> None:
	comp = RepoMetaPackageCompatibility.from_dict({"os": "windows", "arch": "x86"})
	assert comp.os == "windows"
	assert comp.arch == "x86"

	comp = RepoMetaPackageCompatibility.from_string("linux-arm64")
	assert comp.os == "linux"
	assert comp.arch == "arm64"

	comp = RepoMetaPackageCompatibility.from_string("opsi-local-image-x64")
	assert comp.os == "opsi-local-image"
	assert comp.arch == "x64"

	for string in ("linux-invalid", "invalid-all", "linux", "all", "linux-amd64"):
		with pytest.raises(ValueError):
			comp = RepoMetaPackageCompatibility.from_string(string)


def test_repo_meta_from_dict_with_unkown_arguments() -> None:
	RepoMetaPackage.from_dict(
		{
			"url": "https://some.url/",
			"size": 12098322,
			"md5_hash": "15329eb8cd987f46024b593f200b5295",
			"sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"product_id": "localboot_new",
			"name": "localboot new",
			"priority": 10,
			"product_version": "42.0",
			"package_version": "1337",
			"future_attribute": "new",
			"legacy_attribute": 27237,
		}
	)


def test_repo_meta_product_dependency() -> None:
	product_dependency = ProductDependency(
		productId="product_id",
		productVersion="12.1",
		packageVersion="4",
		productAction="setup",
		requiredProductId="product_id2",
		requiredProductVersion="7.3",
		requiredPackageVersion="9",
		requirementType="before",
	)
	rppd = RepoMetaProductDependency.from_product_dependency(product_dependency)
	assert rppd.productAction == product_dependency.productAction
	assert rppd.requiredProductId == product_dependency.requiredProductId
	assert rppd.requiredProductVersion == product_dependency.requiredProductVersion
	assert rppd.requiredPackageVersion == product_dependency.requiredPackageVersion
	assert rppd.requiredAction == product_dependency.requiredAction
	assert rppd.requiredInstallationStatus == product_dependency.requiredInstallationStatus
	assert rppd.requirementType == product_dependency.requirementType


def test_repo_meta_package_dependency() -> None:
	package_dependency = PackageDependency(
		package="other_package",
		condition=">=",
		version="13.1-2",
	)
	rppd = RepoMetaPackageDependency.from_package_dependency(package_dependency)
	assert rppd.package == package_dependency.package
	assert rppd.condition == package_dependency.condition
	assert rppd.version == package_dependency.version


def test_repo_meta_package(tmp_path: Path) -> None:
	shutil.copy(TEST_REPO / "localboot_new_42.0-1337.opsi", tmp_path)
	(tmp_path / "localboot_new_42.0-1337.opsi.zsync").touch()
	url = "path/to/localboot_new_42.0-1337.opsi"
	repo_meta_package = RepoMetaPackage.from_package_file(tmp_path / "localboot_new_42.0-1337.opsi", url=url)
	assert repo_meta_package.url == url
	assert repo_meta_package.size == 10240
	assert repo_meta_package.md5_hash == "15329eb8cd987f46024b593f200b5295"
	assert repo_meta_package.sha256_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	assert repo_meta_package.product_id == "localboot_new"
	assert repo_meta_package.name == "localboot new"
	assert repo_meta_package.priority == 10
	assert repo_meta_package.product_version == "42.0"
	assert repo_meta_package.package_version == "1337"
	assert repo_meta_package.product_dependencies == [
		RepoMetaProductDependency(
			productAction="setup",
			requiredProductId="hwaudit",
			requiredInstallationStatus="installed",
			requirementType="before",
		),
		RepoMetaProductDependency(productAction="setup", requiredProductId="swaudit", requiredInstallationStatus="installed"),
		RepoMetaProductDependency(
			productAction="uninstall",
			requiredProductId="swaudit",
			requiredProductVersion="11",
			requiredPackageVersion="2",
			requiredAction="uninstall",
			requirementType="after",
		),
	]
	assert repo_meta_package.package_dependencies == [
		RepoMetaPackageDependency(package="mshotfix", version="202301-1", condition=">="),
		RepoMetaPackageDependency(package="opsi-client-agent"),
	]
	assert repo_meta_package.description == "this is a localboot new test package"
	assert repo_meta_package.zsync_url == "path/to/localboot_new_42.0-1337.opsi.zsync"

	data = asdict(repo_meta_package)
	assert RepoMetaPackage.from_dict(data) == repo_meta_package


def test_repo_meta_package_merge(tmp_path: Path) -> None:
	shutil.copy(TEST_REPO / "localboot_new_42.0-1337.opsi", tmp_path)
	(tmp_path / "localboot_new_42.0-1337.opsi.zsync").touch()
	url = "path/to/localboot_new_42.0-1337.opsi"
	repo_meta_package = RepoMetaPackage.from_package_file(tmp_path / "localboot_new_42.0-1337.opsi", url=url)

	new_release_date = datetime.now(tz=timezone.utc)
	other_repo_meta_package = RepoMetaPackage.from_package_file(tmp_path / "localboot_new_42.0-1337.opsi", url=url)
	other_repo_meta_package.url = "otherpath/to/localboot_new_42.0-1337.opsi"
	other_repo_meta_package.zsync_url = "otherpath/to/localboot_new_42.0-1337.opsi.zsync"
	other_repo_meta_package.release_date = new_release_date
	repo_meta_package.merge(other_repo_meta_package)

	yet_another_repo_meta_package = RepoMetaPackage.from_package_file(tmp_path / "localboot_new_42.0-1337.opsi", url=url)
	yet_another_repo_meta_package.url = "yetanotherpath/to/localboot_new_42.0-1337.opsi"
	yet_another_repo_meta_package.zsync_url = None
	repo_meta_package.merge(yet_another_repo_meta_package)

	assert isinstance(repo_meta_package.url, list) and isinstance(repo_meta_package.zsync_url, list)
	assert repo_meta_package.url[0] == "path/to/localboot_new_42.0-1337.opsi"
	assert repo_meta_package.url[1] == "otherpath/to/localboot_new_42.0-1337.opsi"
	assert repo_meta_package.url[2] == "yetanotherpath/to/localboot_new_42.0-1337.opsi"
	assert repo_meta_package.zsync_url[0] == "path/to/localboot_new_42.0-1337.opsi.zsync"
	assert repo_meta_package.zsync_url[1] == "otherpath/to/localboot_new_42.0-1337.opsi.zsync"
	assert repo_meta_package.zsync_url[2] is None  # keep None to not change indices
	assert repo_meta_package.release_date == new_release_date


def test_repo_meta_package_url_list_merge(tmp_path: Path) -> None:
	shutil.copy(TEST_REPO / "localboot_new_42.0-1337.opsi", tmp_path)
	(tmp_path / "localboot_new_42.0-1337.opsi.zsync").touch()
	url = ["dir1/localboot_new_42.0-1337.opsi", "dir2/localboot_new_42.0-1337.opsi"]
	repo_meta_package = RepoMetaPackage.from_package_file(tmp_path / "localboot_new_42.0-1337.opsi", url=url)

	url = ["dir2/localboot_new_42.0-1337.opsi", "dir3/localboot_new_42.0-1337.opsi"]
	other_repo_meta_package = RepoMetaPackage.from_package_file(tmp_path / "localboot_new_42.0-1337.opsi", url=url)
	repo_meta_package.merge(other_repo_meta_package)

	assert isinstance(repo_meta_package.url, list) and isinstance(repo_meta_package.zsync_url, list)
	assert len(repo_meta_package.url) == 3 and len(repo_meta_package.zsync_url) == 3
	assert repo_meta_package.url[0] == "dir1/localboot_new_42.0-1337.opsi"
	assert repo_meta_package.url[1] == "dir2/localboot_new_42.0-1337.opsi"
	assert repo_meta_package.url[2] == "dir3/localboot_new_42.0-1337.opsi"


def test_repo_meta_package_collection_scan_packages(tmp_path: Path) -> None:
	repository_dir = tmp_path / "repository-dir"
	formats = ["json", "json.zstd", "msgpack", "msgpack.zstd"]
	shutil.copytree(TEST_REPO, repository_dir)

	package_collection = RepoMetaPackageCollection()
	package_collection.scan_packages(repository_dir)

	assert list(package_collection.packages) == ["localboot_new", "test-netboot"]
	assert len(package_collection.packages["localboot_new"]) == 3
	assert len(package_collection.packages["test-netboot"]) == 1
	assert package_collection.packages["localboot_new"]["1.0-1"].url == "localboot_new_1.0-1.opsi"
	assert package_collection.packages["localboot_new"]["2.0-1"].url == "localboot_new_2.0-1.opsi"
	assert package_collection.packages["localboot_new"]["42.0-1337"].url == "localboot_new_42.0-1337.opsi"
	assert package_collection.packages["test-netboot"]["1.0-2"].url == "subdir/test-netboot_1.0-2.opsi"

	assert len(list(package_collection.get_packages())) == 4

	for suffix in formats:
		metafile = repository_dir / f"packages.{suffix}"
		package_collection.write_metafile(metafile)

		package_collection_read = RepoMetaPackageCollection()
		package_collection_read.read_metafile(metafile)

		assert package_collection_read == package_collection

		package_collection_read = RepoMetaPackageCollection()
		package_collection_read.read_metafile_data(metafile.read_bytes())

		assert package_collection_read == package_collection

	# Test add_callback
	compatibility = [
		RepoMetaPackageCompatibility(os=OperatingSystem.WINDOWS, arch=Architecture.ALL),
		RepoMetaPackageCompatibility(os=OperatingSystem.LINUX, arch=Architecture.X64),
	]
	changelog_url = "https://changelog.opsi.org/changelog.txt"
	release_notes_url = "path/to/releasenotes.txt"
	icon_url = "path/to/icon.png"

	def add_callback(package_meta: RepoMetaPackage) -> None:
		package_meta.compatibility = compatibility
		package_meta.changelog_url = changelog_url
		package_meta.release_notes_url = release_notes_url
		package_meta.icon_url = icon_url

	package_collection = RepoMetaPackageCollection()
	package_collection.scan_packages(repository_dir, add_callback=add_callback)

	for package in package_collection.packages["localboot_new"].values():
		assert package.compatibility == compatibility
		assert package.changelog_url == changelog_url
		assert package.release_notes_url == release_notes_url
		assert package.icon_url == icon_url


def test_repo_meta_package_collection_add_package(tmp_path: Path) -> None:
	repository_dir = tmp_path / "repository-dir"
	shutil.copytree(TEST_REPO, repository_dir)

	package_collection = RepoMetaPackageCollection()
	package_collection.scan_packages(repository_dir)

	# Check if update adds new package and deletes other entries for same package
	compatibility = [RepoMetaPackageCompatibility(os=OperatingSystem.WINDOWS, arch=Architecture.ALL)]

	def add_callback(package_meta: RepoMetaPackage) -> None:
		package_meta.compatibility = compatibility

	package_collection.add_package(
		repository_dir, repository_dir / "localboot_new_1.0-1.opsi", num_allowed_versions=1, add_callback=add_callback
	)
	utc_now = datetime.now(tz=timezone.utc)
	assert len(package_collection.packages["localboot_new"]) == 1
	print(package_collection.packages["localboot_new"])
	assert package_collection.packages["localboot_new"]["1.0-1"].url == "localboot_new_1.0-1.opsi"
	assert package_collection.packages["localboot_new"]["1.0-1"].compatibility == compatibility
	assert package_collection.packages["localboot_new"]["1.0-1"].priority == 0
	assert package_collection.packages["localboot_new"]["1.0-1"].name == "localboot_new"
	assert package_collection.packages["localboot_new"]["1.0-1"].release_date
	assert abs((package_collection.packages["localboot_new"]["1.0-1"].release_date - utc_now).total_seconds()) <= 2

	# Check if update adds new package and keeps others with --num-allowed-versions
	package_collection.add_package(repository_dir, repository_dir / "localboot_new_2.0-1.opsi", num_allowed_versions=2, url="my/url.opsi")
	utc_now = datetime.now(tz=timezone.utc)
	assert len(package_collection.packages["localboot_new"]) == 2
	assert package_collection.packages["localboot_new"]["1.0-1"].url == "localboot_new_1.0-1.opsi"
	assert package_collection.packages["localboot_new"]["1.0-1"].compatibility == compatibility
	assert package_collection.packages["localboot_new"]["2.0-1"].url == "my/url.opsi"
	assert not package_collection.packages["localboot_new"]["2.0-1"].compatibility
	assert package_collection.packages["localboot_new"]["2.0-1"].release_date
	assert abs((package_collection.packages["localboot_new"]["2.0-1"].release_date - utc_now).total_seconds()) <= 2

	for suffix in ["json", "json.zstd", "msgpack", "msgpack.zstd"]:
		package_collection.write_metafile(tmp_path / f"packages.{suffix}")

		package_collection_read = RepoMetaPackageCollection()
		package_collection_read.read_metafile(tmp_path / f"packages.{suffix}")
		assert (
			package_collection_read.packages["localboot_new"]["2.0-1"].release_date
			== package_collection.packages["localboot_new"]["2.0-1"].release_date
		)


def test_repo_meta_package_collection_remove_package(tmp_path: Path) -> None:
	repository_dir = tmp_path / "repository-dir"
	shutil.copytree(TEST_REPO, repository_dir)

	package_collection = RepoMetaPackageCollection()
	package_collection.scan_packages(repository_dir)
	assert len(package_collection.packages["localboot_new"]) == 3

	package_collection.remove_package("localboot_new", "1.0-1")
	assert sorted(list(package_collection.packages["localboot_new"])) == ["2.0-1", "42.0-1337"]

	package_collection.remove_package("localboot_new", "42.0-1337")
	assert list(package_collection.packages["localboot_new"]) == ["2.0-1"]

	package_collection.remove_package("localboot_new", "2.0-1")
	assert "localboot_new" not in package_collection.packages
