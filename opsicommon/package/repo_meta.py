# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
opsi packages repository metadata handling
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable, Generator

import packaging.version as packver
import zstandard
from msgspec import json, msgpack

from opsicommon.logging import get_logger
from opsicommon.objects import ProductDependency
from opsicommon.package import OpsiPackage, PackageDependency
from opsicommon.system import lock_file
from opsicommon.types import Architecture, OperatingSystem

logger = get_logger("opsicommon.package")


@dataclass
class RepoMetaRepository:
	name: str = "opsi package repository"


class RepoMetaMetadataFileType(StrEnum):
	PACKAGES = "packages"
	CUSTOM = "custom"


@dataclass
class RepoMetaMetadataFile:
	type: RepoMetaMetadataFileType
	urls: list[str]


@dataclass
class RepoMetaPackageCompatibility:
	os: OperatingSystem
	arch: Architecture

	@classmethod
	def from_dict(cls, data: dict[str, str]) -> RepoMetaPackageCompatibility:
		return RepoMetaPackageCompatibility(os=OperatingSystem(data["os"]), arch=Architecture(data["arch"]))

	@classmethod
	def from_string(cls, data: str) -> RepoMetaPackageCompatibility:
		os_arch = data.split("-")
		if len(os_arch) < 2:
			raise ValueError(f"Invalid compatibility string: {data!r} (<os>-<arch> needed)")
		# operating system may contain "-" like opsi-local-image
		return RepoMetaPackageCompatibility(os=OperatingSystem("-".join(os_arch[:-1])), arch=Architecture(os_arch[-1]))


@dataclass
class RepoMetaProductDependency:
	productAction: str
	requiredProductId: str
	requiredProductVersion: str | None = None
	requiredPackageVersion: str | None = None
	requiredAction: str | None = None
	requiredInstallationStatus: str | None = None
	requirementType: str | None = None

	@classmethod
	def from_product_dependency(cls, product_dependency: ProductDependency) -> RepoMetaProductDependency:
		attributes = [f.name for f in fields(RepoMetaProductDependency)]
		kwargs = {attr: value for attr, value in product_dependency.to_hash().items() if attr in attributes and value}
		return RepoMetaProductDependency(**kwargs)

	@classmethod
	def from_dict(cls, data: dict[str, str]) -> RepoMetaProductDependency:
		return RepoMetaProductDependency(**data)


@dataclass
class RepoMetaPackageDependency:
	package: str
	version: str | None = None
	condition: str | None = None

	@classmethod
	def from_package_dependency(cls, package_dependency: PackageDependency) -> RepoMetaPackageDependency:
		attributes = [f.name for f in fields(PackageDependency)]
		kwargs = {attr: value for attr, value in asdict(package_dependency).items() if attr in attributes and value}
		return RepoMetaPackageDependency(**kwargs)

	@classmethod
	def from_dict(cls, data: dict[str, str]) -> RepoMetaPackageDependency:
		return RepoMetaPackageDependency(**data)


@dataclass
class RepoMetaPackage:
	url: str | list[str]
	size: int
	md5_hash: str
	sha256_hash: str
	product_id: str
	product_version: str
	package_version: str
	name: str | None = None
	priority: int = 0
	product_dependencies: list[RepoMetaProductDependency] = field(default_factory=list)
	package_dependencies: list[RepoMetaPackageDependency] = field(default_factory=list)
	description: str | None = None
	compatibility: list[RepoMetaPackageCompatibility] | None = None
	changelog_url: str | None = None
	release_notes_url: str | None = None
	icon_url: str | None = None
	zsync_url: str | None | list[str | None] = None
	release_date: datetime | None = None

	@property
	def version(self) -> str:
		return f"{self.product_version}-{self.package_version}"

	@classmethod
	def from_package_file(cls, package_file: Path, url: str | list[str]) -> RepoMetaPackage:
		logger.notice("Reading package file %s", package_file)
		data: dict[str, Any] = {"url": url, "size": package_file.stat().st_size}
		with open(package_file, "rb", buffering=0) as file_handle:
			# file_digest is python>=3.11 only
			data["md5_hash"] = hashlib.file_digest(file_handle, "md5").hexdigest()  # type: ignore
			data["sha256_hash"] = hashlib.file_digest(file_handle, "sha256").hexdigest()  # type: ignore
		if package_file.with_name(f"{package_file.name}.zsync").exists():
			if isinstance(url, str):
				data["zsync_url"] = f"{url}.zsync"
			elif isinstance(url, list):
				data["zsync_url"] = [f"{entry}.zsync" for entry in url]

		opsi_package = OpsiPackage(package_file)
		data["product_id"] = opsi_package.product.id
		data["name"] = opsi_package.product.name
		data["product_version"] = opsi_package.product.productVersion
		data["package_version"] = opsi_package.product.packageVersion
		data["priority"] = opsi_package.product.priority or 0
		data["description"] = opsi_package.product.description
		data["product_dependencies"] = [RepoMetaProductDependency.from_product_dependency(d) for d in opsi_package.product_dependencies]
		data["package_dependencies"] = [RepoMetaPackageDependency.from_package_dependency(d) for d in opsi_package.package_dependencies]

		return RepoMetaPackage(**data)

	@classmethod
	def from_dict(cls, data: dict[str, Any]) -> RepoMetaPackage:
		data = data.copy()
		if data.get("compatibility"):
			data["compatibility"] = [RepoMetaPackageCompatibility.from_dict(d) for d in data["compatibility"]]
		else:
			data["compatibility"] = None
		data["product_dependencies"] = [RepoMetaProductDependency.from_dict(d) for d in data.get("product_dependencies") or []]
		data["package_dependencies"] = [RepoMetaPackageDependency.from_dict(d) for d in data.get("package_dependencies") or []]
		release_date = data.get("release_date")
		if release_date and not isinstance(release_date, datetime):
			data["release_date"] = datetime.fromisoformat(release_date)
		attributes = [field.name for field in fields(RepoMetaPackage)]
		for key in list(data):
			if key not in attributes:
				del data[key]
		return RepoMetaPackage(**data)

	def merge(self, other: RepoMetaPackage) -> None:
		if self.version != other.version or self.product_id != other.product_id:
			raise ValueError("Cannot merge RepoMetaPackages for different products or versions")
		if self.md5_hash != other.md5_hash or self.sha256_hash != other.sha256_hash:
			raise ValueError("Cannot merge RepoMetaPackages if hashes differ")

		for attribute, value in asdict(other).items():
			if isinstance(value, list) or attribute in ("zsync_url", "url"):
				# keep None in list to not change indices
				cur_value = getattr(self, attribute) or []
				if not isinstance(cur_value, list):
					cur_value = [cur_value]
				if not isinstance(value, list):
					value = [value]
				for val in value:
					if val not in cur_value:
						cur_value.append(val)
				setattr(self, attribute, cur_value)
			elif value is not None:
				setattr(self, attribute, value)


@dataclass
class RepoMetaPackageCollection:
	schema_version: str = "1.1"
	repository: RepoMetaRepository = field(default_factory=RepoMetaRepository)
	metadata_files: list[RepoMetaMetadataFile] = field(default_factory=list)
	packages: dict[str, dict[str, RepoMetaPackage]] = field(default_factory=dict)

	def scan_packages(self, directory: Path, add_callback: Callable | None = None) -> None:
		if add_callback and not callable(add_callback):
			raise ValueError("add_callback must be callable")
		logger.notice("Scanning opsi packages in %s", directory)
		for package_file in directory.rglob("*.opsi"):
			# Allow multiple versions for the same product in full scan
			self.add_package(directory, package_file, num_allowed_versions=0, add_callback=add_callback)
		logger.info("Finished scanning opsi packages")

	def limit_versions(self, name: str, num_allowed_versions: int = 1) -> None:
		versions = list(self.packages[name].keys())
		keep_versions = sorted(versions, key=packver.parse, reverse=True)[:num_allowed_versions]
		for version in versions:
			if version not in keep_versions:
				logger.debug("Removing %s %s as limit is %s", name, version, num_allowed_versions)
				del self.packages[name][version]

	def add_package(
		self,
		directory: Path,
		package_file: Path,
		*,
		num_allowed_versions: int = 1,
		url: list[str] | str | None = None,
		compatibility: list[RepoMetaPackageCompatibility] | None = None,
		add_callback: Callable | None = None,
	) -> RepoMetaPackage:
		if not url:
			url = str(package_file.relative_to(directory))
		if isinstance(url, str):
			url = str(url).replace("\\", "/")  # Cannot instantiate PosixPath on windows
		elif isinstance(url, list):
			url = [str(entry).replace("\\", "/") for entry in url]  # Cannot instantiate PosixPath on windows

		if add_callback and not callable(add_callback):
			raise ValueError("add_callback must be callable")

		package = RepoMetaPackage.from_package_file(package_file=package_file, url=url)
		package.release_date = datetime.now(tz=timezone.utc)
		package.compatibility = compatibility or None
		if add_callback:
			add_callback(package)

		# Key only consists of only product id (otw11 revision 03.05.)
		if (
			package.product_id not in self.packages
			or num_allowed_versions == 1
			and any((version != package.version for version in self.packages[package.product_id]))
		):
			# if only one version is allowed, always delete previous versions, if any is different (allow downgrade)
			self.packages[package.product_id] = {}
		if self.packages[package.product_id].get(package.version):
			logger.debug("Merging %s / %s: %s", package.product_id, package.version, package)
			self.packages[package.product_id][package.version].merge(package)
		else:
			logger.debug("Adding %s / %s: %s", package.product_id, package.version, package)
			self.packages[package.product_id][package.version] = package
		# num_allowed_versions = 0 means unlimited
		if num_allowed_versions and len(self.packages[package.product_id]) > num_allowed_versions:
			self.limit_versions(package.product_id, num_allowed_versions)
		return package

	def remove_package(self, name: str, version: str) -> None:
		if name in self.packages and version in self.packages[name]:
			del self.packages[name][version]
			if len(self.packages[name]) == 0:
				del self.packages[name]

	def get_packages(self) -> Generator[RepoMetaPackage, None, None]:
		for _name, versions in self.packages.items():
			for _version, package in versions.items():
				yield package

	def read_metafile_data(self, data: bytes) -> None:
		p_data: dict[str, Any] = {}
		head = data[0:4].hex()
		if head == "28b52ffd":
			decompressor = zstandard.ZstdDecompressor()
			data = decompressor.decompress(data)

		if data.startswith(b"{"):
			p_data = json.decode(data)
		else:
			p_data = msgpack.decode(data)

		self.schema_version = p_data.get("schema_version", self.schema_version)
		self.repository = RepoMetaRepository(**p_data.get("repository", {}))
		self.metadata_files = [RepoMetaMetadataFile(entry.get("type"), entry.get("urls")) for entry in p_data.get("metadata_files", [])]
		self.packages = {}
		for name, product in p_data.get("packages", {}).items():
			if name not in self.packages:
				self.packages[name] = {}
			self.packages[name] = {version: RepoMetaPackage.from_dict(data) for version, data in product.items()}

	def read_metafile(self, path: Path) -> None:
		with open(path, mode="rb") as file:
			with lock_file(file):
				data = file.read()
				if data:
					self.read_metafile_data(data)

	def write_metafile(self, path: Path) -> None:
		encoding = "json"
		compression: str | None = None
		if ".msgpack" in path.suffixes:
			encoding = "msgpack"
		if ".zstd" in path.suffixes:
			compression = "zstd"

		logger.notice("Writing package metafile to %s (encoding=%s, compression=%s)", path, encoding, compression)

		data = asdict(self)
		bdata = msgpack.encode(data) if encoding == "msgpack" else json.encode(data)
		if compression:
			if compression != "zstd":
				raise ValueError(f"Invalid compression: {compression}")
			compressor = zstandard.ZstdCompressor()
			bdata = compressor.compress(bdata)

		if not path.exists():
			path.touch()  # Need to create file before it can be opened with r+
		with open(path, "rb+") as file:
			with lock_file(file, exclusive=True):
				file.seek(0)
				file.truncate()
				file.write(bdata)
