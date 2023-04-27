# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
tests for opsicommon.package.archive
"""

import platform
from pathlib import Path
from random import randbytes
from typing import Literal

import pytest
from hypothesis.strategies import binary, from_regex

from opsicommon.package.archive import (
	create_archive_external,
	create_archive_internal,
	extract_archive_external,
	extract_archive_internal,
)


def make_source_files_hypothesis(path: Path) -> Path:
	source = path / "source"
	source.mkdir()
	filenames = from_regex(r"^[^/\\<>?]{4,64}$")
	data = binary(max_size=4096)
	for _ in range(10):
		(source / filenames.example()).write_bytes(data.example())
	return source


def make_source_files(path: Path) -> Path:
	source = path / "source"
	source.mkdir()
	(source / "test file with spaces").write_bytes(randbytes(128))
	(source / "#how^can°people`think,this´is'a good~idea#").write_bytes(randbytes(128))
	(source / "test'dir").mkdir()
	(source / "test'dir" / "testfileindir").write_bytes(randbytes(128))
	if platform.system().lower() != "windows":  # windows does not like ?, < and > characters
		(source / "test'dir" / 'test"file$in€dir<with>special?').write_bytes(randbytes(128))
	return source


@pytest.mark.linux
@pytest.mark.parametrize(
	"compression",
	("zstd", "bz2", "gz"),
)
@pytest.mark.parametrize(
	"strategy",
	("static", "hypothesis"),
)
def test_create_extract_archive_external(
	tmp_path: Path, compression: Literal["zstd", "bz2", "gz"], strategy: Literal["static", "hypothesis"]
) -> None:
	if strategy == "hypothesis":
		source = make_source_files_hypothesis(tmp_path)
	else:
		source = make_source_files(tmp_path)
	create_archive_external(
		tmp_path / f"archive.tar.{compression}",
		list(source.glob("*")),
		source,
		compression=compression,
	)
	destination = tmp_path / "destination"
	extract_archive_external(tmp_path / f"archive.tar.{compression}", destination)
	contents = [file.relative_to(destination) for file in destination.rglob("*")]
	for file in source.rglob("*"):
		assert file.relative_to(source) in contents


@pytest.mark.parametrize(
	"compression",
	("zstd", "bz2", "gz"),
)
def test_create_extract_archive_internal(tmp_path: Path, compression: Literal["zstd", "bz2", "gz"]) -> None:
	source = make_source_files(tmp_path)
	create_archive_internal(
		tmp_path / f"archive.tar.{compression}",
		list(source.glob("*")),
		source,
		compression=compression,
	)
	destination = tmp_path / "destination"
	extract_archive_internal(tmp_path / f"archive.tar.{compression}", destination)
	contents = [file.relative_to(destination) for file in destination.rglob("*")]
	print(contents)
	for file in source.rglob("*"):
		assert file.relative_to(source) in contents
