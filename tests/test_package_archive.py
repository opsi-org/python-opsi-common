# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
tests for opsicommon.package.archive
"""

import getpass

try:
	import grp
except ModuleNotFoundError:  # not present for windows
	grp = None
import platform
import shutil
import tempfile
from pathlib import Path
from random import randbytes
from typing import Literal

import pytest
from hypothesis import given
from hypothesis.strategies import binary, from_regex, sampled_from

from opsicommon.package.archive import (
	create_archive_external,
	create_archive_internal,
	extract_archive_external,
	extract_archive_internal,
)

# File may not
# * contain slash/backslash path delimiters
FILENAME_REGEX = r"^[^/\\]{4,64}$"


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


# Cannot use function scoped fixtures with hypothesis
@pytest.mark.linux
@given(from_regex(FILENAME_REGEX), binary(max_size=4096), sampled_from(("zstd", "bz2", "gz")))
def test_archive_external_hypothesis(filename: str, data: bytes, compression: Literal["zstd", "bz2", "gz"]) -> None:
	with tempfile.TemporaryDirectory() as tempdir:
		tmp_path = Path(tempdir)
		source = tmp_path / "source"
		source.mkdir()
		(source / filename).write_bytes(data)
		archive = tmp_path / f"archive.tar.{compression}"
		create_archive_external(archive, list(source.glob("*")), source, compression=compression)
		destination = tmp_path / "destination"
		extract_archive_external(archive, destination)
		contents = [file.relative_to(destination) for file in destination.rglob("*")]
		for file in source.rglob("*"):
			assert file.relative_to(source) in contents


@pytest.mark.linux
@pytest.mark.parametrize(
	"compression",
	("zstd", "bz2", "gz"),
)
def test_archive_external(tmp_path: Path, compression: Literal["zstd", "bz2", "gz"]) -> None:
	source = make_source_files(tmp_path)
	# setting group ownership of source to adm group - assuming this is present on every linux
	shutil.chown(source, None, "adm")
	archive = tmp_path / f"archive.tar.{compression}"
	create_archive_external(archive, list(source.glob("*")), source, compression=compression)
	# ownership of archive should be current user group
	assert archive.stat().st_gid == grp.getgrnam(getpass.getuser()).gr_gid
	# setting group ownership of archive to adm group - assuming this is present on every linux
	shutil.chown(archive, None, "adm")
	destination = tmp_path / "destination"
	extract_archive_external(archive, destination)
	# ownership of archive should be current user group
	assert destination.stat().st_gid == grp.getgrnam(getpass.getuser()).gr_gid
	contents = [file.relative_to(destination) for file in destination.rglob("*")]
	for file in source.rglob("*"):
		assert file.relative_to(source) in contents


@pytest.mark.parametrize(
	"compression",
	("zstd", "bz2", "gz"),
)
def test_archive_internal(tmp_path: Path, compression: Literal["zstd", "bz2", "gz"]) -> None:
	source = make_source_files(tmp_path)
	archive = tmp_path / f"archive.tar.{compression}"
	create_archive_internal(archive, list(source.glob("*")), source, compression=compression)
	destination = tmp_path / "destination"
	extract_archive_internal(archive, destination)
	contents = [file.relative_to(destination) for file in destination.rglob("*")]
	for file in source.rglob("*"):
		assert file.relative_to(source) in contents
