# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
tests for opsicommon.package.archive
"""

import getpass

try:
	import grp
except ModuleNotFoundError:  # not present for windows
	pass
import platform
import shutil
import tempfile
from pathlib import Path
from random import randbytes
from typing import Literal

import pytest
from hypothesis import given
from hypothesis.strategies import binary, from_regex, sampled_from
from pyzsync import SOURCE_REMOTE, get_patch_instructions, read_zsync_file

from opsicommon.package.archive import (
	create_archive,
	create_archive_external,
	create_archive_internal,
	extract_archive_external,
	extract_archive_internal,
)
from opsicommon.package.associated_files import create_package_zsync_file
from opsicommon.testing.helpers import memory_usage_monitor

# File may not
# * contain slash/backslash path delimiters
FILENAME_REGEX = r"^[^/\\]{4,64}$"


def make_source_files(path: Path) -> Path:
	source = path / "source"
	source.mkdir()
	(source / "test file with spaces").write_bytes(randbytes(100_000_000))
	(source / "#how^can°people`think,this´is'a good~idea#").write_bytes(randbytes(50_000_000))
	(source / "test'dir").mkdir()
	(source / "test'dir" / "testfileindir").write_bytes(randbytes(10_000_000))
	if platform.system().lower() != "windows":  # windows does not like ?, < and > characters
		(source / "test'dir" / 'test"file$in€dir<with>special?').write_bytes(randbytes(1000))
	return source


# Cannot use function scoped fixtures with hypothesis
@pytest.mark.linux
@given(from_regex(FILENAME_REGEX), binary(max_size=4096), sampled_from(("zstd", "bz2", "gz")))
def test_archive_external_hypothesis(filename: str, data: bytes, compression: Literal["zstd", "bz2", "gz"]) -> None:
	with tempfile.TemporaryDirectory() as tempdir:
		filename = filename.replace("\x00", "")
		tmp_path = Path(tempdir)
		source = tmp_path / "source"
		source.mkdir()
		file_path = source / filename
		file_path.write_bytes(data)
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
	with memory_usage_monitor(interval=0.01) as mem_monitor:
		# Setting group ownership of source to adm group - assuming this is present on every linux
		shutil.chown(source, None, "adm")
		archive = tmp_path / f"archive.tar.{compression}"
		create_archive_external(archive, list(source.glob("*")), source, compression=compression)

		# Ownership of archive should be current user group
		assert archive.stat().st_gid == grp.getgrnam(getpass.getuser()).gr_gid

		# Setting group ownership of archive to adm group - assuming this is present on every linux
		shutil.chown(archive, None, "adm")
		destination = tmp_path / "destination"
		extract_archive_external(archive, destination)

		# Ownership of archive should be current user group
		assert destination.stat().st_gid == grp.getgrnam(getpass.getuser()).gr_gid

		contents = [file.relative_to(destination) for file in destination.rglob("*")]
		for file in source.rglob("*"):
			assert file.relative_to(source) in contents

		mem_monitor.stop()
		mem_monitor.print_stats()
		assert mem_monitor.max_increase_rss < 20_000_000


@pytest.mark.parametrize(
	"compression",
	("zstd", "bz2", "gz"),
)
def test_archive_internal(tmp_path: Path, compression: Literal["zstd", "bz2", "gz"]) -> None:
	source = make_source_files(tmp_path)
	with memory_usage_monitor(interval=0.01) as mem_monitor:
		archive = tmp_path / f"archive.tar.{compression}"
		create_archive_internal(archive, list(source.glob("*")), source, compression=compression)

		destination = tmp_path / "destination"
		extract_archive_internal(archive, destination)

		contents = [file.relative_to(destination) for file in destination.rglob("*")]
		for file in source.rglob("*"):
			assert file.relative_to(source) in contents

		mem_monitor.stop()
		mem_monitor.print_stats()
		assert mem_monitor.max_increase_rss < 20_000_000


@pytest.mark.linux
@pytest.mark.parametrize(
	"mode, compression, expect_min_percent_same",
	(
		# external
		("external", None, 85),
		("external", "zstd", 85),
		("external", "bz2", 0),
		("external", "gz", 72),
		# internal
		("internal", None, 85),
		("internal", "zstd", 85),
		("internal", "bz2", 0),
		("internal", "gz", 55),
		# auto
		("auto", None, 85),
		("auto", "zstd", 85),
		("auto", "bz2", 0),
		("auto", "gz", 74),
	),
)
def test_syncable(
	tmp_path: Path, mode: Literal["external", "internal"], compression: Literal["zstd", "bz2", "gz"], expect_min_percent_same: float
) -> None:
	create_archive_func = create_archive
	if mode == "external":
		create_archive_func = create_archive_external
	elif mode == "internal":
		create_archive_func = create_archive_internal

	source = tmp_path / "source"
	source.mkdir()

	(source / "file1.dat").write_bytes(randbytes(100_000))
	(source / "file2.dat").write_bytes(randbytes(10_000))
	archive_old = tmp_path / f"archive-old.tar.{compression}"
	create_archive_func(archive_old, list(source.glob("*")), source, compression=compression)

	# Keep file1.dat, change file2.dat
	(source / "file2.dat").write_bytes(randbytes(10_000))
	archive_new = tmp_path / f"archive-new.tar.{compression}"
	zsync_new = tmp_path / f"archive-new.tar.{compression}.zsync"
	create_archive_func(archive_new, list(source.glob("*")), source, compression=compression)
	create_package_zsync_file(archive_new, zsync_new)

	zsync_info = read_zsync_file(zsync_new)
	instructions = get_patch_instructions(zsync_info, archive_old)

	same_bytes = sum([i.size for i in instructions if i.source != SOURCE_REMOTE])
	percent_same = same_bytes * 100 / zsync_info.length

	print(mode, compression, expect_min_percent_same, percent_same)

	assert percent_same >= expect_min_percent_same
