# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
tests for opsicommon.package.archive
"""

import mmap
import struct
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

from opsicommon.package.archive import (
	create_archive,
	create_archive_external,
	create_archive_internal,
	extract_archive_external,
	extract_archive_internal,
)
from opsicommon.package.associated_files import (
	create_package_zsync_file,
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


def read_zsync_blocksums(zsync_file: Path) -> list[tuple[int, int, bytes]]:  # pylint: disable=too-many-locals
	checksum_bytes = 16
	rsum_bytes = 4
	seq_matches = 1
	nzblocks = 0
	filelen = 0
	blocksize = 0
	blocks = []
	with open(zsync_file, "r+b") as file:
		memm = mmap.mmap(file.fileno(), 0)
		while True:
			line = memm.readline().decode("utf-8").strip()
			if len(line) == 0:
				break
			attr, value = line.split(":", 1)
			attr = attr.strip().lower()
			value = value.strip()
			# print(attr, "=", value)
			if attr == "length":
				filelen = int(value)
			elif attr == "blocksize":
				blocksize = int(value)
			elif attr == "z-map2":
				nzblocks = int(value)
				# Read Z-Map
				_zmap = memm.read(nzblocks * 4)
			elif attr == "hash-lengths":
				seq_matches, rsum_bytes, checksum_bytes = [int(v) for v in value.split(",")]
				if rsum_bytes < 1 or rsum_bytes > 4:
					raise ValueError("rsum_bytes out of range")
				if checksum_bytes < 3 or checksum_bytes > 16:
					raise ValueError("checksum_bytes out of range")
				if seq_matches < 1 or seq_matches > 2:
					raise ValueError("seq_matches out of range")

		block_count = int((filelen + blocksize - 1) / blocksize)
		# print(filelen, blocksize, block_count)
		for _block_id in range(block_count):
			# struct rsum { unsigned short a; unsigned short b;}
			rsum = struct.unpack("!HH", memm.read(rsum_bytes).ljust(4, b"\x00"))
			checksum = memm.read(checksum_bytes)
			# print(rsum, checksum.hex())
			blocks.append((rsum[0], rsum[1], checksum))
		memm.close()
		return blocks


@pytest.mark.parametrize(
	"mode, compression",
	(
		("external", None),
		("external", "zstd"),
		("external", "bz2"),
		("external", "gz"),
		("internal", None),
		("internal", "zstd"),
		("internal", "bz2"),
		("internal", "gz"),
		("auto", None),
		("auto", "zstd"),
		("auto", "bz2"),
		("auto", "gz"),
	),
)
def test_syncable_external(tmp_path: Path, mode: Literal["external", "internal"], compression: Literal["zstd", "bz2", "gz"]) -> None:
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
	zsync_old = tmp_path / f"archive-old.tar.{compression}.zsync"
	create_archive_func(archive_old, list(source.glob("*")), source, compression=compression)
	create_package_zsync_file(archive_old, zsync_old)

	# Keep file1.dat, change file2.dat
	(source / "file2.dat").write_bytes(randbytes(10_000))
	archive_new = tmp_path / f"archive-new.tar.{compression}"
	zsync_new = tmp_path / f"archive-new.tar.{compression}.zsync"
	create_archive_func(archive_new, list(source.glob("*")), source, compression=compression)
	create_package_zsync_file(archive_new, zsync_new)

	blocksums_old = read_zsync_blocksums(zsync_old)
	assert len(blocksums_old)
	blocksums_new = read_zsync_blocksums(zsync_new)
	assert len(blocksums_new)

	same_blocksums = [b for b in blocksums_new if b in blocksums_old]
	percent_same = len(same_blocksums) / len(blocksums_new)
	# print(len(same_blocksums), len(blocksums_new), percent_same)
	if compression == "bz2":
		# No --rsyncable with bz2
		pass
	elif compression == "zstd" and mode == "internal":
		# Currently not possible to set ZSTD_c_rsyncable
		pass
	else:
		assert percent_same > 0.8
