# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
handling of archives
"""

import fnmatch
import os
import re
import shlex
import subprocess
import tarfile
from contextlib import contextmanager
from functools import lru_cache
from io import BytesIO
from pathlib import Path
from typing import Generator

import packaging.version
import zstandard

from opsicommon.config.opsi import OpsiConfig
from opsicommon.logging import get_logger
from opsicommon.system.info import is_linux

logger = get_logger("opsicommon.package")


@contextmanager
def chdir(new_dir: Path) -> Generator[None, None, None]:
	old_path = os.getcwd()
	try:
		os.chdir(str(new_dir))
		yield
	finally:
		os.chdir(old_path)


# IDEA: tar can use --zstd
CPIO_EXTRACT_COMMAND = "cpio --unconditional --extract --quiet --no-preserve-owner --no-absolute-filenames"
TAR_EXTRACT_COMMAND = "tar --wildcards --no-same-owner --extract --file -"
TAR_CREATE_COMMAND = "tar --owner=nobody --group=nogroup --create --file"
EXCLUDE_DIRS_ON_PACK_REGEX = re.compile(r"(^\.svn$)|(^\.git$)")
EXCLUDE_FILES_ON_PACK_REGEX = re.compile(r"(~$)|(^[Tt]humbs\.db$)|(^\.[Dd][Ss]_[Ss]tore$)")


@lru_cache
def use_pigz() -> bool:
	opsi_conf = OpsiConfig(upgrade_config=False)
	if not opsi_conf.get("packages", "use_pigz"):
		return False
	try:
		process = subprocess.run(["pigz", "--version"], capture_output=True, check=True)
		# Depending on pigz version, version is put to stdout or stderr
		pigz_version = process.stderr.decode("utf-8") + process.stdout.decode("utf-8")
		pigz_version = pigz_version.replace("pigz", "").strip()
		if packaging.version.parse(pigz_version) < packaging.version.parse("2.2.3"):
			raise ValueError("pigz too old")
		return True
	except (subprocess.CalledProcessError, ValueError):
		return False


def get_file_type(filename: str | Path) -> str:
	with open(filename, "rb") as file:
		head = file.read(262)
	if head[1:4] == b"\xb5\x2f\xfd":
		return "zstd"
	if head[:3] == b"\x1f\x8b\x08" or head[:8] == b"\x5c\x30\x33\x37\x5c\x32\x31\x33":
		return "gz"
	if head[:3] == b"\x42\x5a\x68":
		return "bzip2"
	if head[:5] == b"\x30\x37\x30\x37\x30":
		return "cpio"
	if head[257:262] == b"\x75\x73\x74\x61\x72":
		return "tar"
	raise TypeError("get_file_type only accepts gz, bzip2, zstd, cpio and tar files.")


def extract_command(archive: Path, file_pattern: str | None = None) -> str:
	# Look for cpio and tar in last or second last position (for compressed archives like .tar.gz)
	# It is assumed that the extract command gets data via stdin in an uncompressed state
	if archive.suffixes and ".cpio" in archive.suffixes[-2:]:
		cmd = CPIO_EXTRACT_COMMAND
	elif archive.suffixes and ".tar" in archive.suffixes[-2:]:
		cmd = TAR_EXTRACT_COMMAND
	else:
		file_type = get_file_type(archive)
		if file_type == "tar":
			cmd = TAR_EXTRACT_COMMAND
		elif file_type == "cpio":
			cmd = CPIO_EXTRACT_COMMAND
		else:
			raise TypeError(f"Archive to extract must be 'tar' or 'cpio', found: {file_type}")
	if file_pattern:
		cmd += f" '{file_pattern}'"
	return cmd


def decompress_command(archive: Path) -> str:
	if archive.suffix in (".gzip", ".gz"):
		if use_pigz():
			return f"pigz --stdout --quiet --decompress '{archive}'"
		return f"zcat --stdout --quiet --decompress '{archive}'"
	if archive.suffix in (".bzip2", ".bz2"):
		return f"bzcat --stdout --quiet --decompress '{archive}'"
	if archive.suffix == ".zstd":
		try:
			subprocess.run(["zstdcat", "--version"], capture_output=True, check=True)
		except (subprocess.CalledProcessError, FileNotFoundError) as error:
			raise RuntimeError("Zstdcat not available.") from error
		return f"zstdcat --stdout --quiet --decompress '{archive}'"
	raise RuntimeError(f"Unknown compression of file '{archive}'")


def untar(tar: tarfile.TarFile, destination: Path, file_pattern: str | None = None) -> None:
	relevant_members = []
	if file_pattern:
		for member in tar.getmembers():
			if fnmatch.fnmatch(member.name, file_pattern):
				relevant_members.append(member)
		if not relevant_members:
			raise FileNotFoundError(f"Did not find file pattern {file_pattern} in tar file")
		logger.debug("Extracting members according to file pattern %s: %s", file_pattern, relevant_members)
	tar.extractall(path=destination, members=relevant_members or None)


# Warning: this is specific for linux!
def extract_archive_external(archive: Path, destination: Path, file_pattern: str | None = None) -> None:
	logger.info("Extracting archive %s to destination %s", archive, destination)
	destination.mkdir(parents=True, exist_ok=True)
	if archive.suffixes and archive.suffixes[-1] in (".zstd", ".gz", ".gzip", ".bz2", ".bzip2"):
		create_input = decompress_command(archive.absolute())
	else:
		create_input = f"cat {archive.absolute()}"
	process_archive = extract_command(archive.absolute(), file_pattern=file_pattern)
	with chdir(destination):
		cmd = f"{create_input} | {process_archive}"
		proc = subprocess.run(cmd, shell=True, check=False, capture_output=True, text=True)
		logger.debug("%s output: %s", cmd, proc.stdout + proc.stderr)
		if proc.returncode != 0:
			raise RuntimeError(f"Command {cmd} failed: {proc.stdout + proc.stderr}")


def extract_archive_internal(archive: Path, destination: Path, file_pattern: str | None = None) -> None:
	logger.info("Extracting archive %s to destination %s", archive, destination)
	destination.mkdir(parents=True, exist_ok=True)
	if archive.suffixes and archive.suffixes[-1] == ".zstd":
		decompressor = zstandard.ZstdDecompressor()
		with BytesIO() as buffer, open(archive, mode="rb") as archive_handle:
			_, bytes_written = decompressor.copy_stream(archive_handle, buffer)
			buffer.seek(0)
			with tarfile.open(fileobj=buffer, mode="r") as tar_object:
				untar(tar_object, destination, file_pattern)
		logger.debug("Wrote zstd stream of %s bytes (using %s bytes of memory)", bytes_written, decompressor.memory_size())
	else:
		file_type = get_file_type(archive)
		if archive.suffixes and ".cpio" in archive.suffixes[-2:] or file_type == "cpio":
			raise RuntimeError("Extracting cpio archives is not available on this platform.")
		with tarfile.open(archive, mode="r") as tar_object:  # compression can be None, gz, bz2 or xz
			untar(tar_object, destination, file_pattern)


def extract_archive(archive: Path, destination: Path, file_pattern: str | None = None) -> None:
	use_commands = False
	if is_linux():
		file_type = get_file_type(archive)
		if archive.suffixes and ".cpio" in archive.suffixes[-2:] or file_type == "cpio":
			use_commands = True
		elif (archive.suffixes and archive.suffixes[-1] in (".gz", ".gzip") or file_type == "gz") and use_pigz():
			use_commands = True
	if use_commands:
		return extract_archive_external(archive, destination, file_pattern)
	return extract_archive_internal(archive, destination, file_pattern)


def compress_command(archive: Path, compression: str) -> str:
	if compression in ("gzip", "gz"):
		if use_pigz():
			return f"pigz --rsyncable --quiet - > '{archive}'"
		return f"gzip --rsyncable --quiet - > '{archive}'"
	if compression in ("bzip2", "bz2"):
		return f"bzip2 --quiet - > '{archive}'"
	if compression == "zstd":
		zstd_version = "0"
		try:
			match = re.search(r"\sv([\d\.]+)", subprocess.run(["zstd", "--version"], capture_output=True, check=True, text=True).stdout)
			if match:
				zstd_version = match.group(1)
		except (subprocess.CalledProcessError, FileNotFoundError) as error:
			raise RuntimeError("Zstd not available.") from error
		opts = ""
		if packaging.version.parse(zstd_version) >= packaging.version.parse("1.3.8"):
			# With version 1.3.8 zstd introduced --rsyncable mode.
			opts = "--rsyncable"
		return f"zstd - {opts} -o '{archive}' 2> /dev/null"  # --no-progress is not available for deb9 zstd
	raise RuntimeError(f"Unknown compression '{compression}'")


# Warning: this is specific for linux!
def create_archive_external(
	archive: Path, sources: list[Path], base_dir: Path, compression: str | None = None, dereference: bool = False
) -> None:
	logger.info("Creating archive %s from base_dir %s", archive, base_dir)
	if archive.exists():
		archive.unlink()
	source_string = " ".join((shlex.quote(f"{source.relative_to(base_dir)}") for source in sources))
	dereference_string = "--dereference" if dereference else ""
	# Use -- to signal that no options should be processed afterwards
	if compression:
		cmd = f"{TAR_CREATE_COMMAND} - {dereference_string} -- {source_string} | {compress_command(archive, compression)}"
	else:
		cmd = f"{TAR_CREATE_COMMAND} {archive} {dereference_string} -- {source_string}"
	with chdir(base_dir):
		logger.debug("Executing %s at %s", cmd, base_dir)
		proc = subprocess.run(cmd, shell=True, check=False, capture_output=True, text=True)
		logger.debug("%s output: %s", cmd, proc.stdout + proc.stderr)
		if proc.returncode != 0:
			raise RuntimeError(f"Command {cmd} failed: {proc.stdout + proc.stderr}")


def create_archive_internal(
	archive: Path, sources: list[Path], base_dir: Path, compression: str | None = None, dereference: bool = False
) -> None:
	logger.info("Creating archive %s from base_dir %s", archive, base_dir)
	if archive.exists():
		archive.unlink()
	mode = "w|"
	if compression == "bz2":
		mode = "w|bz2"
	elif compression == "gz":
		mode = "w|gz"

	def set_tarinfo(tarinfo: tarfile.TarInfo) -> tarfile.TarInfo:
		tarinfo.uid = 65534
		tarinfo.uname = "nobody"
		tarinfo.gid = 65534
		tarinfo.gname = "nogroup"
		return tarinfo

	if compression == "zstd":
		with open(archive, mode="wb") as outfile, BytesIO() as buffer:
			with tarfile.open(fileobj=buffer, mode=mode, dereference=dereference) as tar_object:
				for source in sources:
					tar_object.add(source, arcname=source.relative_to(base_dir), filter=set_tarinfo)
			logger.warning("Creating unsyncable package (no zsync or rsync support)")
			# TODO: Set ZSTD_c_rsyncable / ZSTD_c_experimentalParam1 / 500 = 1
			compressor = zstandard.ZstdCompressor()
			buffer.seek(0)
			_, bytes_written = compressor.copy_stream(buffer, outfile)
			logger.debug("Wrote zstd stream of %s bytes (using %s bytes of memory)", bytes_written, compressor.memory_size())
	else:
		# Remark: everything except gz can handle Path-like archive, gz requires str
		with tarfile.open(str(archive), mode=mode, dereference=dereference) as tar_object:
			for source in sources:
				tar_object.add(source, arcname=source.relative_to(base_dir), filter=set_tarinfo)


def create_archive(archive: Path, sources: list[Path], base_dir: Path, compression: str | None = None, dereference: bool = False) -> None:
	if (compression == "gz" and is_linux() and use_pigz()) or (compression == "zstd" and is_linux()):
		return create_archive_external(archive, sources, base_dir, compression, dereference)
	return create_archive_internal(archive, sources, base_dir, compression, dereference)
