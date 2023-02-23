"""
handling of archives
"""

import fnmatch
import os
import platform
import re
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
TAR_EXTRACT_COMMAND = "tar -xf - --wildcards"
TAR_CREATE_COMMAND = "tar -cf"
EXCLUDE_DIRS_ON_PACK_REGEX = re.compile(r"(^\.svn$)|(^\.git$)")
EXCLUDE_FILES_ON_PACK_REGEX = re.compile(r"(~$)|(^[Tt]humbs\.db$)|(^\.[Dd][Ss]_[Ss]tore$)")


@lru_cache
def use_pigz() -> bool:
	opsi_conf = OpsiConfig(upgrade_config=False)
	if not opsi_conf.get("packages", "use_pigz"):
		return False
	try:
		pigz_version = subprocess.check_output(["pigz", "--version"]).decode("utf-8")
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
			return f"pigz --stdout --decompress '{archive}'"
		return f"zcat --stdout --quiet --decompress '{archive}'"
	if archive.suffix in (".bzip2", ".bz2"):
		return f"bzcat --stdout --quiet --decompress '{archive}'"
	if archive.suffix == ".zstd":
		try:
			subprocess.check_call("zstdcat --version > /dev/null", shell=True)
		except subprocess.CalledProcessError as error:
			raise RuntimeError("Zstd not available.") from error
		return f"zstdcat --stdout --quiet --decompress '{archive}'"
	raise RuntimeError(f"Unknown compression of file '{archive}'")


# Warning: this is specific for linux!
def extract_archive(archive: Path, destination: Path, file_pattern: str | None = None) -> None:
	logger.info("Extracting archive %s to destination %s", archive, destination)
	if not destination.exists():
		destination.mkdir(parents=True)
	if archive.suffixes and archive.suffixes[-1] in (".zstd", ".gz", ".gzip", ".bz2", ".bzip2"):
		create_input = decompress_command(archive.absolute())
	else:
		create_input = f"cat {archive.absolute()}"
	process_archive = extract_command(archive.absolute(), file_pattern=file_pattern)
	with chdir(destination):
		subprocess.check_call(f"{create_input} | {process_archive}", shell=True)


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


def extract_archive_universal(archive: Path, destination: Path, file_pattern: str | None = None) -> None:
	logger.info("Extracting archive %s to destination %s", archive, destination)
	if not destination.exists():
		destination.mkdir(parents=True)
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
			logger.warning("Found cpio archive. Falling back to old method")
			if platform.system().lower() != "linux":
				raise RuntimeError("Extracting cpio archives is only available on linux.")
			extract_archive(archive, destination, file_pattern=file_pattern)
			return
		with tarfile.open(archive, mode="r") as tar_object:  # compression can be None, gz, bz2 or xz
			untar(tar_object, destination, file_pattern)


def compress_command(archive: Path, compression: str) -> str:
	if compression in ("bzip2", "bz2"):
		return f"bzip2 --quiet - > '{archive}'"
	if compression == "zstd":
		try:
			subprocess.check_call("zstd --version > /dev/null", shell=True)
		except subprocess.CalledProcessError as error:
			raise RuntimeError("Zstd not available.") from error
		return f"zstd - -o '{archive}' 2> /dev/null"  # --no-progress is not available for deb9 zstd
	raise RuntimeError(f"Unknown compression '{compression}'")


# Warning: this is specific for linux!
def create_archive(archive: Path, sources: list[Path], base_dir: Path, compression: str | None = None, dereference: bool = False) -> None:
	logger.info("Creating archive %s from base_dir %s", archive, base_dir)
	if archive.exists():
		archive.unlink()
	source_string = " ".join((str(source.relative_to(base_dir)) for source in sources))
	dereference_string = "--dereference" if dereference else ""
	if compression:
		cmd = f"{TAR_CREATE_COMMAND} - {dereference_string} {source_string} | {compress_command(archive, compression)}"
	else:
		cmd = f"{TAR_CREATE_COMMAND} {archive} {dereference_string} {source_string}"
	with chdir(base_dir):
		logger.debug("Executing %s at %s", cmd, base_dir)
		subprocess.check_call(cmd, shell=True)


def create_archive_universal(
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
	if compression == "zstd":
		with open(archive, mode="wb") as outfile, BytesIO() as buffer:
			with tarfile.open(fileobj=buffer, mode=mode, dereference=dereference) as tar_object:
				for source in sources:
					tar_object.add(source, arcname=source.relative_to(base_dir))
			compressor = zstandard.ZstdCompressor()
			buffer.seek(0)
			_, bytes_written = compressor.copy_stream(buffer, outfile)
			logger.debug("Wrote zstd stream of %s bytes (using %s bytes of memory)", bytes_written, compressor.memory_size())
	else:
		# Remark: everything except gz can handle Path-like archive, gz requires str
		with tarfile.open(str(archive), mode=mode, dereference=dereference) as tar_object:
			for source in sources:
				tar_object.add(source, arcname=source.relative_to(base_dir))
