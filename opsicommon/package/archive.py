"""
handling of archives
"""

import os
import re
import subprocess
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

import packaging.version
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


def pigz_available() -> bool:
	try:  # TODO: check if configured to use pigz? in opsiconf
		pigz_version = subprocess.check_output("pigz --version", shell=True).decode("utf-8")
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
		if pigz_available():
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
	if not destination.exists():
		destination.mkdir(parents=True)
	if archive.suffixes and archive.suffixes[-1] in (".zstd", ".gz", ".gzip", ".bz2", ".bzip2"):
		create_input = decompress_command(archive.absolute())
	else:
		create_input = f"cat {archive.absolute()}"
	process_archive = extract_command(archive.absolute(), file_pattern=file_pattern)
	with chdir(destination):
		subprocess.check_call(f"{create_input} | {process_archive}", shell=True)


def compress_command(archive: Path, compression: str) -> str:
	if compression in ("bzip2", "bz2"):
		return f"bzip2 --quiet - > '{archive}'"
	if compression == "zstd":
		try:
			subprocess.check_call("zstd --version > /dev/null", shell=True)
		except subprocess.CalledProcessError as error:
			raise RuntimeError("Zstd not available.") from error
		return f"zstd - -o '{archive}' > /dev/null"  # --no-progress is not available for deb9 zstd
	raise RuntimeError(f"Unknown compression '{compression}'")


def create_archive(archive: Path, sources: list[Path], base_dir: Path, compression: str | None = None) -> None:
	if archive.exists():
		archive.unlink()
	source_string = " ".join((str(source.relative_to(base_dir)) for source in sources))
	if compression:
		cmd = f"{TAR_CREATE_COMMAND} - {source_string} | {compress_command(archive, compression)}"
	else:
		cmd = f"{TAR_CREATE_COMMAND} {archive} {source_string}"
	with chdir(base_dir):
		logger.debug("Executing %s at %s", cmd, base_dir)
		subprocess.check_call(cmd, shell=True)
