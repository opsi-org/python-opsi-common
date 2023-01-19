"""
handling of serialization and deserialization
"""

import os
import re
import subprocess
from pathlib import Path

import packaging.version

# IDEA: tar can use --zstd
CPIO_EXTRACT_COMMAND = "cpio -u --extract --quiet --no-preserve-owner --no-absolute-filenames"
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


def deserialize_command(archive: Path, destination: Path, file_pattern: str | None = None) -> str:
	# Look for cpio and tar in last or second last position (for compressed archives like .tar.gz)
	# It is assumed that the deserialize command gets data via stdin in an uncompressed state
	if archive.suffixes and ".cpio" in archive.suffixes[-2:]:
		cmd = f"{CPIO_EXTRACT_COMMAND} --directory {destination}"
	elif archive.suffixes and ".tar" in archive.suffixes[-2:]:
		cmd = f"{TAR_EXTRACT_COMMAND} --directory {destination}"
	else:
		file_type = get_file_type(archive)
		if file_type == "tar":
			cmd = f"{TAR_EXTRACT_COMMAND} --directory {destination}"
		elif file_type == "cpio":
			cmd = f"{CPIO_EXTRACT_COMMAND} --directory {destination}"
		else:
			raise TypeError(f"Archive to deserialize must be 'tar' or 'cpio', found: {file_type}")
	if file_pattern:
		cmd += f" '{file_pattern}'"
	return cmd


def extract_command(archive: Path) -> str:
	if archive.suffix in (".gzip", ".gz"):
		if pigz_available():
			return f"pigz --stdout --decompress '{archive}'"
		return f"zcat --stdout --decompress '{archive}'"
	if archive.suffix in (".bzip2", ".bz2"):
		return f"bzcat --stdout --decompress '{archive}'"
	if archive.suffix == ".zstd":
		try:
			subprocess.check_call("zstdcat --version", shell=True)
		except subprocess.CalledProcessError as error:
			raise RuntimeError("Zstd not available.") from error
		return f"zstdcat --stdout --decompress '{archive}'"
	raise RuntimeError(f"Unknown compression of file '{archive}'")


# Warning: this is specific for linux!
def deserialize(archive: Path, destination: Path, file_pattern: str | None = None) -> None:
	if not destination.exists():
		destination.mkdir(parents=True)
	if archive.suffixes and archive.suffixes[-1] in (".zstd", ".gz", ".gzip", ".bz2", ".bzip2"):
		create_input = extract_command(archive)
	else:
		create_input = f"cat {archive}"
	process_archive = deserialize_command(archive, destination, file_pattern=file_pattern)
	subprocess.check_call(f"{create_input} | {process_archive}", shell=True)


def compress_command(archive: Path, compression: str) -> str:
	if compression in ("bzip2", "bz2"):
		return f"bzip2 - > '{archive}'"
	if compression == "zstd":
		try:
			subprocess.check_call("zstd --version", shell=True)
		except subprocess.CalledProcessError as error:
			raise RuntimeError("Zstd not available.") from error
		return f"zstd - -o '{archive}'"
	raise RuntimeError(f"Unknown compression of file '{archive}'")


def serialize(archive: Path, sources: list[Path], base_dir: Path, compression: str | None = None) -> None:
	print("serializing", sources, "rooted at", base_dir, "to", archive)
	if archive.exists():
		archive.unlink()
	source_string = " ".join((str(source.relative_to(base_dir)) for source in sources))
	if compression:
		cmd = f"{TAR_CREATE_COMMAND} - {source_string} | {compress_command(archive, compression)}"
	else:
		cmd = f"{TAR_CREATE_COMMAND} {archive} {source_string}"
	old_path = os.getcwd()
	try:
		os.chdir(str(base_dir))
		subprocess.check_call(cmd, shell=True)
	finally:
		os.chdir(old_path)
