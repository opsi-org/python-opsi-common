# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
handling of archives
"""
from __future__ import annotations

from abc import ABC
from dataclasses import dataclass, field
import fnmatch
import os
import re
import shlex
import subprocess
import tarfile
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from threading import Lock
import time
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
CPIO_EXTRACT_COMMAND = "cpio --unconditional --extract --make-directories --quiet --no-preserve-owner --no-absolute-filenames"
TAR_EXTRACT_COMMAND = "tar --wildcards --no-same-owner --extract --file -"
TAR_CREATE_COMMAND = "tar --owner=nobody --group=nogroup --create --file"
EXCLUDE_DIRS_ON_PACK_REGEX = re.compile(r"(^\.svn$)|(^\.git$)")
EXCLUDE_FILES_ON_PACK_REGEX = re.compile(r"(~$)|(^[Tt]humbs\.db$)|(^\.[Dd][Ss]_[Ss]tore$)")


@dataclass
class ArchiveProgress:
	total: int = 100
	completed: int = 0
	percent_completed: float = 0.0
	_listener: list[ArchiveProgressListener] = field(default_factory=list)
	_listener_lock: Lock = field(default_factory=Lock)
	_last_notification = 0
	_notification_interval = 0.5

	def set_completed(self, completed: int) -> None:
		self.completed = completed
		percent_completed = self.percent_completed
		self.percent_completed = round(self.completed * 100 / self.total if self.total > 0 else 1.0, 2)
		if percent_completed == self.percent_completed:
			return
		now = time.time()
		if now - self._last_notification < self._notification_interval:
			return
		self._notification_interval = now
		with self._listener_lock:
			for listener in self._listener:
				listener.progress_changed(self)

	def advance(self, amount: int) -> None:
		self.set_completed(self.completed + amount)

	def register_progress_listener(self, listener: ArchiveProgressListener) -> None:
		with self._listener_lock:
			if listener not in self._listener:
				self._listener.append(listener)

	def unregister_progress_listener(self, listener: ArchiveProgressListener) -> None:
		with self._listener_lock:
			if listener in self._listener:
				self._listener.remove(listener)


class ArchiveProgressListener(ABC):
	def progress_changed(self, progress: ArchiveProgress) -> None:
		"""
		Called when the progress state changes.
		"""


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
	except (FileNotFoundError, subprocess.CalledProcessError, ValueError):
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
			return "pigz --stdout --quiet --decompress"
		return "gunzip --stdout --quiet --decompress"
	if archive.suffix in (".bzip2", ".bz2"):
		return "bunzip2 --stdout --quiet --decompress"
	if archive.suffix == ".zstd":
		try:
			subprocess.run(["zstdcat", "--version"], capture_output=True, check=True)
		except (subprocess.CalledProcessError, FileNotFoundError) as error:
			raise RuntimeError("Zstdcat not available.") from error
		return "zstd --stdout --quiet --decompress"
	raise RuntimeError(f"Unknown compression of file '{archive}'")


def untar(tar: tarfile.TarFile, destination: Path, file_pattern: str | None = None) -> None:
	extracted_members = 0
	for member in tar:
		if file_pattern and not fnmatch.fnmatch(member.name, file_pattern):
			logger.debug("Member does not match file pattern %r: %r", file_pattern, member.name)
			continue
		logger.debug("Extracting member: %r", member.name)
		tar.extract(member, path=destination)
		extracted_members += 1

	if file_pattern and not extracted_members:
		raise FileNotFoundError(f"Did not find file pattern {file_pattern} in tar file")


# Warning: this is specific for linux!
def extract_archive_external(
	archive: Path, destination: Path, *, file_pattern: str | None = None, progress_listener: ArchiveProgressListener | None = None
) -> None:
	logger.info("Extracting archive %s to destination %s", archive, destination)
	destination.mkdir(parents=True, exist_ok=True)

	cmd = ""
	if archive.suffixes and archive.suffixes[-1] in (".zstd", ".gz", ".gzip", ".bz2", ".bzip2"):
		cmd = decompress_command(archive.absolute()) + " | "
	cmd += extract_command(archive.absolute(), file_pattern=file_pattern)

	chunk_size = 512 * 1024
	progress: ArchiveProgress | None = None
	if progress_listener:
		progress = ArchiveProgress(total=archive.stat().st_size)
		progress.register_progress_listener(progress_listener)
	with chdir(destination):
		proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
		assert proc.stdin
		assert proc.stdout
		assert proc.stderr
		with open(archive, "rb") as file:
			while True:
				data = file.read(chunk_size)
				if data:
					proc.stdin.write(data)
					proc.stdin.flush()
					if progress:
						progress.advance(len(data))
				else:
					proc.stdin.close()
					break
		proc.wait(timeout=7200)
		out = proc.stdout.read().decode(errors="ignore") + proc.stderr.read().decode(errors="ignore")
		logger.debug("%s output: %s", cmd, out)
		if proc.returncode != 0:
			raise RuntimeError(f"Command {cmd} failed: {out}")


def extract_archive_internal(
	archive: Path, destination: Path, *, file_pattern: str | None = None, progress_listener: ArchiveProgressListener | None = None
) -> None:
	logger.info("Extracting archive %s to destination %s", archive, destination)
	destination.mkdir(parents=True, exist_ok=True)

	if archive.suffixes and archive.suffixes[-1] == ".zstd":
		decompressor = zstandard.ZstdDecompressor()
		with open(archive, "rb") as file:
			with decompressor.stream_reader(file) as zstd_reader:
				with tarfile.open(fileobj=zstd_reader, mode="r:") as tar_object:  # compression can be None, gz, bz2 or xz
					untar(tar_object, destination, file_pattern)
		return

	file_type = get_file_type(archive)
	if archive.suffixes and ".cpio" in archive.suffixes[-2:] or file_type == "cpio":
		raise RuntimeError("Extracting cpio archives is not available on this platform.")

	with tarfile.open(name=str(archive), mode="r") as tar_object:  # compression can be None, gz, bz2 or xz
		untar(tar_object, destination, file_pattern)


def extract_archive(
	archive: Path, destination: Path, *, file_pattern: str | None = None, progress_listener: ArchiveProgressListener | None = None
) -> None:
	use_commands = False
	if is_linux():
		file_type = get_file_type(archive)
		if archive.suffixes and ".cpio" in archive.suffixes[-2:] or file_type == "cpio":
			use_commands = True
		elif (archive.suffixes and archive.suffixes[-1] in (".gz", ".gzip") or file_type == "gz") and use_pigz():
			use_commands = True
	if use_commands:
		return extract_archive_external(archive, destination, file_pattern=file_pattern, progress_listener=progress_listener)
	return extract_archive_internal(archive, destination, file_pattern=file_pattern, progress_listener=progress_listener)


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
	archive: Path,
	sources: list[Path],
	base_dir: Path,
	*,
	compression: str | None = None,
	dereference: bool = False,
	progress_listener: ArchiveProgressListener | None = None,
) -> None:
	logger.info("Creating archive %s from base_dir %s", archive, base_dir)
	if compression == "bz2":
		logger.warning("Creating unsyncable package (no zsync or rsync support)")

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
	if compression == "bz2":
		logger.warning("Creating unsyncable package (no zsync or rsync support)")

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
		compressor = zstandard.ZstdCompressor()
		with open(archive, "wb") as file:
			with compressor.stream_writer(file) as zstd_writer:
				with tarfile.open(fileobj=zstd_writer, dereference=dereference, mode="w:") as tar_object:
					for source in sources:
						tar_object.add(source, arcname=source.relative_to(base_dir), filter=set_tarinfo)
		return

	# Remark: everything except gz can handle Path-like archive, gz requires str
	with tarfile.open(name=str(archive), mode=mode, dereference=dereference) as tar_object:
		for source in sources:
			tar_object.add(source, arcname=source.relative_to(base_dir), filter=set_tarinfo)


def create_archive(archive: Path, sources: list[Path], base_dir: Path, compression: str | None = None, dereference: bool = False) -> None:
	if compression == "gz" and is_linux() and use_pigz():
		return create_archive_external(archive, sources, base_dir, compression, dereference)
	return create_archive_internal(archive, sources, base_dir, compression, dereference)
