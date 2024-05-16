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
import subprocess
import tarfile
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from threading import Lock
import time
from typing import IO, Any, Generator
from contextlib import nullcontext
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
		self.completed = min(self.total, completed)
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


class ProgressFileWrapper:
	def __init__(self, filesize: int, fileobj: IO[bytes], progress: ArchiveProgress | None = None):
		self._filesize = filesize
		self._fileobj = fileobj
		self._progress = progress
		self._pos = 0
		self._last_pos = 0

	def _update_progress(self, data_size: int) -> None:
		if not self._progress:
			return
		self._pos += data_size
		diff = self._pos - self._last_pos
		if diff > 1_000_000:
			self._progress.advance(diff)
			self._last_pos = self._pos

	def read(self, size: int = -1) -> bytes:
		data = self._fileobj.read(size)
		self._update_progress(len(data))
		return data

	def __getattr__(self, name: str) -> Any:
		return getattr(self._fileobj, name)

	def __del__(self) -> None:
		if not self._progress:
			return
		self._progress.advance(self._filesize - self._last_pos)


class ProgressTarFile(tarfile.TarFile):
	def __init__(self, *args: Any, **kwargs: Any) -> None:
		self._progress = kwargs.pop("progress", None)
		if self._progress:
			assert isinstance(self._progress, ArchiveProgress)
		super().__init__(*args, **kwargs)

	def addfile(self, tarinfo: tarfile.TarInfo, fileobj: IO[bytes] | None = None) -> None:
		if fileobj and self._progress:
			fileobj = ProgressFileWrapper(filesize=tarinfo.size, fileobj=fileobj, progress=self._progress)  # type: ignore[assignment]
		return super().addfile(tarinfo, fileobj)


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
	archive = archive.absolute()

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
	archive = archive.absolute()

	logger.info("Extracting archive %s to destination %s", archive, destination)
	destination.mkdir(parents=True, exist_ok=True)

	file_type = get_file_type(archive)
	if archive.suffixes and ".cpio" in archive.suffixes[-2:] or file_type == "cpio":
		raise RuntimeError("Extracting cpio archives is not available on this platform.")

	filesize = archive.stat().st_size
	progress: ArchiveProgress | None = None
	if progress_listener:
		progress = ArchiveProgress(total=filesize)
		progress.register_progress_listener(progress_listener)

	is_zstd = archive.suffixes and archive.suffixes[-1] == ".zstd"
	with open(archive, "rb") as file:
		file = ProgressFileWrapper(filesize=filesize, fileobj=file, progress=progress)  # type: ignore[assignment]
		with zstandard.ZstdDecompressor().stream_reader(file) if is_zstd else nullcontext(file) as fileobj:  # type: ignore[attr-defined]
			with tarfile.open(fileobj=fileobj, mode="r:" if is_zstd else "r") as tar_object:  # compression can be None, gz, bz2 or xz
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


def get_files(paths: list[Path], follow_symlinks: bool = False) -> Generator[tuple[Path, int], None, None]:
	for path in paths:
		if path.is_dir():
			for root, dirnames, filenames in os.walk(path, followlinks=follow_symlinks):
				if not filenames and not dirnames:
					# Empty directory
					yield Path(root), 0
					continue
				for filename in filenames:
					file = Path(root) / filename
					yield file, file.stat().st_size

		else:
			yield path, path.stat().st_size


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
	if not is_linux():
		raise RuntimeError("External archiving is only available on linux")
	from fcntl import fcntl, F_GETFL, F_SETFL

	archive = archive.absolute()
	logger.info("Creating archive %s from base_dir %s", archive, base_dir)
	if compression == "bz2":
		logger.warning("Creating unsyncable package (no zsync or rsync support)")

	if archive.exists():
		archive.unlink()

	archive_file = "-" if compression else f"'{archive}'"
	cmd = (
		f'{TAR_CREATE_COMMAND} {archive_file} {"--dereference" if dereference else ""}'
		' --files-from=- --checkpoint=100 --checkpoint-action="echo=|%u|"'
	)
	if compression:
		cmd += f" | {compress_command(archive, compression)}"

	files = list(get_files(sources, follow_symlinks=dereference))
	logger.trace("Files: %r", files)
	total_size = sum(size for _, size in files)
	logger.info("Adding %d files with a total size of %d", len(files), total_size)

	progress: ArchiveProgress | None = None
	if progress_listener:
		progress = ArchiveProgress(total=total_size)
		progress.register_progress_listener(progress_listener)

	checkpoint_re = re.compile(r"\|(\d+)\|")

	def read_checkpoint_number(proc: subprocess.Popen, progress: ArchiveProgress | None) -> str:
		assert proc.stderr
		try:
			raw_data = proc.stderr.read()
		except OSError:
			return ""
		if not raw_data:
			return ""
		data = raw_data.decode(errors="ignore")
		line = data.strip().split("\n")[-1]
		match = checkpoint_re.search(line)
		if not match:
			return data
		number = int(match.group(1))
		logger.trace("Read checkpoint number %d", number)
		if progress:
			progress.set_completed(number * 512 * 20)
		return data

	with chdir(base_dir):
		# Cannot get a reliable exit code on piped commands because dash does not support pipefail
		logger.debug("Executing %s at %s", cmd, base_dir)
		proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
		assert proc.stdin
		assert proc.stdout
		assert proc.stderr
		fileno = proc.stderr.fileno()
		flags = fcntl(fileno, F_GETFL)
		fcntl(fileno, F_SETFL, flags | os.O_NONBLOCK)
		stderr = ""
		for file in files:
			file_path = file[0].relative_to(base_dir)
			file_str = str(file_path)
			logger.trace("Adding file: '%s'", file_str)
			if "\n" in file_str:
				raise ValueError(f"Invalid filename '{file_str}'")
			proc.stdin.write(f"{file_str}\n".encode())
			proc.stdin.flush()
			if data := read_checkpoint_number(proc, progress):
				stderr += data

		logger.debug("All filenames sent, closing stdin")
		proc.stdin.close()
		while proc.poll() is None:
			if data := read_checkpoint_number(proc, progress):
				stderr += data
			time.sleep(0.5)

		logger.debug("Process ended with exit code %r", proc.returncode)
		if progress:
			progress.set_completed(total_size)
		try:
			stderr += proc.stderr.read().decode(errors="ignore")
		except Exception:
			pass
		out = proc.stdout.read().decode(errors="ignore") + stderr
		logger.debug("%s output: %s", cmd, out)
		if proc.returncode != 0 or "Exiting with failure status" in out:
			raise RuntimeError(f"Command {cmd} failed: {out}")


def create_archive_internal(
	archive: Path,
	sources: list[Path],
	base_dir: Path,
	compression: str | None = None,
	dereference: bool = False,
	progress_listener: ArchiveProgressListener | None = None,
) -> None:
	archive = archive.absolute()

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

	files = list(get_files(sources, follow_symlinks=dereference))
	logger.trace("Files: %r", files)
	total_size = sum(size for _, size in files)
	logger.info("Adding %d files with a total size of %d", len(files), total_size)

	progress: ArchiveProgress | None = None
	if progress_listener:
		progress = ArchiveProgress(total=total_size)
		progress.register_progress_listener(progress_listener)

	def set_tarinfo(tarinfo: tarfile.TarInfo) -> tarfile.TarInfo:
		tarinfo.uid = 65534
		tarinfo.uname = "nobody"
		tarinfo.gid = 65534
		tarinfo.gname = "nogroup"
		return tarinfo

	if compression == "zstd":
		compressor = zstandard.ZstdCompressor()
		with open(archive, "wb") as archive_file:
			with compressor.stream_writer(archive_file) as zstd_writer:
				with ProgressTarFile.open(fileobj=zstd_writer, dereference=dereference, mode="w:") as tar_object:  # type: ignore[call-arg]
					for file in files:
						tar_object.add(file[0], arcname=file[0].relative_to(base_dir), filter=set_tarinfo)
						if progress:
							progress.advance(file[1])
			if progress:
				progress.set_completed(total_size)
		return

	with ProgressTarFile.open(name=str(archive), mode=mode, dereference=dereference, progress=progress) as tar_object:  # type: ignore[call-arg]
		for file in files:
			tar_object.add(file[0], arcname=file[0].relative_to(base_dir), filter=set_tarinfo)
			if progress:
				progress.advance(file[1])
		if progress:
			progress.set_completed(total_size)


def create_archive(
	archive: Path,
	sources: list[Path],
	base_dir: Path,
	*,
	compression: str | None = None,
	dereference: bool = False,
	progress_listener: ArchiveProgressListener | None = None,
) -> None:
	if compression == "gz" and is_linux() and use_pigz():
		return create_archive_external(
			archive, sources, base_dir, compression=compression, dereference=dereference, progress_listener=progress_listener
		)
	return create_archive_internal(
		archive, sources, base_dir, compression=compression, dereference=dereference, progress_listener=progress_listener
	)
