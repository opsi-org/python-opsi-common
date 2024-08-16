# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
handling of package content, hash files and more
"""

import os
from hashlib import md5
from pathlib import Path
from typing import Callable

from pyzsync import create_zsync_file  # type: ignore[import]

from opsicommon.logging import get_logger

logger = get_logger("opsicommon.package")


def md5sum(path: Path, progress_callback: Callable | None = None) -> str:
	md5object = md5()
	file_size = path.stat().st_size
	position = 0
	if progress_callback:
		progress_callback(position, file_size)

	block_size = 524288
	with open(path, "rb") as file_to_hash:
		for data in iter(lambda: file_to_hash.read(block_size), b""):
			md5object.update(data)
			if progress_callback:
				position += len(data)
				progress_callback(position, file_size)
	return md5object.hexdigest()


def create_package_content_file(base_dir: Path) -> Path:
	def handle_directory(path: Path) -> tuple[str, int, str]:
		logger.trace("Processing '%s' as directory", path)
		return "d", 0, ""

	def handle_file(path: Path) -> tuple[str, int, str]:
		logger.trace("Processing '%s' as file", path)
		return "f", os.path.getsize(path), md5sum(path)

	package_content_file = base_dir / f"{base_dir.name}.files"
	if package_content_file.exists():
		package_content_file.unlink()
	logger.info("Creating package content file %s", package_content_file)
	lines = []

	try:
		for path in base_dir.rglob("*"):
			try:
				if path.is_dir():
					entry_type, size, additional = handle_directory(path)
				else:
					entry_type, size, additional = handle_file(path)
				filename = str(path.relative_to(base_dir)).replace("'", "\\'")
				lines.append(f"{entry_type} '{filename}' {size} {additional}")
			except Exception as err:
				logger.error(err, exc_info=True)
		package_content_file.write_text("\n".join(lines), encoding="utf-8")
	except Exception as err:
		logger.error(err, exc_info=True)
		raise RuntimeError(f"Failed to create package content file of directory '{base_dir}': {err}") from err
	return package_content_file


def create_package_md5_file(package_path: Path, filename: Path | None = None, progress_callback: Callable | None = None) -> Path:
	if not filename:
		filename = Path(f"{package_path}.md5")
	filename.write_text(md5sum(package_path, progress_callback), encoding="utf-8")
	return filename


def create_package_zsync_file(package_path: Path, filename: Path | None = None, progress_callback: Callable | None = None) -> Path:
	if not filename:
		filename = Path(f"{package_path}.zsync")
	create_zsync_file(file=package_path, zsync_file=filename, legacy_mode=True, progress_callback=progress_callback)
	return filename
