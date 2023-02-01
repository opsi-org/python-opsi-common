"""
handling of package content, hash files and more
"""
import os
import subprocess
from hashlib import md5
from pathlib import Path

from opsicommon.logging import get_logger

logger = get_logger("opsicommon.package")


def md5sum(path: Path) -> str:
	md5object = md5()
	with open(path, "rb") as file_to_hash:
		for data in iter(lambda: file_to_hash.read(524288), b""):
			md5object.update(data)
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
			except Exception as err:  # pylint: disable=broad-except
				logger.error(err, exc_info=True)
		package_content_file.write_text("\n".join(lines), encoding="utf-8")
	except Exception as err:  # pylint: disable=broad-except
		logger.error(err, exc_info=True)
		raise RuntimeError(f"Failed to create package content file of directory '{base_dir}': {err}") from err
	return package_content_file


def create_package_md5_file(package_path: Path, filename: Path | None = None) -> Path:
	if not filename:
		filename = Path(f"{package_path}.md5")
	filename.write_text(md5sum(package_path), encoding="utf-8")
	return filename


def create_package_zsync_file(package_path: Path, filename: Path | None = None) -> Path:
	if not filename:
		filename = Path(f"{package_path}.zsync")

	try:
		subprocess.check_call(f"zsyncmake -u '{package_path.name}' -o '{filename}' '{package_path}'", shell=True)
	except subprocess.CalledProcessError:
		try:
			subprocess.check_call(f"zsyncmake-curl -u '{package_path.name}' -o '{filename}' '{package_path}'", shell=True)
		except subprocess.CalledProcessError as error:
			raise FileNotFoundError("zsyncmake(-curl) binary not found in PATH") from error

	header = {}
	with open(filename, "rb") as file:
		for line in iter(lambda: file.readline().strip(), b""):
			key, value = line.decode().split(":", 1)
			header[key.strip()] = value.strip()
		# Header and data are divided by an empty line
		data = file.read()

	with open(filename, "wb") as file:
		for key, value in header.items():
			if key.lower() == "mtime":
				continue
			file.write(f"{key}: {value}\n".encode())
		file.write("\n".encode())
		file.write(data)
	return filename
