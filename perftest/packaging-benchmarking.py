"""
Benchmarking for performance evaluation
"""

import platform
import random
import shutil
import statistics
import string
from datetime import datetime
from pathlib import Path
from typing import Callable

from opsicommon.package.archive import (
	create_archive,
	create_archive_universal,
	extract_archive,
	extract_archive_universal,
)
from opsicommon.utils import make_temp_dir

REPETITIONS = 20
FILES = 10
CHARS_PER_FILE = 1_000_000


def time_tar_create(work_dir: Path, method: Callable, compression: str | None = None) -> None:
	timings = []

	for _ in range(REPETITIONS):
		archive = work_dir / "archive"
		start = datetime.now()
		method(archive, [work_dir / "source"], work_dir, compression=compression)
		timings.append((datetime.now() - start).microseconds / 1000)
		if _ == 0:
			(Path() / method.__name__ / str(compression)).mkdir(exist_ok=True, parents=True)
			shutil.copy(archive, Path() / method.__name__ / str(compression))
		archive.unlink(missing_ok=True)

	print(f"method: {method.__name__}, compression: {compression}")
	print(f"mean:\t{statistics.mean(timings):.3f}ms")
	print(f"stdev:\t{statistics.stdev(timings):.3f}ms")
	print(f"min:\t{min(timings)}ms")
	print(f"max:\t{max(timings)}ms\n")


def benchmark_tar_create() -> None:
	with make_temp_dir(Path("/tmp")) as temp_dir:
		(temp_dir / "source").mkdir()
		for filename in range(FILES):
			text = "".join(random.choices(string.ascii_uppercase + string.digits, k=CHARS_PER_FILE))
			(temp_dir / "source" / str(filename)).write_text(text)
		for compression in (None, "zstd", "bz2", "gz"):
			for method in (create_archive, create_archive_universal):
				if compression == "gz" and method is create_archive:
					continue
				if platform.system().lower() != "linux" and method is create_archive:
					continue
				time_tar_create(temp_dir, method, compression)


def time_tar_extract(archive: Path, method: Callable, compression: str | None = None) -> None:
	timings = []

	for _ in range(REPETITIONS):
		with make_temp_dir(Path("/tmp")) as temp_dir:
			start = datetime.now()
			method(archive, temp_dir)
			timings.append((datetime.now() - start).microseconds / 1000)

	print(f"method: {method.__name__}, compression: {compression}")
	print(f"mean:\t{statistics.mean(timings):.3f}ms")
	print(f"stdev:\t{statistics.stdev(timings):.3f}ms")
	print(f"min:\t{min(timings)}ms")
	print(f"max:\t{max(timings)}ms\n")


def benchmark_tar_extract() -> None:
	with make_temp_dir(Path("/tmp")) as temp_dir:
		(temp_dir / "source").mkdir()
		for filename in range(FILES):
			text = "".join(random.choices(string.ascii_uppercase + string.digits, k=CHARS_PER_FILE))
			(temp_dir / "source" / str(filename)).write_text(text)
		for compression in (None, "zstd", "bz2", "gz"):
			archive = temp_dir / f"archive.tar{f'.{compression}' if compression else ''}"
			create_archive_universal(archive, [temp_dir / "source"], temp_dir, compression=compression)
			for method in (extract_archive, extract_archive_universal):
				if platform.system().lower() != "linux" and method is create_archive:
					continue
				time_tar_extract(archive, method, compression)


if __name__ == "__main__":
	benchmark_tar_create()
	benchmark_tar_extract()
