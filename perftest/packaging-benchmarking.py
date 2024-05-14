"""
Benchmarking for performance evaluation
"""

import platform
import random
import shutil
import statistics
from datetime import datetime
from pathlib import Path
from typing import Callable
import time
from opsicommon.package.archive import (
	create_archive_external,
	create_archive_internal,
	extract_archive_external,
	extract_archive_internal,
	ArchiveProgressListener,
)
from opsicommon.utils import make_temp_dir

FILES = 25
FILE_SIZE = 15_000_000
COMPRESSIONS = (None, "zstd", "bz2", "gz")
REPETITIONS = 3


class ProgressListener(ArchiveProgressListener):
	pass


def create_source(work_dir: Path) -> None:
	(work_dir / "source").mkdir()
	for idx in range(FILES):
		if idx % 2:
			data = b"opsi" * int(FILE_SIZE / 4)
		else:
			data = random.randbytes(FILE_SIZE)
		(work_dir / "source" / f"file_{idx}").write_bytes(data)


def time_tar_create(work_dir: Path, method: Callable, compression: str | None = None, progress: bool = False) -> None:
	timings = []
	size = 0
	for _ in range(REPETITIONS):
		archive = work_dir / "archive"
		start = time.perf_counter() * 1000
		method(
			archive, [work_dir / "source"], work_dir, compression=compression, progress_listener=ProgressListener() if progress else None
		)
		timings.append(time.perf_counter() * 1000 - start)
		size = archive.stat().st_size
		if _ == 0:
			(Path() / method.__name__ / str(compression)).mkdir(exist_ok=True, parents=True)
			shutil.copy(archive, Path() / method.__name__ / str(compression))
		archive.unlink(missing_ok=True)

	print(f"method: {method.__name__}, compression: {compression}, progress: {progress}, size: {(size/1_000_000):.1f} MB")
	print(f"mean:\t{statistics.mean(timings):.2f}ms")
	print(f"stdev:\t{statistics.stdev(timings):.2f}ms")
	print(f"min:\t{min(timings):.2f}ms")
	print(f"max:\t{max(timings):.2f}ms\n")


def benchmark_tar_create() -> None:
	with make_temp_dir(Path("/tmp")) as temp_dir:
		create_source(temp_dir)
		for compression in COMPRESSIONS:
			for method in (create_archive_internal, create_archive_external):
				if platform.system().lower() != "linux" and method is create_archive_external:
					continue
				for progress in [False] if compression else [False, True]:
					time_tar_create(temp_dir, method, compression, progress)


def time_tar_extract(archive: Path, method: Callable, compression: str | None = None, progress: bool = False) -> None:
	timings = []
	size = archive.stat().st_size

	for _ in range(REPETITIONS):
		with make_temp_dir(Path("/tmp")) as temp_dir:
			start = datetime.now()
			method(archive, temp_dir, progress_listener=ProgressListener() if progress else None)
			timings.append((datetime.now() - start).microseconds / 1000)

	print(f"method: {method.__name__}, compression: {compression}, progress: {progress}, size: {(size/1_000_000):.1f} MB")
	print(f"mean:\t{statistics.mean(timings):.2f}ms")
	print(f"stdev:\t{statistics.stdev(timings):.2f}ms")
	print(f"min:\t{min(timings):.2f}ms")
	print(f"max:\t{max(timings):.2f}ms\n")


def benchmark_tar_extract() -> None:
	with make_temp_dir(Path("/tmp")) as temp_dir:
		create_source(temp_dir)
		for compression in COMPRESSIONS:
			archive = temp_dir / f"archive.tar{f'.{compression}' if compression else ''}"
			create_archive_internal(archive, [temp_dir / "source"], temp_dir, compression=compression)
			for method in (extract_archive_external, extract_archive_internal):
				if platform.system().lower() != "linux" and method is extract_archive_external:
					continue
				for progress in [False] if compression else [False, True]:
					time_tar_extract(archive, method, compression, progress)


if __name__ == "__main__":
	benchmark_tar_create()
	benchmark_tar_extract()
