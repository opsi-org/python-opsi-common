# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
test_package_wim
"""

from datetime import datetime
from pathlib import Path
from subprocess import run, CalledProcessError

import pytest
from opsicommon.package.wim import wim_capture, wim_info

WIMLIB_MISSING = False
WIMLIB_ERROR = ""
try:
	run(["wimlib-imagex", "--version"], check=True, capture_output=True, text=True)
except (FileNotFoundError, CalledProcessError) as err:
	WIMLIB_MISSING = True
	WIMLIB_ERROR = str(err)


@pytest.mark.skipif(WIMLIB_MISSING, reason=WIMLIB_ERROR)
def test_wim_capture(tmp_path: Path) -> None:
	wim_file = tmp_path / "test.wim"
	source = tmp_path / "source"
	(source / "testdir1").mkdir(parents=True)
	(source / "testdir2").mkdir()
	(source / "testfile1").write_text("opsi")
	(source / "testdir1" / "testfile2").write_text("opsi")
	wim_capture(
		tmp_path, wim_file, image_name="image name", image_description="image description", boot=True, dereference=True, unix_data=True
	)
	assert wim_file.exists()

	info = wim_info(wim_file)
	assert info.boot_index == 1
	assert len(info.guid) == 32
	assert info.image_count == 1
	assert info.part_number == 1
	assert info.total_parts == 1
	assert info.total_bytes > 0
	assert len(info.images) == 1

	img = info.images[0]
	assert img.index == 1
	assert img.name == "image name"
	assert img.description == "image description"
	assert img.dir_count == 4
	assert img.file_count == 2
	assert img.hardlink_bytes == 0
	assert abs((img.creation_time - datetime.utcnow()).total_seconds()) < 10
	assert abs((img.modification_time - datetime.utcnow()).total_seconds()) < 10
