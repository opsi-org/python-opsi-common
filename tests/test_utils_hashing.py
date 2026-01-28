# opsicommon is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2025 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0-only

from pathlib import Path

import pytest

from opsicommon.utils.hashing import compute_file_hash, verify_file_hash


def test_verify_file_hash(tmp_path: Path) -> None:
	file_path = tmp_path / "testfile.bin"
	file_path.write_bytes(b"Test data for hashing.\n" * 1000)

	assert compute_file_hash(file_path, "md5") == "1ec7769251775e55268a584de164f320"
	assert compute_file_hash(file_path, "blake3") == "20294ccbccc9eb04e6c8245213920d3be812de6ed1fb7e727526de4189acc5a9"

	assert verify_file_hash("1ec7769251775e55268a584de164f320", file_path, "md5")
	assert verify_file_hash("20294ccbccc9eb04e6c8245213920d3be812de6ed1fb7e727526de4189acc5a9", file_path, "blake3")
	assert not verify_file_hash("04e6c8245213920d3be812de6ed1fb7e", file_path, "md5")
	assert not verify_file_hash("04e6c8245213920d3be812de6ed1fb7e", file_path, "blake3")

	with pytest.raises(ValueError, match="Invalid hash method 'sha256', supported are 'blake3' and 'md5'"):
		compute_file_hash(file_path, "sha256")  # type: ignore[invalid-argument-type]
		verify_file_hash("somehash", file_path, "sha256")  # type: ignore[invalid-argument-type]
