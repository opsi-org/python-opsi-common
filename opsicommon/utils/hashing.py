# opsicommon is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2025 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0-only

from hashlib import file_digest
from pathlib import Path
from typing import Literal

from blake3 import blake3


def verify_file_hash(hash: str, file_path: Path, algorithm: Literal["blake3", "md5"]) -> bool:
	"""
	Verify the hash of a file using the specified algorithm.
	Returns True if the computed hash matches the provided hash, False otherwise.
	"""
	return hash == compute_file_hash(file_path, algorithm)


def compute_file_hash(file_path: Path, algorithm: Literal["blake3", "md5"]) -> str:
	"""
	Compute the hash of a file using the specified algorithm.
	returns the hexadecimal digest of the file.
	"""
	if algorithm not in ("blake3", "md5"):
		raise ValueError(f"Invalid hash method '{algorithm}', supported are 'blake3' and 'md5'")

	buffer_size = 2**18
	with open(file_path, "rb") as file_handle:
		if algorithm == "md5":
			return file_digest(file_handle, "md5", _bufsize=buffer_size).hexdigest()

		blake3_hasher = blake3()
		buf = bytearray(buffer_size)
		view = memoryview(buf)
		while size := file_handle.readinto(buf):
			blake3_hasher.update(view[:size])
		return blake3_hasher.hexdigest()
