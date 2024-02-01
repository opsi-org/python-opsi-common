# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
Helpers for testing opsi.
"""

import io
import os
from contextlib import contextmanager
from typing import Generator

from opsicommon.logging import use_logging_config


@contextmanager
def log_stream(new_level: int, format: str | None = None) -> Generator[io.StringIO, None, None]:  # pylint: disable=redefined-builtin
	stream = io.StringIO()
	with use_logging_config(stderr_level=new_level, stderr_format=format, stderr_file=stream):
		yield stream


@contextmanager
def environment(**env_vars: str) -> Generator[None, None, None]:
	env_bak = os.environ.copy()
	try:
		os.environ.clear()
		os.environ.update(env_vars)
		yield
	finally:
		os.environ = env_bak  # type: ignore[assignment]
