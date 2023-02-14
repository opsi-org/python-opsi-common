# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import datetime
import os
import socket
import subprocess
from contextlib import contextmanager
from typing import Generator
from unittest import mock

import psutil  # type: ignore[import]
import pytest
from opsicommon.logging.constants import LEVEL_TO_OPSI_LEVEL
from opsicommon.logging.logging import StreamHandler, get_all_handlers, logging_config
from opsicommon.objects import Product
from opsicommon.utils import (
	Singleton,
	combine_versions,
	frozen_lru_cache,
	generate_opsi_host_key,
	get_fqdn,
	monkeypatch_subprocess_for_frozen,
	timestamp,
)

from .helpers import environment


def test_get_fqdn() -> None:
	fqdn = socket.getfqdn()
	if "." in fqdn:
		assert fqdn == socket.getfqdn()
	try:
		with mock.patch("socket.getfqdn", lambda x=None: "hostname"):
			assert "." in get_fqdn()
	except RuntimeError:
		pass


@pytest.mark.parametrize(
	"prod, expected", ((Product("test-prod", "2.0", "3"), "2.0-3"), (Product("test-prod", "44k123", "yx1"), "44k123-yx1"))
)
def test_combine_versions(prod: Product, expected: str) -> None:
	assert combine_versions(prod) == expected


def test_generate_opsi_host_key() -> None:
	key = generate_opsi_host_key()
	assert len(key) == 32
	assert bytes.fromhex(key)


def test_timestamp() -> None:
	now = datetime.datetime.now()
	assert timestamp(now.timestamp()) == now.strftime("%Y-%m-%d %H:%M:%S")
	assert timestamp(now.timestamp(), date_only=True) == now.strftime("%Y-%m-%d")
	assert timestamp() == datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def test_singleton() -> None:
	class TestSingleton(metaclass=Singleton):  # pylint: disable=too-few-public-methods
		pass

	assert id(TestSingleton()) == id(TestSingleton())


@pytest.mark.linux
def test_monkeypatch_subprocess_for_frozen() -> None:
	monkeypatch_subprocess_for_frozen()
	ld_library_path_orig = "/orig_path"
	ld_library_path = "/path"
	with environment(LD_LIBRARY_PATH_ORIG=ld_library_path_orig, LD_LIBRARY_PATH=ld_library_path):
		assert os.environ.get("LD_LIBRARY_PATH_ORIG") == ld_library_path_orig
		assert os.environ.get("LD_LIBRARY_PATH") == ld_library_path
		with subprocess.Popen(["sleep", "1"]) as proc:
			ps_proc = psutil.Process(proc.pid)
			proc_env = ps_proc.environ()
			assert proc_env.get("LD_LIBRARY_PATH_ORIG") == ld_library_path_orig
			assert proc_env.get("LD_LIBRARY_PATH") == ld_library_path_orig
			assert os.environ.get("LD_LIBRARY_PATH_ORIG") == ld_library_path_orig
			assert os.environ.get("LD_LIBRARY_PATH") == ld_library_path
			proc.wait()
		assert os.environ.get("LD_LIBRARY_PATH_ORIG") == ld_library_path_orig
		assert os.environ.get("LD_LIBRARY_PATH") == ld_library_path


def test_frozen_lru_cache() -> None:
	@frozen_lru_cache
	def testfunc(mydict: dict) -> dict:
		return {key: value + 1 for key, value in mydict.items()}

	@frozen_lru_cache(1)
	def testfunc_parameterized(mydict: dict) -> dict:
		return {key: value + 1 for key, value in mydict.items()}

	for func in (testfunc, testfunc_parameterized):
		result = func({"a": 0, "b": 42})
		assert result["a"] == 1 and result["b"] == 43
		result = func({"a": 10, "b": 10})
		assert result["a"] == 11 and result["b"] == 11
		result = func({"a": 0, "b": 42})
		assert result["a"] == 1 and result["b"] == 43


@contextmanager
def log_level_stderr(opsi_level: int) -> Generator[None, None, None]:
	level = LEVEL_TO_OPSI_LEVEL[get_all_handlers(StreamHandler)[0].level]
	logging_config(stderr_level=opsi_level)
	try:
		yield
	finally:
		logging_config(stderr_level=level)
