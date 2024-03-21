# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import datetime
import os
import platform
import time
from contextlib import contextmanager
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from pathlib import Path
from typing import Generator, Literal

import pytest

from opsicommon.logging import LEVEL_TO_OPSI_LEVEL, LOG_WARNING, StreamHandler, get_all_handlers, logging_config, use_logging_config
from opsicommon.objects import Product
from opsicommon.utils import (
	Singleton,
	combine_versions,
	compare_versions,
	frozen_lru_cache,
	generate_opsi_host_key,
	ip_address_in_network,
	prepare_proxy_environment,
	retry,
	timestamp,
	unix_timestamp,
	update_environment_from_config_files,
	utc_timestamp,
)


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
	now = datetime.datetime.now()
	assert timestamp(now.timestamp(), date_only=True) == now.strftime("%Y-%m-%d")
	now = datetime.datetime.now()
	assert timestamp() == now.strftime("%Y-%m-%d %H:%M:%S")


def test_utc_timestamp() -> None:
	now = datetime.datetime.now(datetime.timezone.utc)
	assert utc_timestamp() == now.strftime("%Y-%m-%d %H:%M:%S")
	now = datetime.datetime.now(datetime.timezone.utc)
	assert utc_timestamp(date_only=True) == now.strftime("%Y-%m-%d")


def test_unix_timestamp() -> None:
	# TODO: mock timezones
	unix_ts = unix_timestamp()
	assert isinstance(unix_ts, float)
	unix_ts_ms = unix_timestamp(millis=True)
	assert unix_ts_ms / 1000 - unix_ts < 2
	assert (unix_timestamp(add_seconds=30) - (unix_ts + 30)) < 2
	assert (unix_timestamp(add_seconds=-30) - (unix_ts - 30)) < 2


def test_singleton() -> None:
	class TestSingleton(metaclass=Singleton):
		pass

	assert id(TestSingleton()) == id(TestSingleton())


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


@pytest.mark.parametrize(
	"first, operator, second",
	[
		("1.0", "<", "2.0"),
		("2.0", ">", "1.0"),
		("1.0", "==", "1.0"),
		("1.2.3.5", "<=", "2.2.3.5"),
		("1.2.3.4-5~6", ">=", "1.2.3.4-5~1"),
	],
)
def test_comparing_versions_of_same_size(first: str, operator: Literal["<", "<=", "==", ">=", ">"], second: str) -> None:
	assert compare_versions(first, operator, second)


@pytest.mark.parametrize(
	"ver1, operator, ver2",
	[
		("1.0", "", "1.0"),
	],
)
def test_comparing_without_giving_operator_defaults_to_equal(ver1: str, operator: str, ver2: str) -> None:
	assert compare_versions(ver1, operator, ver2)  # type: ignore[arg-type]


def test_comparing_with_only_one_equality_sign() -> None:
	assert compare_versions("1.0", "=", "1.0")


@pytest.mark.parametrize(
	"first, operator, second", [("1.0or2.0", "<", "1.0or2.1"), ("1.0or2.0", "<", "1.1or2.0"), ("1.0or2.1", "<", "1.1or2.0")]
)
def test_comparing_or_versions(first: str, operator: Literal["<"], second: str) -> None:
	assert compare_versions(first, operator, second)


@pytest.mark.parametrize(
	"first, operator, second",
	[
		("20.09", "<", "21.h1"),
		("1.0.2s", "<", "1.0.2u"),
		("1.blubb.bla", "<", "1.foo"),
		("1.0.a", "<", "1.0.b"),
		("a.b", ">", "a.a"),
	],
)
def test_comparing_letter_versions(first: str, operator: Literal["<"], second: str) -> None:
	assert compare_versions(first, operator, second)


@pytest.mark.parametrize("operator", ["asdf", "+-", "<>", "!="])
def test_using_unknown_operator_fails(operator: str) -> None:
	with pytest.raises(ValueError):
		compare_versions("1", operator, "2")  # type: ignore[arg-type]


@pytest.mark.parametrize(
	"ver1, operator, ver2",
	[
		("1.0~20131212", "<", "2.0~20120101"),
		("1.0~20131212", "==", "1.0~20120101"),
	],
)
def test_ignoring_versions_with_wave_in_them(ver1: str, operator: Literal["<", "=="], ver2: str) -> None:
	assert compare_versions(ver1, operator, ver2)


@pytest.mark.parametrize("ver1, operator, ver2", [("abc-1.2.3-4", "==", "1.2.3-4"), ("1.2.3-4", "==", "abc-1.2.3-4")])
def test_using_invalid_version_strings_fails(ver1: str, operator: Literal["=="], ver2: str) -> None:
	with pytest.raises(ValueError):
		compare_versions(ver1, operator, ver2)


@pytest.mark.parametrize(
	"ver1, operator, ver2",
	[
		("1.1.0.1", ">", "1.1"),
		("1.1", "<", "1.1.0.1"),
		("1.1", "==", "1.1.0.0"),
	],
)
def test_comparisons_with_differnt_depths_are_made_the_same_depth(ver1: str, operator: Literal["<", ">", "=="], ver2: str) -> None:
	assert compare_versions(ver1, operator, ver2)


@pytest.mark.parametrize("ver1, operator, ver2", [("1-2", "<", "1-3"), ("1-2.0", "<", "1-2.1")])
def test_package_versions_are_compared_aswell(ver1: str, operator: Literal["<"], ver2: str) -> None:
	assert compare_versions(ver1, operator, ver2)


@pytest.mark.parametrize(
	"address, network, expected",
	[
		("10.10.1.1", "10.10.0.0/16", True),
		("10.10.1.1", "10.10.0.0/23", True),
		("10.10.1.1", "10.10.0.0/24", False),
		("10.10.1.1", "10.10.0.0/25", False),
		("10.10.1.1", "0.0.0.0/0", True),
		("10.10.1.1", "10.10.0.0/255.255.0.0", True),
		(IPv4Address("192.168.1.1"), IPv4Network("192.168.1.0/24"), True),
		(IPv4Address("192.168.1.1"), IPv4Network("192.168.2.0/24"), False),
	],
)
def test_ip_address_in_network(address: str | IPv4Address | IPv6Address, network: str | IPv4Network | IPv6Network, expected: bool) -> None:
	assert ip_address_in_network(address, network) == expected


def test_prepare_proxy_environment() -> None:
	env = {}
	try:
		env = os.environ.copy()
		os.environ["http_proxy"] = "http://my.proxy.server:3128"
		os.environ["https_proxy"] = "https://my.proxy.server:3129"
		os.environ["no_proxy"] = ""
		session = prepare_proxy_environment("my.test.server", proxy_url="http://my.proxy.server:3130")
		assert session.proxies.get("http") == "http://my.proxy.server:3130"

		session = prepare_proxy_environment("my.test.server")
		assert not session.proxies  # rely on environment, proxy not set explicitly
	finally:
		if env:
			os.environ = env  # type: ignore[assignment]


def test_prepare_proxy_environment_file(tmp_path: Path) -> None:
	env = {}
	try:
		env = os.environ.copy()
		os.environ["https_proxy"] = ""
		os.environ["http_proxy"] = ""
		os.environ["no_proxy"] = ""
		with open(tmp_path / "somefile.env", "w", encoding="utf-8") as f:
			f.write("https_proxy=https://my.proxy.server:3129\n")
			f.write("export http_proxy=http://my.proxy.server:3128\n")
			f.write('export no_proy=""\n')
		update_environment_from_config_files([tmp_path / "somefile.env"])
		if platform.system().lower() == "linux":  # only consult environment files on linux
			assert os.environ.get("http_proxy") == "http://my.proxy.server:3128"
			assert os.environ.get("https_proxy") == "https://my.proxy.server:3129"
			assert os.environ.get("no_proxy") == ""  # not '""'!
		else:
			assert os.environ.get("http_proxy") == ""
			assert os.environ.get("https_proxy") == ""
			assert os.environ.get("no_proxy") == ""
	finally:
		if env:
			os.environ = env  # type: ignore[assignment]


def test_retry() -> None:
	with use_logging_config(stderr_level=LOG_WARNING):
		caught_exceptions: list[Exception] = []

		@retry(retries=2, wait=0.5, exceptions=(ValueError,), caught_exceptions=caught_exceptions)
		def failing_function() -> None:
			raise ValueError("Test")

		start = time.time()
		with pytest.raises(ValueError):
			failing_function()
		assert time.time() - start >= 1

		assert len(caught_exceptions) == 2
		assert isinstance(caught_exceptions[0], ValueError)
		assert isinstance(caught_exceptions[1], ValueError)

		caught_exceptions = []

		@retry(retries=10, exceptions=(PermissionError, ValueError), caught_exceptions=caught_exceptions)
		def failing_function2() -> None:
			if len(caught_exceptions) < 2:
				raise PermissionError("Test")
			if len(caught_exceptions) < 4:
				raise ValueError("Test")
			raise RuntimeError("Test")

		with pytest.raises(RuntimeError):
			failing_function2()

		assert len(caught_exceptions) == 4
