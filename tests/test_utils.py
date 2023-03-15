# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import datetime
import os
import subprocess
from typing import Literal

import psutil  # type: ignore[import]
import pytest

from opsicommon.objects import LocalbootProduct, Product
from opsicommon.utils import (
	Singleton,
	combine_versions,
	compare_versions,
	deserialize,
	from_json,
	frozen_lru_cache,
	generate_opsi_host_key,
	monkeypatch_subprocess_for_frozen,
	serialize,
	timestamp,
	to_json,
)

from .helpers import environment


@pytest.mark.parametrize(
	"obj,json_exc",
	(
		(Product("test-prod", "2.0", "3", windowsSoftwareIds=["123", "abc"]), None),
		({"ident": ["product", "LocalbootProduct", "client1.dom.tld"]}, None),
		("string", None),
		(Exception("test"), TypeError),
		(123, None),
		(None, None),
		([1, "b", {"x": "y"}], None),
	),
)
def test_serialize_deserialize(obj, json_exc):
	assert obj == deserialize(serialize(obj))
	if json_exc:
		with pytest.raises(json_exc):
			to_json(obj)
	else:
		assert obj == from_json(to_json(obj))
		assert obj == from_json(to_json(obj).encode("utf-8"))


def test_deserialize_error():
	with pytest.raises(ValueError):
		deserialize({"type": "LocalbootProduct", "id": "--invalid id--", "productVersion": "1", "packageVersion": "2"})


def test_object_fom_json():
	json_data = '{"type": "LocalbootProduct", "id": "product1", "productVersion": "1", "packageVersion": "2"}'
	res = from_json(json_data)
	assert isinstance(res, LocalbootProduct)

	res = from_json(json_data, prevent_object_creation=True)
	assert isinstance(res, dict)

	json_data = '{"id": "product1", "productVersion": "1", "packageVersion": "2"}'
	res = from_json(json_data, object_type="LocalbootProduct")
	assert isinstance(res, LocalbootProduct)


@pytest.mark.parametrize(
	"prod, expected", ((Product("test-prod", "2.0", "3"), "2.0-3"), (Product("test-prod", "44k123", "yx1"), "44k123-yx1"))
)
def test_combine_versions(prod, expected):
	assert combine_versions(prod) == expected


def test_generate_opsi_host_key():
	key = generate_opsi_host_key()
	assert len(key) == 32
	assert bytes.fromhex(key)


def test_timestamp():
	now = datetime.datetime.now()
	assert timestamp(now.timestamp()) == now.strftime("%Y-%m-%d %H:%M:%S")
	assert timestamp(now.timestamp(), date_only=True) == now.strftime("%Y-%m-%d")
	assert timestamp() == datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def test_singleton():
	class TestSingleton(metaclass=Singleton):  # pylint: disable=too-few-public-methods
		pass

	assert id(TestSingleton()) == id(TestSingleton())


@pytest.mark.linux
def test_monkeypatch_subprocess_for_frozen():
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


def test_frozen_lru_cache():
	@frozen_lru_cache
	def testfunc(mydict: dict):
		return {key: value + 1 for key, value in mydict.items()}

	@frozen_lru_cache(1)
	def testfunc_parameterized(mydict: dict):
		return {key: value + 1 for key, value in mydict.items()}

	for func in (testfunc, testfunc_parameterized):
		result = func({"a": 0, "b": 42})
		assert result["a"] == 1 and result["b"] == 43
		result = func({"a": 10, "b": 10})
		assert result["a"] == 11 and result["b"] == 11
		result = func({"a": 0, "b": 42})
		assert result["a"] == 1 and result["b"] == 43


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
