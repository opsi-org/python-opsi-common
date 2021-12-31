# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import datetime
import pytest

from opsicommon.objects import Product, LocalbootProduct
from opsicommon.utils import (
	serialize, deserialize, combine_versions, to_json, from_json,
	generate_opsi_host_key, timestamp, Singleton
)


@pytest.mark.parametrize("obj,json_exc", (
	(Product("test-prod", "2.0", "3", windowsSoftwareIds=["123", "abc"]), None),
	({"ident": ["product", "LocalbootProduct", "client1.dom.tld"]}, None),
	("string", None),
	(Exception("test"), TypeError),
	(123, None),
	(None, None),
	([1, "b", {"x": "y"}], None)
))
def test_serialize_deserialize(obj,json_exc):
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


@pytest.mark.parametrize("prod, expected", (
	(Product("test-prod", "2.0", "3"), "2.0-3"),
	(Product("test-prod", "44k123", "yx1"), "44k123-yx1")
))
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
	class TestSingleton(metaclass=Singleton):
		pass

	assert id(TestSingleton()) == id(TestSingleton())
