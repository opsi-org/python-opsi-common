# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import re
import time
import shutil
import codecs
import json
import pathlib
from datetime import date, timedelta
from unittest import mock
import pytest
from Crypto.PublicKey import RSA

from opsicommon.license import (
	set_default_opsi_license_pool,
	get_default_opsi_license_pool,
	OPSI_MODULE_STATE_CLOSE_TO_LIMIT,
	OPSI_MODULE_STATE_OVER_LIMIT,
	OpsiLicenseFile,
	generate_key_pair,
	OpsiLicense,
	OpsiModulesFile,
	OpsiLicensePool,
	OPSI_LICENSE_STATE_REPLACED_BY_NON_CORE,
	OPSI_LICENSE_STATE_VALID,
	OPSI_LICENSE_STATE_INVALID_SIGNATURE,
	OPSI_LICENSE_STATE_EXPIRED,
	OPSI_LICENSE_STATE_NOT_YET_VALID,
	OPSI_LICENSE_STATE_REVOKED,
	OPSI_LICENSE_TYPE_STANDARD,
	OPSI_MODULE_STATE_FREE,
	OPSI_MODULE_STATE_LICENSED,
	OPSI_MODULE_STATE_UNLICENSED,
	OPSI_MODULE_IDS,
	OPSI_LICENSE_DATE_UNLIMITED,
	OPSI_LICENSE_CLIENT_NUMBER_UNLIMITED,
	MAX_STATE_CACHE_VALUES,
)

LIC1 = {
	"id": "1bf8e14c-1faf-4288-a468-d92e1ee2dd8b",
	"type": "core",
	"schema_version": 2,
	"opsi_version": "4.2",
	"customer_id": "12345",
	"customer_name": "Test Holding",
	"customer_address": "香港",
	"customer_unit": "Test GmbH",
	"contract_id": "XY82378342343323",
	"service_id": "opsi.test.gmbh",
	"module_id": "scalability1",
	"client_number": 1000,
	"issued_at": "2021-08-05",
	"valid_from": "2021-09-01",
	"valid_until": "2023-12-31",
	"revoked_ids": ["c6af25cf-62e4-4b90-8f4b-21c542d8b74b", "cc4e2986-d28d-4bef-807b-a74ba9a8df04"],
	"note": "Some notes",
	"additional_data": None,
	"signature": "0102030405060708090a0b0c0d0e",
}


def _read_modules_file(modules_file):
	modules = {}
	expires = None
	customer = None
	signature = None
	with codecs.open(modules_file, "r", "utf-8") as file:
		for line in file:
			key, val = line.lower().split("=", 1)
			key = key.strip()
			val = val.strip()
			if key == "expires":
				expires = date.fromisoformat(OPSI_LICENSE_CLIENT_NUMBER_UNLIMITED) if val == "never" else date.fromisoformat(val)
			elif key == "customer":
				customer = val
			elif key == "signature":
				signature = val
				if len(signature) % 2:
					signature = "0" + signature
			else:
				modules[key] = val
	return modules, expires, customer, signature


def test_generate_key_pair():
	private_key, public_key = generate_key_pair(return_pem=False)
	assert private_key.has_private()
	assert not public_key.has_private()

	private_key, public_key = generate_key_pair(return_pem=True)
	assert "-----BEGIN RSA PRIVATE KEY-----" in private_key
	assert "-----BEGIN PUBLIC KEY-----" in public_key


def test_sign_opsi_license():
	private_key, public_key = generate_key_pair(return_pem=False)
	with mock.patch("opsicommon.license.get_signature_public_key_schema_version_2", lambda: public_key):
		lic = OpsiLicense(**LIC1)
		lic.valid_from = lic.valid_until = date.today()
		assert lic.get_state() == OPSI_LICENSE_STATE_INVALID_SIGNATURE
		lic.sign(private_key)
		assert lic.get_state() == OPSI_LICENSE_STATE_VALID

	private_key, public_key = generate_key_pair(return_pem=True)
	with mock.patch("opsicommon.license.get_signature_public_key_schema_version_2", lambda: RSA.import_key(public_key)):
		lic = OpsiLicense(**LIC1)
		lic.sign(private_key)
		assert lic.get_state() == OPSI_LICENSE_STATE_VALID

		lic.schema_version = 1
		with pytest.raises(NotImplementedError):
			lic.sign(private_key)


def test_opsi_license_defaults():
	lic = OpsiLicense(
		customer_id="12345",
		customer_name="uib GmbH",
		customer_address="Mainz",
		module_id="scalability1",
		client_number=1000,
		valid_until="2099-12-31",
	)
	assert lic.id
	assert lic.type == "standard"
	assert lic.valid_from == date.today()
	assert lic.issued_at == date.today()


@pytest.mark.parametrize(
	"attribute,value,exception",
	(
		("id", "a62e8266-5df8-41b3-bce3-81da6f69a9d0", None),
		("id", "", ValueError),
		("type", "core", None),
		("type", "invalid", ValueError),
		("schema_version", 1, None),
		("schema_version", 0, ValueError),
		("opsi_version", "5.0", None),
		("opsi_version", "4", ValueError),
		("opsi_version", "4.1.2", ValueError),
		("customer_id", "XY12536", None),
		("customer_id", "", ValueError),
		("customer_name", "uib GmbH", None),
		("customer_name", "", ValueError),
		("customer_address", "üö", None),
		("customer_address", "", ValueError),
		("customer_address", " Mainz", ValueError),
		("service_id", "opsi.uinit.dom.tld", None),
		("service_id", "invalid value", ValueError),
		("module_id", "vpn", None),
		("module_id", "", ValueError),
		("client_number", OPSI_LICENSE_CLIENT_NUMBER_UNLIMITED, None),
		("client_number", -1, ValueError),
		("issued_at", "2021-01-01", None),
		("issued_at", "", ValueError),
		("valid_from", date.today(), None),
		("valid_from", None, TypeError),
		("valid_until", OPSI_LICENSE_DATE_UNLIMITED, None),
		("valid_until", "0000-00-00", ValueError),
		("revoked_ids", ["a62e8266-5df8-41b3-bce3-6f69a81da9d0", "legacy_scalability1"], None),
		("revoked_ids", ["1", 2], ValueError),
		("revoked_ids", "not-a-list", ValueError),
		("signature", "----------------------------", ValueError),
		("signature", "0102030405060708090a0b0c0d0e", None),
		("signature", "102030405060708090a0b0c0d0e", None),
		("signature", bytes.fromhex("0102030405060708090a0b0c0d0e"), None),
	),
)
def test_opsi_license_validation(attribute, value, exception):
	kwargs = {
		"customer_id": "12345",
		"customer_name": "uib GmbH",
		"customer_address": "Mainz",
		"module_id": "scalability1",
		"client_number": 1000,
		"valid_until": "2099-12-31",
	}
	kwargs[attribute] = value
	if exception:
		with pytest.raises(exception):
			OpsiLicense(**kwargs)
	else:
		OpsiLicense(**kwargs)


def test_opsi_license_to_from_json():
	lic = OpsiLicense(**LIC1)
	json_data = lic.to_json()
	assert LIC1 == json.loads(json_data)

	lic = OpsiLicense.from_json(json_data)
	json_data = lic.to_json()
	assert LIC1 == json.loads(json_data)

	data = json.loads(lic.to_json(with_state=True))
	assert data["_state"] == OPSI_LICENSE_STATE_INVALID_SIGNATURE


def test_opsi_license_to_from_dict():
	lic = OpsiLicense(**LIC1)
	lic_dict = lic.to_dict(serializable=True)
	assert lic_dict == LIC1

	lic_dict2 = lic_dict.copy()
	lic_dict2["_attribute_with_underscore"] = "should_be_removed"
	lic = OpsiLicense.from_dict(lic_dict2)
	assert lic.to_dict(serializable=True) == lic_dict


def test_opsi_license_hash():
	lic = OpsiLicense(**LIC1)
	assert lic.get_hash(hex_digest=True) == (
		"137cd167b2b1104cdbdd5190e12bd9a6cf5bb2726218c966d136c80c271f262c"
		"4766a3d9ff31d1f0e2790d00aab733b3aea12da3ec41e7e93c13b7ae687aa564"
	)
	assert lic.get_hash(digest=True) == bytes.fromhex(
		"137cd167b2b1104cdbdd5190e12bd9a6cf5bb2726218c966d136c80c271f262c"
		"4766a3d9ff31d1f0e2790d00aab733b3aea12da3ec41e7e93c13b7ae687aa564"
	)


def test_default_opsi_license_pool():
	def_pool1 = get_default_opsi_license_pool()
	pool = OpsiLicensePool(license_file_path="/tmp/licenses")
	set_default_opsi_license_pool(pool)
	def_pool2 = get_default_opsi_license_pool()
	assert def_pool1 != def_pool2
	assert def_pool2 == pool

	set_default_opsi_license_pool(None)
	def_pool3 = get_default_opsi_license_pool()
	assert def_pool3 != def_pool1
	assert def_pool3 != def_pool2


def test_load_opsi_license_pool():
	modules_file = "tests/data/license/modules"
	olp = OpsiLicensePool(license_file_path="tests/data/license/test1.opsilic")
	olp.load()

	assert len(olp.licenses) == 3
	assert "e7f707a7-c184-45e2-a477-27dbf5516b1c" in [lic.id for lic in olp.licenses]
	assert "707ef1b7-6139-4ec4-b60d-8480ce6dae34" in [lic.id for lic in olp.licenses]
	assert "c6af25cf-62e4-4b90-8f4b-21c542d8b74b" in [lic.id for lic in olp.licenses]

	olp.license_file_path = "tests/data/license"
	olp.load()
	assert len(olp.licenses) == 4
	assert "e7f707a7-c184-45e2-a477-27dbf5516b1c" in [lic.id for lic in olp.licenses]
	assert "707ef1b7-6139-4ec4-b60d-8480ce6dae34" in [lic.id for lic in olp.licenses]
	assert "c6af25cf-62e4-4b90-8f4b-21c542d8b74b" in [lic.id for lic in olp.licenses]
	assert "7cf9ef7e-6e6f-43f5-8b52-7c4e582ff6f1" in [lic.id for lic in olp.licenses]

	olp.license_file_path = None
	olp.modules_file_path = modules_file
	olp.load()

	modules, _expires, _customer, _signature = _read_modules_file(modules_file)
	module_ids = [m for m, v in modules.items() if v != "no"]
	assert len(module_ids) == len(olp.licenses)

	for lic in olp.licenses:
		assert lic.module_id in module_ids
		_prefix, module_id = lic.id.split("-", 1)
		assert _prefix == "legacy"
		assert module_id in module_ids


def test_opsi_license_pool_modified(tmp_path):
	license_file_path = tmp_path / "licenses"
	modules_file_path = tmp_path / "licenses" / "modules"
	shutil.copytree("tests/data/license", str(license_file_path))
	olp = OpsiLicensePool(license_file_path=str(license_file_path), modules_file_path=str(modules_file_path))
	olp.load()
	assert olp.get_licenses()
	assert not olp.modified()

	modules_file_path.touch()
	assert olp.modified()
	olp.load()
	assert not olp.modified()

	lic_file = license_file_path / "test1.opsilic"
	lic_file.rename(lic_file.with_suffix(".hide"))
	assert olp.modified()
	olp.load()
	assert not olp.modified()

	lic_file.with_suffix(".hide").rename(lic_file)
	assert olp.modified()
	olp.load()
	assert not olp.modified()


def test_opsi_license_pool_add_remove_license(tmp_path):
	license_file_path = tmp_path / "licenses"
	modules_file_path = tmp_path / "licenses" / "modules"
	shutil.copytree("tests/data/license", str(license_file_path))
	olp = OpsiLicensePool(license_file_path=str(license_file_path), modules_file_path=str(modules_file_path))
	olp.load()
	licenses = list(olp._licenses.values())  # pylint: disable=protected-access
	assert len(licenses) == 25
	for lic in licenses:
		lic.get_state()
		assert len(lic._cached_state) > 0  # pylint: disable=protected-access

	removed_lic = licenses.pop()
	olp.remove_license(removed_lic)

	licenses = list(olp._licenses.values())  # pylint: disable=protected-access
	assert len(licenses) == 24
	# Assert empty cache
	for lic in licenses:
		assert len(lic._cached_state) == 0  # pylint: disable=protected-access

	# Fill cache
	for lic in licenses:
		lic.get_state()
		assert len(lic._cached_state) > 0  # pylint: disable=protected-access

	olp.add_license(removed_lic)
	licenses = list(olp._licenses.values())  # pylint: disable=protected-access
	assert len(licenses) == 25
	# Assert empty cache
	for lic in licenses:
		assert len(lic._cached_state) == 0  # pylint: disable=protected-access


def test_opsi_license_pool_licenses_checksum():
	olp = OpsiLicensePool(license_file_path="tests/data/license")
	olp.load()
	private_key, public_key = generate_key_pair(return_pem=False)
	with mock.patch("opsicommon.license.get_signature_public_key_schema_version_2", lambda: public_key):
		for lic in olp.licenses:
			lic.sign(private_key)
		assert olp.get_licenses_checksum() == "372ac8d6"

	olp = OpsiLicensePool()
	private_key, public_key = generate_key_pair(return_pem=False)
	with mock.patch("opsicommon.license.get_signature_public_key_schema_version_2", lambda: public_key):
		assert olp.get_licenses_checksum() == "0"

		lic1 = OpsiLicense(**LIC1)
		lic1.module_id = "directory-connector"
		olp.add_license(lic1)
		# Unsigned license
		assert olp.get_licenses_checksum() == "0"

		lic1.sign(private_key)
		assert olp.get_licenses_checksum() == "2c3bde7c"

		lic2 = OpsiLicense(**LIC1)
		lic2.module_id = "dynamic_depot"
		lic2.sign(private_key)
		olp.add_license(lic2)
		assert olp.get_licenses_checksum() == "34c7b2d2"


def test_opsi_license_pool_relevant_dates():
	olp = OpsiLicensePool(license_file_path="tests/data/license")
	olp.load()
	private_key, public_key = generate_key_pair(return_pem=False)
	with mock.patch("opsicommon.license.get_signature_public_key_schema_version_2", lambda: public_key):
		for lic in olp.licenses:
			lic.sign(private_key)
		dates = olp.get_relevant_dates()
		assert len(dates) == 5

		for at_date in dates:
			modules = olp.get_modules(at_date=at_date)
			assert sorted(OPSI_MODULE_IDS) == sorted(modules)

			assert modules["treeview"]["available"]
			assert modules["treeview"]["state"] == OPSI_MODULE_STATE_FREE

			assert modules["vista"]["available"]
			assert modules["vista"]["state"] == OPSI_MODULE_STATE_FREE

			assert not modules["secureboot"]["available"]
			assert modules["secureboot"]["state"] == OPSI_MODULE_STATE_UNLICENSED

			if at_date >= date.fromisoformat("2019-08-01"):
				assert modules["vpn"]["available"]
				assert modules["vpn"]["state"] == OPSI_MODULE_STATE_LICENSED
			else:
				assert not modules["vpn"]["available"]
				assert modules["vpn"]["state"] == OPSI_MODULE_STATE_UNLICENSED

			if date.fromisoformat("2020-01-01") <= at_date <= date.fromisoformat("2031-12-31"):
				assert modules["scalability1"]["available"]
				assert modules["scalability1"]["state"] == OPSI_MODULE_STATE_LICENSED
			else:
				assert not modules["scalability1"]["available"]
				assert modules["scalability1"]["state"] == OPSI_MODULE_STATE_UNLICENSED


def test_licensing_info_and_cache():
	olp = OpsiLicensePool(license_file_path="tests/data/license", modules_file_path="tests/data/license/modules")
	olp.load()
	private_key, public_key = generate_key_pair(return_pem=False)
	with mock.patch("opsicommon.license.get_signature_public_key_schema_version_2", lambda: public_key):
		for lic in olp.licenses:
			if lic.schema_version > 1:
				lic.sign(private_key)

		timings = []
		for num in range(3):
			start = time.time()
			info = {
				"client_numbers": olp.client_numbers,
				"available_modules": [module_id for module_id, info in olp.get_modules().items() if info["available"]],
				"licenses_checksum": olp.get_licenses_checksum(),
			}
			licenses = olp.get_licenses()
			info["licenses"] = [lic.to_dict(serializable=True, with_state=True) for lic in licenses]
			info["legacy_modules"] = olp.get_legacy_modules()
			info["dates"] = {}
			for at_date in olp.get_relevant_dates():
				info["dates"][str(at_date)] = {"modules": olp.get_modules(at_date=at_date)}
			timings.append(time.time() - start)
			if num == 1:
				# Cached should be faster
				assert timings[1] < timings[0]
				# Clear cache
				olp.clear_license_state_cache()
			if num == 2:
				# Cached should be faster
				assert timings[2] > timings[1]


@pytest.mark.parametrize(
	"lic_scalability1, lic_linux, clients_total, clients_linux, warn_absolute, warn_percent,"
	"exp_state_scalabilty, exp_avail_scalability, exp_state_linux, exp_avail_linux",
	(
		# OPSI_MODULE_STATE_LICENSED
		(1000, 100, 994, 94, 0, 0, OPSI_MODULE_STATE_LICENSED, True, OPSI_MODULE_STATE_LICENSED, True),
		(1000, 100, 995, 94, 0, 0, OPSI_MODULE_STATE_LICENSED, True, OPSI_MODULE_STATE_LICENSED, True),
		(1000, 100, 995, 95, 0, 0, OPSI_MODULE_STATE_LICENSED, True, OPSI_MODULE_STATE_LICENSED, True),
		(1000, 100, 994, 94, 5, 0, OPSI_MODULE_STATE_LICENSED, True, OPSI_MODULE_STATE_LICENSED, True),
		(1000, 100, 998, 98, 1, 0, OPSI_MODULE_STATE_LICENSED, True, OPSI_MODULE_STATE_LICENSED, True),
		(1000, 100, 989, 98, 0, 99, OPSI_MODULE_STATE_LICENSED, True, OPSI_MODULE_STATE_LICENSED, True),
		# OPSI_MODULE_STATE_CLOSE_TO_LIMIT
		(1000, 100, 995, 94, 5, 0, OPSI_MODULE_STATE_CLOSE_TO_LIMIT, True, OPSI_MODULE_STATE_LICENSED, True),
		(1000, 100, 995, 95, 5, 0, OPSI_MODULE_STATE_CLOSE_TO_LIMIT, True, OPSI_MODULE_STATE_CLOSE_TO_LIMIT, True),
		(1000, 100, 949, 94, 0, 95, OPSI_MODULE_STATE_LICENSED, True, OPSI_MODULE_STATE_LICENSED, True),
		(1000, 100, 950, 94, 0, 95, OPSI_MODULE_STATE_CLOSE_TO_LIMIT, True, OPSI_MODULE_STATE_LICENSED, True),
		(1000, 100, 950, 95, 0, 95, OPSI_MODULE_STATE_CLOSE_TO_LIMIT, True, OPSI_MODULE_STATE_CLOSE_TO_LIMIT, True),
		# OPSI_MODULE_STATE_OVER_LIMIT
		(1000, 100, 1031, 100, 5, 95, OPSI_MODULE_STATE_OVER_LIMIT, True, OPSI_MODULE_STATE_CLOSE_TO_LIMIT, True),
		(1000, 100, 1000, 101, 5, 95, OPSI_MODULE_STATE_CLOSE_TO_LIMIT, True, OPSI_MODULE_STATE_OVER_LIMIT, True),
		(1000, 100, 1001, 101, 5, 95, OPSI_MODULE_STATE_OVER_LIMIT, True, OPSI_MODULE_STATE_OVER_LIMIT, True),
		(1000, 100, 1031, 101, 5, 95, OPSI_MODULE_STATE_OVER_LIMIT, True, OPSI_MODULE_STATE_OVER_LIMIT, True),
		(1000, 100, 1032, 109, 5, 95, OPSI_MODULE_STATE_OVER_LIMIT, False, OPSI_MODULE_STATE_OVER_LIMIT, True),
		(1000, 100, 1031, 110, 5, 95, OPSI_MODULE_STATE_OVER_LIMIT, True, OPSI_MODULE_STATE_OVER_LIMIT, False),
		(1000, 100, 1032, 110, 5, 95, OPSI_MODULE_STATE_OVER_LIMIT, False, OPSI_MODULE_STATE_OVER_LIMIT, False),
		(1000, 100, 100000, 100000, 5, 95, OPSI_MODULE_STATE_OVER_LIMIT, False, OPSI_MODULE_STATE_OVER_LIMIT, False),
		(1000, 100, 1032, 110, -100000, -100000, OPSI_MODULE_STATE_OVER_LIMIT, False, OPSI_MODULE_STATE_OVER_LIMIT, False),
		(1000, 100, 1032, 110, 100000, 100000, OPSI_MODULE_STATE_OVER_LIMIT, False, OPSI_MODULE_STATE_OVER_LIMIT, False),
	),  # pylint: disable=too-many-arguments,too-many-locals
)
def test_license_state_client_number_warning_and_thresholds(
	lic_scalability1,
	lic_linux,
	clients_total,
	clients_linux,
	warn_absolute,
	warn_percent,
	exp_state_scalabilty,
	exp_avail_scalability,
	exp_state_linux,
	exp_avail_linux,
):
	private_key, public_key = generate_key_pair(return_pem=False)

	def client_info():
		return {"macos": 0, "linux": clients_linux, "windows": clients_total - clients_linux}

	with mock.patch("opsicommon.license.get_signature_public_key_schema_version_2", lambda: public_key):
		lic = dict(LIC1)
		del lic["id"]
		lic["module_id"] = "scalability1"
		lic["type"] = OPSI_LICENSE_TYPE_STANDARD
		lic["valid_from"] = "2000-01-01"
		lic["valid_until"] = "9999-12-31"
		lic["client_number"] = lic_scalability1
		lic1 = OpsiLicense(**lic)
		lic1.sign(private_key)

		lic["module_id"] = "linux_agent"
		lic["client_number"] = lic_linux
		lic2 = OpsiLicense(**lic)
		lic2.sign(private_key)

		olp = OpsiLicensePool(
			client_info=client_info, client_limit_warning_absolute=warn_absolute, client_limit_warning_percent=warn_percent
		)
		olp.add_license(lic1, lic2)

		modules = olp.get_modules()
		assert modules["scalability1"]["client_number"] == lic_scalability1
		assert modules["scalability1"]["state"] == exp_state_scalabilty
		assert modules["scalability1"]["available"] == exp_avail_scalability

		assert modules["linux_agent"]["client_number"] == lic_linux
		assert modules["linux_agent"]["state"] == exp_state_linux
		assert modules["linux_agent"]["available"] == exp_avail_linux


def test_license_state():
	private_key, public_key = generate_key_pair(return_pem=False)
	with mock.patch("opsicommon.license.get_signature_public_key_schema_version_2", lambda: public_key):
		lic = OpsiLicense(**LIC1)
		lic.sign(private_key)

		lic.valid_from = date.today() - timedelta(days=10)
		lic.valid_until = date.today() - timedelta(days=1)
		lic.sign(private_key)
		assert lic.get_state() == OPSI_LICENSE_STATE_EXPIRED

		lic.valid_until = date.today()
		lic.sign(private_key)
		assert lic.get_state() == OPSI_LICENSE_STATE_VALID

		lic.valid_until = date.today() + timedelta(days=1)
		lic.sign(private_key)
		assert lic.get_state() == OPSI_LICENSE_STATE_VALID

		lic.valid_from = date.today() + timedelta(days=1)
		lic.sign(private_key)
		assert lic.get_state() == OPSI_LICENSE_STATE_NOT_YET_VALID

		lic.valid_from = date.today()
		lic.sign(private_key)
		assert lic.get_state() == OPSI_LICENSE_STATE_VALID

		lic.valid_from = date.today() - timedelta(days=1)
		lic.sign(private_key)
		assert lic.get_state() == OPSI_LICENSE_STATE_VALID

		lic.valid_from = date.today()
		lic.valid_until = date.today()
		lic.sign(private_key)
		assert lic.get_state() == OPSI_LICENSE_STATE_VALID
		assert lic.get_state(at_date=date.today() + timedelta(days=1)) == OPSI_LICENSE_STATE_EXPIRED
		assert lic.get_state(at_date=date.today() - timedelta(days=1)) == OPSI_LICENSE_STATE_NOT_YET_VALID

		lic.client_number = 1234567
		assert lic.get_state() == OPSI_LICENSE_STATE_INVALID_SIGNATURE


def test_license_state_cache():
	private_key, public_key = generate_key_pair(return_pem=False)
	with mock.patch("opsicommon.license.get_signature_public_key_schema_version_2", lambda: public_key):
		lic = OpsiLicense(**LIC1)
		lic.sign(private_key)

		assert len(lic._cached_state) == 0  # pylint: disable=protected-access

		lic.valid_from = date.today() - timedelta(days=10)
		lic.valid_until = date.today() - timedelta(days=1)
		lic.sign(private_key)

		for num in range(1, MAX_STATE_CACHE_VALUES + 5):
			assert lic.get_state(at_date=date.today() + timedelta(days=num)) == OPSI_LICENSE_STATE_EXPIRED
			assert len(lic._cached_state) == min(MAX_STATE_CACHE_VALUES, num)  # pylint: disable=protected-access

		lic.clear_state_cache()
		assert len(lic._cached_state) == 0  # pylint: disable=protected-access

		today = date.today()
		start = time.perf_counter_ns()
		lic.get_state(at_date=today)
		uncached_time_ns = time.perf_counter_ns() - start

		for _ in range(20):
			start = time.perf_counter_ns()
			lic.get_state(at_date=today)

			# Cached state should be much faster
			time_ns = time.perf_counter_ns() - start
			assert time_ns * 2 < uncached_time_ns

			# Cache should keep size
			assert len(lic._cached_state) == 1  # pylint: disable=protected-access


def test_opsi_license_pool_unknown_module_id():
	private_key, public_key = generate_key_pair(return_pem=False)
	with mock.patch("opsicommon.license.get_signature_public_key_schema_version_2", lambda: public_key):
		olp = OpsiLicensePool()
		lic = dict(LIC1)
		lic["module_id"] = "unknownmod"
		lic["valid_until"] = "2123-12-31"
		lic = OpsiLicense(**lic)
		lic.sign(private_key)
		olp.add_license(lic)
		mods = olp.get_modules()
		assert "unknownmod" in mods


def test_license_state_modules(tmp_path):
	modules = pathlib.Path("tests/data/license/modules").read_text(encoding="utf-8")
	modules_file = tmp_path / "modules"
	modules_file.write_text(modules)

	omf = OpsiModulesFile(str(modules_file))
	omf.read()
	lic = omf.licenses[0]

	lic.valid_from = date.today() - timedelta(days=10)

	lic.valid_until = date.today() - timedelta(days=1)
	assert lic.get_state() == OPSI_LICENSE_STATE_EXPIRED

	lic.valid_until = date.today()
	assert lic.get_state() == OPSI_LICENSE_STATE_VALID

	lic.valid_until = date.today() + timedelta(days=1)
	assert lic.get_state() == OPSI_LICENSE_STATE_VALID

	lic.valid_from = date.today() + timedelta(days=1)
	assert lic.get_state() == OPSI_LICENSE_STATE_NOT_YET_VALID

	lic.valid_from = date.today()
	assert lic.get_state() == OPSI_LICENSE_STATE_VALID

	lic.valid_from = date.today() - timedelta(days=1)
	assert lic.get_state() == OPSI_LICENSE_STATE_VALID

	lic.valid_from = date.today()
	lic.valid_until = date.today()
	assert lic.get_state() == OPSI_LICENSE_STATE_VALID
	assert lic.get_state(at_date=date.today() + timedelta(days=1)) == OPSI_LICENSE_STATE_EXPIRED
	assert lic.get_state(at_date=date.today() - timedelta(days=1)) == OPSI_LICENSE_STATE_NOT_YET_VALID

	modules = re.sub(r"secureboot.*", "secureboot = 100", modules, re.MULTILINE)
	modules_file.write_text(modules)
	omf.read()
	lic = omf.licenses[0]

	assert lic.get_state() == OPSI_LICENSE_STATE_INVALID_SIGNATURE


def test_license_state_replaced_by_non_core():
	olp = OpsiLicensePool(license_file_path="tests/data/license")
	olp.load()
	private_key, public_key = generate_key_pair(return_pem=False)
	with mock.patch("opsicommon.license.get_signature_public_key_schema_version_2", lambda: public_key):
		for lic in olp.licenses:
			lic.sign(private_key)
		for lic in olp.licenses:
			if lic.id == "7cf9ef7e-6e6f-43f5-8b52-7c4e582ff6f1":
				assert lic.get_state() == OPSI_LICENSE_STATE_REPLACED_BY_NON_CORE


def test_license_state_revoked():
	olp = OpsiLicensePool(license_file_path="tests/data/license")
	olp.load()
	private_key, public_key = generate_key_pair(return_pem=False)
	with mock.patch("opsicommon.license.get_signature_public_key_schema_version_2", lambda: public_key):
		for lic in olp.licenses:
			lic.sign(private_key)
		for lic in olp.licenses:
			if lic.id == "c6af25cf-62e4-4b90-8f4b-21c542d8b74b":
				assert lic.get_state() == OPSI_LICENSE_STATE_REVOKED


def test_opsi_modules_file(tmp_path):
	orig_modules_file = "tests/data/license/modules"
	raw_data = pathlib.Path(orig_modules_file).read_text(encoding="utf-8")

	modules_file = tmp_path / "modules"
	modules_file.write_text(raw_data, encoding="utf-8")

	modules, expires, _customer, signature = _read_modules_file(modules_file)
	omf = OpsiModulesFile(modules_file)
	omf.read()
	assert len(modules) == len(omf.licenses)
	for lic in omf.licenses:
		assert lic.get_state() == OPSI_LICENSE_STATE_VALID
		assert lic.module_id in modules
		assert lic.valid_until == expires
		client_number = OPSI_LICENSE_CLIENT_NUMBER_UNLIMITED
		if modules[lic.module_id] not in ("yes", "no"):
			client_number = int(modules[lic.module_id])
		assert lic.client_number == client_number
		assert lic.signature.hex() == signature
		assert sorted([x for x in raw_data.replace("\r", "").split("\n") if x and not x.startswith("signature")]) == sorted(
			[x for x in lic.additional_data.replace("\r", "").split("\n") if x]
		)

	raw_data = re.sub(r"expires.*", "expires = never", raw_data, re.MULTILINE)
	modules_file.write_text(raw_data, encoding="utf-8")
	omf = OpsiModulesFile(modules_file)
	omf.read()
	assert len(modules) == len(omf.licenses)
	for lic in omf.licenses:
		assert lic.valid_until == OPSI_LICENSE_DATE_UNLIMITED
		assert lic.get_state() == OPSI_LICENSE_STATE_INVALID_SIGNATURE


def test_write_license_file(tmp_path):
	license_file = str(tmp_path / "test.opsilic")
	private_key, public_key = generate_key_pair(return_pem=False)
	with mock.patch("opsicommon.license.get_signature_public_key_schema_version_2", lambda: public_key):
		lic1 = dict(LIC1)
		del lic1["id"]
		lic1["module_id"] = "scalability1"
		lic1["note"] = "Line1\nLine2"
		lic1 = OpsiLicense(**lic1)
		lic1.sign(private_key)

		lic2 = dict(LIC1)
		del lic2["id"]
		lic2["module_id"] = "vpn"
		lic2["revoked_ids"] = ["legacy-vpn", "7cf9ef7e-6e6f-43f5-8b52-7c4e582ff6f1"]
		lic2 = OpsiLicense(**lic2)
		lic2.sign(private_key)

		file = OpsiLicenseFile(license_file)
		with pytest.raises(RuntimeError) as err:
			file.write()
		assert str(err.value) == "No licenses to write"

		file = OpsiLicenseFile(license_file)
		file.add_license(lic1)
		file.add_license(lic2)
		file.write()

		file = OpsiLicenseFile(license_file)
		file.read()
		assert len(file.licenses) == 2
		for lic in file.licenses:
			if lic.id == lic1.id:
				assert lic.to_dict() == lic1.to_dict()
			elif lic.id == lic2.id:
				assert lic.to_dict() == lic2.to_dict()


def test_modules_file_and_license_file(tmp_path):
	license_file = str(tmp_path / "test.opsilic")
	lic1 = dict(LIC1)
	lic1["type"] = "standard"
	lic1["module_id"] = "scalability1"
	lic1["valid_from"] = "2020-01-01"
	lic1["valid_until"] = "2020-02-01"
	lic1["revoked_ids"] = ["c6af25cf-62e4-4b90-8f4b-21c542d8b74b", "legacy-scalability1"]
	lic1 = OpsiLicense(**lic1)

	private_key, public_key = generate_key_pair(return_pem=False)
	with mock.patch("opsicommon.license.get_signature_public_key_schema_version_2", lambda: public_key):
		lic1.sign(private_key)
		file = OpsiLicenseFile(license_file)
		file.add_license(lic1)
		file.write()

		pool = OpsiLicensePool(license_file_path=str(tmp_path), modules_file_path="tests/data/license/modules")
		print(pool.license_files)
		pool.load()
		dates = pool.get_relevant_dates()
		print(dates)
		for lic in pool.get_licenses():
			print(lic.module_id, lic.get_state())
		assert len(dates) == 4

		start_date = date.fromisoformat("2010-01-01")
		assert start_date in dates
		assert lic1.valid_from in dates
		assert lic1.valid_until + timedelta(days=1) in dates

		lics = pool.get_licenses(at_date=start_date)
		for lic in lics:
			state = lic.get_state(at_date=start_date)
			if lic.schema_version == 1:
				assert state == OPSI_LICENSE_STATE_VALID
			else:
				assert state == OPSI_LICENSE_STATE_NOT_YET_VALID

		lics = pool.get_licenses(at_date=lic1.valid_from)
		for lic in lics:
			state = lic.get_state(at_date=lic1.valid_from)
			if lic.schema_version == 1 and lic.module_id == lic1.module_id:
				assert state == OPSI_LICENSE_STATE_REVOKED
			else:
				assert state == OPSI_LICENSE_STATE_VALID

		lics = pool.get_licenses(at_date=lic1.valid_until + timedelta(days=1))
		for lic in lics:
			state = lic.get_state(at_date=lic1.valid_until + timedelta(days=1))
			if lic.schema_version == 1:
				assert state == OPSI_LICENSE_STATE_VALID
			else:
				assert state == OPSI_LICENSE_STATE_EXPIRED
