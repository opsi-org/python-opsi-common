# -*- coding: utf-8 -*-

# Copyright (c) 2010-2023 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
"""
License handling
"""

from __future__ import annotations

import ast
import base64
import codecs
import configparser
import glob
import json
import os
import re
import struct
import uuid
import zlib
from collections import OrderedDict
from datetime import date, timedelta
from functools import lru_cache
from pathlib import Path
from typing import (
	Any,
	Callable,
	Generator,
	Literal,
	overload,
)

import attr

from opsicommon.logging import get_logger

try:
	# PyCryptodome from pypi installs into Crypto
	from Crypto.Hash import MD5, SHA3_512
	from Crypto.PublicKey import RSA
	from Crypto.Signature import pss
	from Crypto.Util.number import bytes_to_long
except (ImportError, OSError):
	# python3-pycryptodome installs into Cryptodome
	from Cryptodome.Hash import MD5, SHA3_512  # type: ignore[import,no-redef]
	from Cryptodome.PublicKey import RSA  # type: ignore[import,no-redef]
	from Cryptodome.Signature import pss  # type: ignore[import,no-redef]
	from Cryptodome.Util.number import bytes_to_long  # type: ignore[import,no-redef]


OPSI_CLIENT_INACTIVE_AFTER = 365

OPSI_LICENCE_ID_REGEX = re.compile(r"^[a-zA-Z0-9\-_]{10,}$")

OPSI_LICENSE_TYPE_CORE = "core"
OPSI_LICENSE_TYPE_STANDARD = "standard"

OPSI_LICENSE_STATE_VALID = "valid"
OPSI_LICENSE_STATE_INVALID_SIGNATURE = "invalid_signature"
OPSI_LICENSE_STATE_EXPIRED = "expired"
OPSI_LICENSE_STATE_NOT_YET_VALID = "not_yet_valid"
OPSI_LICENSE_STATE_REVOKED = "revoked"
OPSI_LICENSE_STATE_REPLACED_BY_NON_CORE = "replaced_by_non_core"

OPSI_LICENSE_DATE_UNLIMITED = date.fromisoformat("9999-12-31")
OPSI_LICENSE_CLIENT_NUMBER_UNLIMITED = 999999999

OPSI_MODULE_STATE_FREE = "free"
OPSI_MODULE_STATE_LICENSED = "licensed"
OPSI_MODULE_STATE_UNLICENSED = "unlicensed"
OPSI_MODULE_STATE_OVER_LIMIT = "over_limit"
OPSI_MODULE_STATE_CLOSE_TO_LIMIT = "close_to_limit"

OPSI_MODULE_IDS = (
	"directory-connector",
	"dynamic_depot",
	"install_by_shutdown",
	"license_management",
	"linux_agent",
	"local_imaging",
	"macos_agent",
	"monitoring",
	"roaming_profiles",
	"scalability1",
	"secureboot",
	"swondemand",
	"treeview",
	"userroles",
	"vista",
	"wim-capture",
	"win-vhd",
	"vpn",
)

OPSI_OBSOLETE_MODULE_IDS = (
	"dynamic_depot",
	"treeview",
	"vista",
)

OPSI_FREE_MODULE_IDS = (
	"dynamic_depot",
	"install_by_shutdown",
	"mysql_backend",
	"roaming_profiles",
	"swondemand",
	"treeview",
	"uefi",
	"vista",
)

logger = get_logger("opsicommon.license")


def _str2date(value: str) -> date:
	if isinstance(value, str):
		return date.fromisoformat(value)
	return value


def _hexstr2bytes(value: str) -> bytes:
	if isinstance(value, str):
		if len(value) % 2:
			value = "0" + value
		return bytes.fromhex(value)
	return value


@overload
def generate_key_pair(return_pem: Literal[True], bits: int = 2048) -> tuple[str, str]:
	...


@overload
def generate_key_pair(return_pem: Literal[False], bits: int = 2048) -> tuple[RSA.RsaKey, RSA.RsaKey]:
	...


def generate_key_pair(return_pem: bool = False, bits: int = 2048) -> tuple[str, str] | tuple[RSA.RsaKey, RSA.RsaKey]:
	key = RSA.generate(bits=bits)
	if not return_pem:
		return key, key.publickey()
	return key.export_key().decode(), key.publickey().export_key().decode()


@lru_cache(maxsize=None)
def get_signature_public_key_schema_version_1() -> RSA.RsaKey:
	data = base64.decodebytes(
		b"AAAAB3NzaC1yc2EAAAADAQABAAABAQCAD/I79Jd0eKwwfuVwh5B2z+S8aV0C5suItJa18RrYip+d4P0ogzqoCfOoVWtDo"
		b"jY96FDYv+2d73LsoOckHCnuh55GA0mtuVMWdXNZIE8Avt/RzbEoYGo/H0weuga7I8PuQNC/nyS8w3W8TH4pt+ZCjZZoX8"
		b"S+IizWCYwfqYoYTMLgB0i+6TCAfJj3mNgCrDZkQ24+rOFS4a8RrjamEz/b81noWl9IntllK1hySkR+LbulfTGALHgHkDU"
		b"lk0OSu+zBPw/hcDSOMiDQvvHfmR4quGyLPbQ2FOVm1TzE0bQPR+Bhx4V8Eo2kNYstG2eJELrz7J1TJI0rCjpB+FQjYPsP"
	)

	# Key type can be found in 4:11.
	rest = data[11:]
	count = 0
	tmp = []
	for _ in range(2):
		length = struct.unpack(">L", rest[count : count + 4])[0]
		tmp.append(bytes_to_long(rest[count + 4 : count + 4 + length]))
		count += 4 + length

	return RSA.construct((tmp[1], tmp[0]))


@lru_cache(maxsize=None)
def get_signature_public_key_schema_version_2() -> RSA.RsaKey:
	return RSA.import_key(
		"-----BEGIN PUBLIC KEY-----\n"
		"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqTWmFj6m6O3gO676GStL\n"
		"Kk388kPxRRvQ7uoieSyafmwmsxxGiRQ6ifM+I2m8o3Gk5wEVBI+UU2jIZONTvNOP\n"
		"RbSmm96NEfHMUbnwwNwn5J5j8a9NpT6/sthEzptevgm6inCIpGlnhD03/Qaqx5qn\n"
		"81kczHMIcfYjpzgIRK7xBdG7XEpgVzsdwVI5EgBoX651n6TgJ5nHIYlOwhmF6L3W\n"
		"y/LEF4vQ5amESMTQ5eOR9xEfZoUgeyt15JLl9TUBQqoSx8nkS+O2o+qYF9wiFaFm\n"
		"ZqmPuNFbk1fM1BrsqrBMFVrzx6mRFdDfAdpqtxfFaOWTLwGGFaOEi2k39EVgnc6Z\n"
		"8QIDAQAB\n"
		"-----END PUBLIC KEY-----\n"
	)


def get_signature_public_key(schema_version: int) -> RSA.RsaKey:
	if schema_version < 2:
		return get_signature_public_key_schema_version_1()
	return get_signature_public_key_schema_version_2()


MAX_STATE_CACHE_VALUES = 64


def generate_license_id() -> str:
	return str(uuid.uuid4())


@attr.s(slots=True, auto_attribs=True, kw_only=True)
class OpsiLicense:  # pylint: disable=too-few-public-methods,too-many-instance-attributes
	id: str = attr.ib(  # pylint: disable=invalid-name
		factory=generate_license_id, validator=attr.validators.matches_re(OPSI_LICENCE_ID_REGEX)
	)

	type: str = attr.ib(
		default=OPSI_LICENSE_TYPE_STANDARD, validator=attr.validators.in_((OPSI_LICENSE_TYPE_CORE, OPSI_LICENSE_TYPE_STANDARD))
	)

	schema_version: int = attr.ib(default=2, converter=int)

	@schema_version.validator
	def validate_schema_version(self, attribute: str, value: Any) -> None:  # pylint: disable=bad-classmethod-argument
		if not isinstance(value, int) or value <= 0:
			raise ValueError(f"Invalid value for {attribute}", value)

	opsi_version: str = attr.ib(default="4.2", validator=attr.validators.matches_re(r"^\d+\.\d+$"))

	customer_id: str = attr.ib(default=None)

	@customer_id.validator
	def validate_customer_id(self, attribute: str, value: Any) -> None:  # pylint: disable=bad-classmethod-argument
		if self.schema_version > 1 and self.type != OPSI_LICENSE_TYPE_CORE and not re.match(r"^[a-zA-Z0-9\-_]{3,}$", value):
			raise ValueError(f"Invalid value for {attribute}", value)

	customer_name: str = attr.ib()

	@customer_name.validator
	def validate_customer_name(self, attribute: str, value: Any) -> None:  # pylint: disable=bad-classmethod-argument
		if self.type != OPSI_LICENSE_TYPE_CORE and not re.match(r"^\S.*\S$", value):
			raise ValueError(f"Invalid value for {attribute}", value)

	customer_address: str = attr.ib(default=None)

	@customer_address.validator
	def validate_customer_address(self, attribute: str, value: Any) -> None:  # pylint: disable=bad-classmethod-argument
		if self.schema_version > 1 and self.type != OPSI_LICENSE_TYPE_CORE and not re.match(r"^\S.*\S$", value):
			raise ValueError(f"Invalid value for {attribute}", value)

	customer_unit: str = attr.ib(default=None)

	contract_id: str = attr.ib(default=None)

	service_id: str = attr.ib(
		default=None,
	)

	@service_id.validator
	def validate_service_id(self, attribute: str, value: Any) -> None:  # pylint: disable=bad-classmethod-argument
		if value is not None and not re.match(r"^[a-z0-9\-\.]+$", value):
			raise ValueError(f"Invalid value for {attribute}", value)

	module_id: str = attr.ib(validator=attr.validators.matches_re(r"^[a-z0-9\-_]+$"))

	client_number: int = attr.ib(converter=int, validator=attr.validators.instance_of(int))

	@client_number.validator
	def validate_client_number(self, attribute: str, value: Any) -> None:  # pylint: disable=bad-classmethod-argument
		if value <= 0:
			raise ValueError(f"Invalid value for {attribute}", value)

	issued_at: date = attr.ib(factory=date.today, converter=_str2date, validator=attr.validators.instance_of(date))

	valid_from: date = attr.ib(factory=date.today, converter=_str2date, validator=attr.validators.instance_of(date))

	valid_until: date = attr.ib(converter=_str2date, validator=attr.validators.instance_of(date))

	revoked_ids: list[str] = attr.ib(default=[])

	@revoked_ids.validator
	def validate_revoked_ids(self, attribute: str, value: Any) -> None:  # pylint: disable=bad-classmethod-argument
		if not isinstance(value, list):
			raise ValueError(f"Invalid value for {attribute}", value)
		for val in value:
			if not OPSI_LICENCE_ID_REGEX.match(val):
				raise ValueError(f"Invalid value for {attribute}", val)

	note: str = attr.ib(default=None)

	additional_data: str = attr.ib(default=None)

	signature: bytes = attr.ib(
		default=None,
		converter=_hexstr2bytes,
	)

	_license_pool: OpsiLicensePool = attr.ib(default=None)

	_checksum: str = attr.ib(default=None)

	_cached_state: dict[str, str] = attr.ib(default=OrderedDict())

	_cached_signature_valid: bool | None = None

	def __attrs_post_init__(self) -> None:
		for attribute, value in attr.asdict(self).items():
			if not attribute.startswith("_") and isinstance(value, str) and value.strip() == "":
				setattr(self, attribute, None)

	def set_license_pool(self, license_pool: OpsiLicensePool) -> None:
		self._license_pool = license_pool

	def to_dict(self, serializable: bool = False, with_state: bool = False) -> dict:
		res = attr.asdict(self)
		del res["_license_pool"]
		del res["_checksum"]
		del res["_cached_state"]
		del res["_cached_signature_valid"]
		if with_state:
			res["_state"] = self.get_state()
		if serializable:
			res["issued_at"] = str(res["issued_at"])
			res["valid_from"] = str(res["valid_from"])
			res["valid_until"] = str(res["valid_until"])
			if res["signature"]:
				res["signature"] = res["signature"].hex()
		return res

	@classmethod
	def from_dict(cls, data_dict: dict) -> "OpsiLicense":
		data_dict = dict(data_dict)
		for attribute in list(data_dict):
			if attribute.startswith("_"):
				del data_dict[attribute]
		return OpsiLicense(**data_dict)

	def to_json(self, with_state: bool = False) -> str:
		return json.dumps(self.to_dict(serializable=True, with_state=with_state))

	@classmethod
	def from_json(cls, json_data: str) -> "OpsiLicense":
		return OpsiLicense.from_dict(json.loads(json_data))

	def _hash_base(self, with_signature: bool = True) -> bytes:
		string = ""
		data = self.to_dict(serializable=True, with_state=False)
		for attribute in sorted(data):
			if attribute.startswith("_") or (attribute == "signature" and not with_signature):
				continue
			value = data[attribute]
			if isinstance(value, list):
				value = ",".join(sorted(value))
			string += f"{attribute}={json.dumps(value)}\n"
		return string.encode("utf-8")

	def get_checksum(self, with_signature: bool = True) -> str:
		return f"{zlib.crc32(self._hash_base(with_signature)):x}"

	def get_hash(self, digest: bool = False, hex_digest: bool = False) -> MD5.MD5Hash | SHA3_512.SHA3_512_Hash | str | bytes:
		_hash: MD5.MD5Hash | SHA3_512.SHA3_512_Hash
		if self.schema_version == 1:
			_hash = MD5.new(self.additional_data.encode("utf-8"))
		else:
			_hash = SHA3_512.new(self._hash_base(with_signature=False))

		if hex_digest:
			return _hash.hexdigest()
		if digest:
			return _hash.digest()
		return _hash

	def clear_cache(self) -> None:
		self._cached_signature_valid = None
		self._cached_state = OrderedDict()

	def get_state(self, test_revoked: bool = True, at_date: date | None = None) -> str:
		checksum = self.get_checksum(with_signature=True)
		if checksum != self._checksum:
			self.clear_cache()
		self._checksum = checksum

		if len(self._cached_state) >= MAX_STATE_CACHE_VALUES:
			self._cached_state.popitem()

		cache_key = f"{test_revoked}{at_date}"
		if cache_key not in self._cached_state:
			self._cached_state[cache_key] = self._get_state(test_revoked=test_revoked, at_date=at_date)
		return self._cached_state[cache_key]

	def is_signature_valid(self) -> bool:
		if self._cached_signature_valid is None:
			_hash = self.get_hash()
			public_key = get_signature_public_key(self.schema_version)
			try:
				if self.schema_version == 1:
					h_int = int.from_bytes(_hash.digest(), "big")  # type: ignore[union-attr]
					s_int = public_key._encrypt(int(self.signature.hex()))  # type: ignore[attr-defined] # pylint: disable=protected-access
					self._cached_signature_valid = h_int == s_int
				else:
					pss.new(public_key).verify(_hash, self.signature)  # type: ignore[arg-type]
					self._cached_signature_valid = True
			except (ValueError, TypeError):
				logger.warning("License %r has invalid signature", self.id)
				self._cached_signature_valid = False

		return self._cached_signature_valid

	def _get_state(self, test_revoked: bool = True, at_date: date | None = None) -> str:  # pylint: disable=too-many-return-statements
		if not at_date:
			at_date = date.today()

		if not self.is_signature_valid():
			return OPSI_LICENSE_STATE_INVALID_SIGNATURE

		if self.type == OPSI_LICENSE_TYPE_CORE and self._license_pool:
			for lic in self._license_pool.get_licenses(
				exclude_ids=[self.id], valid_only=True, test_revoked=False, types=[OPSI_LICENSE_TYPE_STANDARD], at_date=at_date
			):
				if lic.type != OPSI_LICENSE_TYPE_CORE and lic.module_id == self.module_id:
					return OPSI_LICENSE_STATE_REPLACED_BY_NON_CORE
		if test_revoked and self._license_pool and self.id in self._license_pool.get_revoked_license_ids(at_date=at_date):
			return OPSI_LICENSE_STATE_REVOKED
		if (self.valid_from - at_date).days > 0:
			return OPSI_LICENSE_STATE_NOT_YET_VALID
		if (self.valid_until - at_date).days < 0:
			return OPSI_LICENSE_STATE_EXPIRED
		return OPSI_LICENSE_STATE_VALID

	def sign(self, private_key: RSA.RsaKey | str) -> None:
		if self.schema_version < 2:
			raise NotImplementedError("Signing for schema_version < 2 not implemented")
		if isinstance(private_key, str):
			private_key = RSA.import_key(private_key.encode("ascii"))
		self.signature = pss.new(private_key).sign(self.get_hash())  # type: ignore[arg-type]


class OpsiLicenseFile:
	def __init__(self, filename: str | None) -> None:
		self.filename = filename
		self._licenses: dict[str, OpsiLicense] = {}

	@property
	def licenses(self) -> list[OpsiLicense]:
		return list(self._licenses.values())

	def add_license(self, opsi_license: OpsiLicense) -> None:
		self._licenses[opsi_license.id] = opsi_license

	def read_string(self, data: str) -> None:
		ini = configparser.ConfigParser()
		ini.read_string(data)
		for section in ini.sections():
			kwargs = dict(ini.items(section=section, raw=True))
			kwargs["id"] = section
			for key in ("customer_name", "customer_address", "customer_unit", "note"):
				kwargs[key] = ast.literal_eval(f'"{kwargs.get(key)}"') or None  # type: ignore[assignment]
			kwargs["revoked_ids"] = [x.strip() for x in kwargs.get("revoked_ids", "").split(",") if x]  # type: ignore[assignment]
			for key, val in kwargs.items():
				if val == "":
					kwargs[key] = None  # type: ignore[assignment]
			self.add_license(OpsiLicense(**kwargs))  # type: ignore[arg-type]

	def read(self) -> None:
		if not self.filename:
			raise ValueError("Filename not defined")
		with open(self.filename, "r", encoding="utf-8") as file:
			self.read_string(file.read())

	def write_string(self) -> str:
		if not self._licenses:
			raise RuntimeError("No licenses to write")

		data = ""
		for license_id in sorted(self._licenses):
			data = f"{data}[{license_id}]\n"
			lic = self._licenses[license_id].to_dict(serializable=True)
			for field in attr.fields(OpsiLicense):
				value = lic.get(field.name)
				if field.name.startswith("_") or field.name == "id":
					continue
				if value in (None, ""):
					value = ""
				elif field.name == "revoked_ids":
					value = ",".join(value)  # type: ignore[arg-type]
				elif field.name in ("customer_name", "customer_address", "customer_unit", "note"):
					value = repr(value)[1:-1]
				data = f"{data}{field.name} = {value}\n"
			data = f"{data}\n"
		return data

	def write(self) -> None:
		if not self.filename:
			raise ValueError("Filename not defined")
		data = self.write_string()
		with codecs.open(self.filename, "w", "utf-8") as file:
			file.write(data)


class OpsiModulesFile:  # pylint: disable=too-few-public-methods
	def __init__(self, filename: Path | str) -> None:
		self.filename = filename if isinstance(filename, Path) else Path(filename)
		self._licenses: dict[str, OpsiLicense] = {}

	@property
	def licenses(self) -> list[OpsiLicense]:
		return list(self._licenses.values())

	def add_license(self, opsi_license: OpsiLicense) -> None:
		self._licenses[opsi_license.id] = opsi_license

	def _read_raw_data(self) -> dict[str, str]:
		data: dict[str, str] = {}
		if self.filename.is_dir():
			logger.error("License file %r is a directory", self.filename)
			return data

		for line in self.filename.read_text(encoding="utf-8").split("\n"):
			line = line.strip()
			if "=" not in line:
				continue
			(attribute, value) = line.split("=", 1)
			attribute = attribute.strip().lower()
			value = value.strip()
			if attribute != "customer":
				value = value.lower()
			data[attribute] = value
		return data

	def read(self) -> None:
		data = self._read_raw_data()
		common_lic = {
			"type": OPSI_LICENSE_TYPE_STANDARD,
			"schema_version": 1,
			"opsi_version": "4.1",
			"issued_at": "2010-01-01",
			"valid_from": "2010-01-01",
			"additional_data": "",
		}
		modules = {}
		for attribute in sorted(data):
			value = data[attribute]
			if attribute != "signature":
				common_lic["additional_data"] = f"{common_lic['additional_data']}{attribute} = {value}\r\n"

			if attribute == "signature":
				common_lic["signature"] = value
			elif attribute == "customer":
				common_lic["customer_name"] = value
			elif attribute == "expires":
				if value == "never":
					value = OPSI_LICENSE_DATE_UNLIMITED  # type: ignore[assignment]
				common_lic["valid_until"] = value
			else:
				module_id = attribute.lower()
				client_number = 0
				try:
					client_number = int(value)
				except ValueError:
					if value == "yes":
						client_number = OPSI_LICENSE_CLIENT_NUMBER_UNLIMITED
				if client_number > 0:
					modules[module_id] = client_number

		for module_id, client_number in modules.items():
			kwargs = dict(common_lic)
			kwargs["id"] = f"legacy-{module_id}"
			kwargs["module_id"] = module_id
			kwargs["client_number"] = client_number
			self.add_license(OpsiLicense(**kwargs))  # type: ignore[arg-type]


class OpsiLicensePool:
	def __init__(  # pylint: disable=too-many-arguments
		self,
		license_file_path: str | Path | None = None,
		modules_file_path: str | Path | None = None,
		client_info: dict | Callable | None = None,
		client_limit_warning_percent: int | None = 95,
		client_limit_warning_absolute: int | None = 5,
	) -> None:
		self.license_file_path: str | None = str(license_file_path) if license_file_path else None
		self.modules_file_path: str | None = str(modules_file_path) if modules_file_path else None
		self.client_limit_warning_percent: int | None = client_limit_warning_percent
		self.client_limit_warning_absolute: int | None = client_limit_warning_absolute
		self._client_info: dict | Callable | None = client_info
		self._licenses: dict[str, OpsiLicense] = {}
		self._file_modification_dates: dict[str, float] = {}

	@property
	def license_files(self) -> list[str]:
		license_files = []
		if self.license_file_path and os.path.exists(self.license_file_path):
			license_files = [self.license_file_path]
			if os.path.isdir(self.license_file_path):
				license_files = glob.glob(os.path.join(self.license_file_path, "*.opsilic"))
		return license_files

	@property
	def modules_file(self) -> str | None:
		if self.modules_file_path and os.path.exists(self.modules_file_path):
			return self.modules_file_path
		return None

	@property
	def licenses(self) -> list[OpsiLicense]:
		return list(self.get_licenses())

	@property
	def client_numbers(self) -> dict[str, int]:
		client_numbers = {}
		if callable(self._client_info):
			client_numbers = self._client_info()
		elif self._client_info:
			client_numbers = dict(self._client_info)
		client_numbers["all"] = 0
		for client_type in ("windows", "linux", "macos"):
			if client_type not in client_numbers:
				client_numbers[client_type] = 0
			client_numbers["all"] += client_numbers[client_type]
		return client_numbers

	@property
	def enabled_module_ids(self) -> list[str]:
		module_ids = set(OPSI_FREE_MODULE_IDS)
		for lic in self._licenses.values():
			if lic.is_signature_valid():
				module_ids.add(lic.module_id)
		return sorted(list(module_ids))

	def get_licenses(  # pylint: disable=too-many-arguments
		self,
		exclude_ids: list[str] | None = None,
		valid_only: bool = False,
		test_revoked: bool = True,
		types: list[str] | None = None,
		at_date: date | None = None,
	) -> Generator[OpsiLicense, None, None]:
		if not at_date:
			at_date = date.today()

		for lic in self._licenses.values():
			if exclude_ids and lic.id in exclude_ids:
				continue
			if types and lic.type not in types:
				continue
			if valid_only and lic.get_state(test_revoked=test_revoked, at_date=at_date) != OPSI_LICENSE_STATE_VALID:
				continue
			yield lic

	def clear_license_state_cache(self) -> None:
		for lic in self._licenses.values():
			lic.clear_cache()

	def add_license(self, *opsi_license: OpsiLicense) -> None:
		for lic in opsi_license:
			lic.set_license_pool(self)
			self._licenses[lic.id] = lic
		self.clear_license_state_cache()

	def remove_license(self, *opsi_license: OpsiLicense) -> None:
		for lic in opsi_license:
			if lic.id in self._licenses:
				del self._licenses[lic.id]
		self.clear_license_state_cache()

	def get_revoked_license_ids(self, at_date: date | None = None) -> set[str]:
		if not at_date:
			at_date = date.today()
		revoked_ids = set()
		for lic in self._licenses.values():
			if lic.get_state(test_revoked=False, at_date=at_date) == OPSI_LICENSE_STATE_VALID:
				for revoked_id in lic.revoked_ids:
					revoked_ids.add(revoked_id)
		return revoked_ids

	def get_licenses_checksum(self) -> str:
		data = zlib.crc32(
			b"".join(sorted([lic.get_checksum(with_signature=False).encode("utf-8") for lic in self.get_licenses(valid_only=True)]))
		)
		return f"{data:x}"

	def get_relevant_dates(self) -> list[date]:
		dates = set()
		for lic in self.get_licenses():
			if lic.get_state() != OPSI_LICENSE_STATE_INVALID_SIGNATURE:
				if lic.valid_from != OPSI_LICENSE_DATE_UNLIMITED:
					dates.add(lic.valid_from)
				if lic.valid_until != OPSI_LICENSE_DATE_UNLIMITED:
					dates.add(lic.valid_until + timedelta(days=1))
		return sorted(dates)

	def get_modules(self, at_date: date | None = None) -> dict[str, Any]:  # pylint: disable=too-many-branches
		if not at_date:
			at_date = date.today()

		enabled_module_ids = self.enabled_module_ids
		client_numbers = self.client_numbers
		modules: dict[str, dict[str, Any]] = {}
		for module_id in OPSI_MODULE_IDS:
			if module_id in OPSI_FREE_MODULE_IDS:
				modules[module_id] = {
					"available": True,
					"state": OPSI_MODULE_STATE_FREE,
					"license_ids": [],
					"client_number": OPSI_LICENSE_CLIENT_NUMBER_UNLIMITED,
				}
			else:
				modules[module_id] = {"available": False, "state": OPSI_MODULE_STATE_UNLICENSED, "license_ids": [], "client_number": 0}

		for lic in self.get_licenses(valid_only=True, at_date=at_date):
			if lic.module_id not in modules:
				modules[lic.module_id] = {"client_number": 0, "license_ids": []}
			elif modules[lic.module_id]["state"] == OPSI_MODULE_STATE_FREE:
				continue

			modules[lic.module_id]["available"] = True
			modules[lic.module_id]["state"] = OPSI_MODULE_STATE_LICENSED
			modules[lic.module_id]["license_ids"].append(lic.id)
			modules[lic.module_id]["license_ids"].sort()
			modules[lic.module_id]["client_number"] += lic.client_number
			modules[lic.module_id]["client_number"] = min(modules[lic.module_id]["client_number"], OPSI_LICENSE_CLIENT_NUMBER_UNLIMITED)

		for module_id, info in modules.items():
			if module_id not in enabled_module_ids:
				info["state"] = OPSI_MODULE_STATE_UNLICENSED
				continue

			client_number = client_numbers["all"]
			if module_id == "linux_agent":
				client_number = client_numbers["linux"]
			elif module_id == "macos_agent":
				client_number = client_numbers["macos"]
			# elif module_id == "vpn":
			# client_number = client_numbers["vpn"]

			usage_percent = 100
			if info["client_number"] > 0:
				usage_percent = client_number * 100 / info["client_number"]
			absolute_free = info["client_number"] - client_number
			if client_number >= info["client_number"] + info["client_number"] ** 0.5:
				info["state"] = OPSI_MODULE_STATE_OVER_LIMIT
				info["available"] = False
			elif absolute_free < 0 or usage_percent > 100:
				info["state"] = OPSI_MODULE_STATE_OVER_LIMIT
			elif (self.client_limit_warning_absolute and (absolute_free <= self.client_limit_warning_absolute)) or (
				self.client_limit_warning_percent and (usage_percent >= self.client_limit_warning_percent)
			):
				info["state"] = OPSI_MODULE_STATE_CLOSE_TO_LIMIT

		return modules

	def get_legacy_modules(self) -> dict[str, Any] | None:
		for lic in self.get_licenses():  # pylint: disable=too-many-nested-blocks
			if lic.schema_version == 1:
				modules = {"signature": lic.signature.hex()}
				for line in lic.additional_data.split("\r\n"):
					if line.strip():
						attribute, value = line.split("=", 1)
						attribute = attribute.strip()
						value = value.strip()
						if attribute != "customer":
							try:
								value = int(value)  # type: ignore[assignment]
							except ValueError:
								pass
						modules[attribute] = value
				return modules
		return None

	def _read_license_files(self) -> None:
		for license_file in self.license_files:
			olf = OpsiLicenseFile(license_file)
			olf.read()
			self.add_license(*olf.licenses)
			self._file_modification_dates[license_file] = os.path.getmtime(license_file)

	def _read_modules_file(self) -> None:
		modules_file = self.modules_file
		if not modules_file:
			return
		omf = OpsiModulesFile(modules_file)
		omf.read()
		self.add_license(*omf.licenses)
		self._file_modification_dates[modules_file] = os.path.getmtime(modules_file)

	def modified(self) -> bool:
		files = self.license_files
		modules_file = self.modules_file
		if modules_file:
			files.append(modules_file)
		if len(files) != len(self._file_modification_dates):
			return True
		for file in files:
			if file not in self._file_modification_dates:
				return True
			if os.path.getmtime(file) != self._file_modification_dates[file]:
				return True
		return False

	def load(self) -> None:
		self._licenses = {}
		self._file_modification_dates = {}
		if self.license_files:
			self._read_license_files()
		self._read_modules_file()


_default_opsi_license_pool = None  # pylint: disable=invalid-name


def set_default_opsi_license_pool(pool: OpsiLicensePool | None) -> None:
	global _default_opsi_license_pool  # pylint: disable=invalid-name,global-statement
	_default_opsi_license_pool = pool


def get_default_opsi_license_pool(
	license_file_path: str | Path | None = None,
	modules_file_path: str | Path | None = None,
	client_info: dict | Callable | None = None,
	client_limit_warning_percent: int | None = 95,
	client_limit_warning_absolute: int | None = 5,
) -> OpsiLicensePool:
	global _default_opsi_license_pool  # pylint: disable=invalid-name,global-statement
	if not _default_opsi_license_pool:
		_default_opsi_license_pool = OpsiLicensePool(
			license_file_path=license_file_path,
			modules_file_path=modules_file_path,
			client_info=client_info,
			client_limit_warning_percent=client_limit_warning_percent,
			client_limit_warning_absolute=client_limit_warning_absolute,
		)
		_default_opsi_license_pool.load()
	return _default_opsi_license_pool
