# opsicommon is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2025 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0-only

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
from typing import TYPE_CHECKING, Any, Callable, Generator, Literal, Self, cast, overload

from Crypto.Hash import MD5, SHA3_512
from Crypto.Signature import pss
from Crypto.Util.number import bytes_to_long
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from opsicommon.logging import get_logger
from opsicommon.utils import json_decode, json_encode

if TYPE_CHECKING:
	# RSA import is slow
	from Crypto.PublicKey import RSA

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
	"2fa",
	"background_install",
	"custom_ca",
	"directory-connector",
	"dynamic_depot",
	"install_by_shutdown",
	"letsencrypt",
	"license_management",
	"linux_agent",
	"local_imaging",
	"macos_agent",
	"message_of_the_day",
	"monitoring",
	"mysql_backend",
	"opsi_auth",
	"roaming_profiles",
	"scalability_light",
	"scalability1",
	"secureboot",
	"sso",
	"swondemand",
	"treeview",
	"uefi",
	"userroles",
	"vista",
	"wim-capture",
	"win-vhd",
	"vpn",
)

OPSI_MODULE_BUNDLES = {
	"basic": (
		"directory-connector",
		"linux_agent",
		"license_management",
		"local_imaging",
		"monitoring",
		"userroles",
		"secureboot",
		"wim-capture",
	),
	"professional": (
		"2fa",
		"directory-connector",
		"linux_agent",
		"license_management",
		"local_imaging",
		"monitoring",
		"opsi_auth",
		"scalability_light",
		"userroles",
		"wim-capture",
		"vpn",
	),
	"enterprise": (
		"2fa",
		"custom_ca",
		"directory-connector",
		"letsencrypt",
		"license_management",
		"linux_agent",
		"local_imaging",
		"macos_agent",
		"message_of_the_day",
		"monitoring",
		"opsi_auth",
		"scalability1",
		"secureboot",
		"sso",
		"userroles",
		"wim-capture",
		"vpn",
	),
}

OPSI_OBSOLETE_MODULE_IDS = (
	"dynamic_depot",
	"treeview",
	"vista",
	"win-vhd",
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

OPSI_STAGING_MODULE_IDS = ("background_install",)

logger = get_logger("opsicommon.license")


def _hexstr2bytes(value: str) -> bytes:
	if isinstance(value, str):
		if len(value) % 2:
			value = "0" + value
		return bytes.fromhex(value)
	return value


@overload
def generate_key_pair(return_pem: Literal[True], bits: int = 2048) -> tuple[str, str]: ...


@overload
def generate_key_pair(return_pem: Literal[False], bits: int = 2048) -> tuple[RSA.RsaKey, RSA.RsaKey]: ...


def generate_key_pair(return_pem: bool = False, bits: int = 2048) -> tuple[str, str] | tuple[RSA.RsaKey, RSA.RsaKey]:
	# RSA import is slow, lazy import
	from Crypto.PublicKey import RSA

	key = RSA.generate(bits=bits)
	if not return_pem:
		return key, key.publickey()
	return key.export_key().decode(), key.publickey().export_key().decode()


@lru_cache(maxsize=None)
def get_signature_public_key_schema_version_1() -> RSA.RsaKey:
	# RSA import is slow, lazy import
	from Crypto.PublicKey import RSA

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
	# RSA import is slow, lazy import
	from Crypto.PublicKey import RSA

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


class OpsiLicense(BaseModel):
	model_config = ConfigDict(arbitrary_types_allowed=True)

	id: str = Field(pattern=OPSI_LICENCE_ID_REGEX, default_factory=generate_license_id)

	type: Literal["core", "standard"] = Field(default=OPSI_LICENSE_TYPE_STANDARD)

	schema_version: int = Field(default=2, ge=1)

	opsi_version: str = Field(default="4.2", pattern=r"^\d+\.\d+$")

	customer_id: str | None = None

	customer_name: str | None = None

	customer_address: str | None = None

	customer_unit: str | None = None

	contract_id: str | None = None

	service_id: str | None = None

	module_id: str = Field(pattern=r"^[a-z0-9\-_]+$")

	client_number: int = Field(ge=1)

	issued_at: date = Field(default_factory=date.today)

	valid_from: date = Field(default_factory=date.today)

	valid_until: date

	revoked_ids: list[str] = Field(default_factory=list)

	note: str | None = None

	additional_data: str | None = None

	signature: bytes | None = None

	# Internal use only
	license_pool: OpsiLicensePool | None = Field(exclude=True, default=None)

	checksum: str | None = Field(exclude=True, default=None)

	cached_state: dict[str, str] = Field(exclude=True, default_factory=OrderedDict)

	cached_signature_valid: bool | None = Field(exclude=True, default=None)

	@field_validator("signature", mode="before")
	@classmethod
	def validate_signature(cls, value: bytes) -> bytes:
		if isinstance(value, str):
			return _hexstr2bytes(value)
		return value

	@model_validator(mode="after")
	def validate_model(self) -> Self:
		if self.type != OPSI_LICENSE_TYPE_CORE:
			if self.schema_version > 1:
				if not self.customer_id or not re.match(r"^[a-zA-Z0-9\-_]{3,}$", self.customer_id):
					raise ValueError("Invalid customer_id")
				if not self.customer_name or not re.match(r"^\S.*\S$", self.customer_name):
					raise ValueError("Invalid customer_name")
				if not self.customer_address or not re.match(r"^\S.*\S$", self.customer_address):
					raise ValueError("Invalid customer_address")
		if not self.customer_name:
			self.customer_name = ""
		if self.service_id and not re.match(r"^[a-z0-9\-.]+$", self.service_id):
			raise ValueError("Invalid service_id")
		for revoked_id in self.revoked_ids:
			if not OPSI_LICENCE_ID_REGEX.match(revoked_id):
				raise ValueError(f"Invalid revoked_id: {revoked_id}")
		return self

	def module_ids(self) -> set[str]:
		"""Return list of module IDs provided by this license."""
		return {self.module_id} | set(OPSI_MODULE_BUNDLES.get(self.module_id, ()))

	def set_license_pool(self, license_pool: OpsiLicensePool) -> None:
		self.license_pool = license_pool

	def to_dict(self, serializable: bool = False, with_state: bool = False) -> dict:
		data = self.model_dump()
		if serializable:
			data["issued_at"] = str(data["issued_at"])
			data["valid_from"] = str(data["valid_from"])
			data["valid_until"] = str(data["valid_until"])
			if data["signature"]:
				data["signature"] = data["signature"].hex()
		if with_state:
			data["_state"] = self.get_state()
		return data

	@classmethod
	def from_dict(cls, data: dict) -> "OpsiLicense":
		return cls(**data)

	def to_json(self, with_state: bool = False) -> bytes:
		return json_encode(self.to_dict(serializable=True, with_state=with_state))

	@classmethod
	def from_json(cls, json_data: bytes) -> "OpsiLicense":
		return cls.from_dict(json_decode(json_data))

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

	def getchecksum(self, with_signature: bool = True) -> str:
		return f"{zlib.crc32(self._hash_base(with_signature)):x}"

	def get_hash(self, digest: bool = False, hex_digest: bool = False) -> MD5.MD5Hash | SHA3_512.SHA3_512_Hash | str | bytes:
		_hash: MD5.MD5Hash | SHA3_512.SHA3_512_Hash
		if self.schema_version == 1:
			_hash = MD5.new((self.additional_data or "").encode("utf-8"))
		else:
			_hash = SHA3_512.new(self._hash_base(with_signature=False))

		if hex_digest:
			return _hash.hexdigest()
		if digest:
			return _hash.digest()
		return _hash

	def clear_cache(self) -> None:
		self.cached_signature_valid = None
		self.cached_state = OrderedDict()

	def get_state(self, test_revoked: bool = True, at_date: date | None = None) -> str:
		checksum = self.getchecksum(with_signature=True)
		if checksum != self.checksum:
			self.clear_cache()
		self.checksum = checksum

		if len(self.cached_state) >= MAX_STATE_CACHE_VALUES:
			self.cached_state.popitem()

		cache_key = f"{test_revoked}{at_date}"
		if cache_key not in self.cached_state:
			self.cached_state[cache_key] = self._get_state(test_revoked=test_revoked, at_date=at_date)
		return self.cached_state[cache_key]

	def is_signature_valid(self) -> bool:
		if self.cached_signature_valid is None:
			_hash = self.get_hash()
			public_key = get_signature_public_key(self.schema_version)
			try:
				if self.schema_version == 1:
					h_int = int.from_bytes(_hash.digest(), "big")  # type: ignore[union-attr]
					s_int = public_key._encrypt(int(self.signature.hex()))  # type: ignore[attr-defined]
					self.cached_signature_valid = h_int == s_int
				else:
					pss.new(public_key).verify(_hash, self.signature)  # type: ignore[arg-type]
					self.cached_signature_valid = True
			except (ValueError, TypeError):
				logger.warning("License %r has invalid signature", self.id)
				self.cached_signature_valid = False

		return self.cached_signature_valid

	def _get_state(self, test_revoked: bool = True, at_date: date | None = None) -> str:
		if not at_date:
			at_date = date.today()

		if not self.is_signature_valid():
			return OPSI_LICENSE_STATE_INVALID_SIGNATURE

		if self.type == OPSI_LICENSE_TYPE_CORE and self.license_pool:
			module_ids = self.module_ids()
			for lic in self.license_pool.get_licenses(
				exclude_ids=[self.id], valid_only=True, test_revoked=False, types=[OPSI_LICENSE_TYPE_STANDARD], at_date=at_date
			):
				if lic.type != OPSI_LICENSE_TYPE_CORE and lic.module_ids().intersection(module_ids):
					return OPSI_LICENSE_STATE_REPLACED_BY_NON_CORE
		if test_revoked and self.license_pool and self.id in self.license_pool.get_revoked_license_ids(at_date=at_date):
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
			# RSA import is slow, lazy import
			from Crypto.PublicKey import RSA

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
			for field_name, field in OpsiLicense.model_fields.items():
				if field.exclude:
					continue
				value = lic.get(field_name)
				if field_name.startswith("_") or field_name == "id":
					continue
				if value in (None, ""):
					value = ""
				elif field_name == "revoked_ids":
					value = ",".join(value)  # type: ignore[arg-type]
				elif field_name in ("customer_name", "customer_address", "customer_unit", "note"):
					value = repr(value)[1:-1]
				data = f"{data}{field_name} = {value}\n"
			data = f"{data}\n"
		return data

	def write(self) -> None:
		if not self.filename:
			raise ValueError("Filename not defined")
		data = self.write_string()
		with codecs.open(self.filename, "w", "utf-8") as file:
			file.write(data)


class OpsiModulesFile:
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
	def __init__(
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
		self._client_info: dict[str, int] | Callable | None = client_info
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
		client_numbers: dict[str, int] = {}
		if callable(self._client_info):
			client_numbers = self._client_info()
		elif isinstance(self._client_info, dict):
			client_numbers = cast(dict[str, int], self._client_info)
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
				module_ids.update(lic.module_ids())
		return sorted(list(module_ids))

	def get_licenses(
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
			b"".join(sorted([lic.getchecksum(with_signature=False).encode("utf-8") for lic in self.get_licenses(valid_only=True)]))
		)
		return f"{data:08x}"

	def get_relevant_dates(self) -> list[date]:
		dates = set()
		for lic in self.get_licenses():
			if lic.get_state() != OPSI_LICENSE_STATE_INVALID_SIGNATURE:
				if lic.valid_from != OPSI_LICENSE_DATE_UNLIMITED:
					dates.add(lic.valid_from)
				if lic.valid_until != OPSI_LICENSE_DATE_UNLIMITED:
					dates.add(lic.valid_until + timedelta(days=1))
		return sorted(dates)

	def get_modules(self, at_date: date | None = None) -> dict[str, Any]:
		if not at_date:
			at_date = date.today()

		enabled_module_ids = self.enabled_module_ids
		client_numbers = self.client_numbers
		modules: dict[str, dict[str, Any]] = {}
		for module_id in list(OPSI_MODULE_BUNDLES) + list(OPSI_MODULE_IDS):
			if module_id in OPSI_FREE_MODULE_IDS:
				modules[module_id] = {
					"available": True,
					"state": OPSI_MODULE_STATE_FREE,
					"license_ids": [],
					"client_number": OPSI_LICENSE_CLIENT_NUMBER_UNLIMITED,
				}
			elif module_id not in OPSI_STAGING_MODULE_IDS:
				modules[module_id] = {"available": False, "state": OPSI_MODULE_STATE_UNLICENSED, "license_ids": [], "client_number": 0}

		for lic in sorted(
			self.get_licenses(valid_only=True, at_date=at_date), key=lambda li: 1 if li.type == OPSI_LICENSE_TYPE_CORE else 0
		):
			# Process CORE licenses last
			for module_id in lic.module_ids():
				if module_id not in modules:
					modules[module_id] = {"available": False, "state": OPSI_MODULE_STATE_UNLICENSED, "license_ids": [], "client_number": 0}
				if modules[module_id]["state"] == OPSI_MODULE_STATE_FREE:
					continue
				modules[module_id]["available"] = True
				modules[module_id]["state"] = OPSI_MODULE_STATE_LICENSED
				modules[module_id]["license_ids"].append(lic.id)
				modules[module_id]["license_ids"].sort()
				if lic.type == OPSI_LICENSE_TYPE_CORE:
					if modules[module_id]["client_number"] < lic.client_number:
						modules[module_id]["client_number"] = lic.client_number
				else:
					modules[module_id]["client_number"] += lic.client_number
				modules[module_id]["client_number"] = min(modules[module_id]["client_number"], OPSI_LICENSE_CLIENT_NUMBER_UNLIMITED)

		if not modules["2fa"]["available"] and modules["vpn"]["available"]:
			modules["2fa"] = modules["vpn"].copy()

		for module_id, info in modules.items():
			if module_id not in enabled_module_ids:
				info["state"] = OPSI_MODULE_STATE_UNLICENSED
				continue

			client_number = client_numbers["all"]
			if module_id == "linux_agent":
				client_number = client_numbers["linux"]
			elif module_id == "macos_agent":
				client_number = client_numbers["macos"]

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
		for lic in self.get_licenses():
			if lic.schema_version == 1:
				modules = {"signature": lic.signature.hex() if lic.signature else ""}
				for line in (lic.additional_data or "").split("\r\n"):
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


_default_opsilicense_pool = None


def set_default_opsi_license_pool(pool: OpsiLicensePool | None) -> None:
	global _default_opsilicense_pool
	_default_opsilicense_pool = pool


def get_default_opsi_license_pool(
	license_file_path: str | Path | None = None,
	modules_file_path: str | Path | None = None,
	client_info: dict | Callable | None = None,
	client_limit_warning_percent: int | None = 95,
	client_limit_warning_absolute: int | None = 5,
) -> OpsiLicensePool:
	global _default_opsilicense_pool
	if not _default_opsilicense_pool:
		_default_opsilicense_pool = OpsiLicensePool(
			license_file_path=license_file_path,
			modules_file_path=modules_file_path,
			client_info=client_info,
			client_limit_warning_percent=client_limit_warning_percent,
			client_limit_warning_absolute=client_limit_warning_absolute,
		)
		_default_opsilicense_pool.load()
	return _default_opsilicense_pool
