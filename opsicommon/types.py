# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
Type forcing features.

This module contains various methods to ensure force a special type
on an object.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import re
import sys
import time
import types
from typing import TYPE_CHECKING, Any, Callable, Optional, Type, Union
from uuid import UUID

from opsicommon.logging import get_logger

if os.name != "nt":
	WindowsError = RuntimeError

if TYPE_CHECKING:
	from opsicommon.objects import BaseObjectT

__all__ = (
	"args",
	"forceActionProgress",
	"forceActionRequest",
	"forceActionRequestList",
	"forceActionResult",
	"forceArchitecture",
	"forceArchitectureList",
	"forceAuditState",
	"forceBool",
	"forceBoolList",
	"forceConfigId",
	"forceDict",
	"forceDictList",
	"forceDomain",
	"forceEmailAddress",
	"forceFilename",
	"forceFloat",
	"forceFqdn",
	"forceGroupId",
	"forceGroupIdList",
	"forceGroupType",
	"forceGroupTypeList",
	"forceHardwareAddress",
	"forceHardwareDeviceId",
	"forceHardwareVendorId",
	"forceHostAddress",
	"forceHostId",
	"forceHostIdList",
	"forceHostname",
	"forceIPAddress",
	"forceInstallationStatus",
	"forceInt",
	"forceIntList",
	"forceIpAddress",
	"forceLanguageCode",
	"forceLanguageCodeList",
	"forceLicenseContractId",
	"forceLicenseContractIdList",
	"forceLicensePoolId",
	"forceLicensePoolIdList",
	"forceList",
	"forceNetmask",
	"forceNetworkAddress",
	"forceObjectClass",
	"forceObjectClassList",
	"forceObjectId",
	"forceObjectIdList",
	"forceOct",
	"forceOpsiHostKey",
	"forceOpsiTimestamp",
	"forcePackageCustomName",
	"forcePackageVersion",
	"forcePackageVersionList",
	"forceProductId",
	"forceProductIdList",
	"forceProductPriority",
	"forceProductPropertyId",
	"forceProductPropertyType",
	"forceProductTargetConfiguration",
	"forceProductType",
	"forceProductVersion",
	"forceProductVersionList",
	"forceRequirementType",
	"forceSoftwareLicenseId",
	"forceSoftwareLicenseIdList",
	"forceTime",
	"forceUnicode",
	"forceUnicodeList",
	"forceUnicodeLower",
	"forceUnicodeLowerList",
	"forceUnicodeUpper",
	"forceUniqueList",
	"forceUnsignedInt",
	"forceUrl",
)

logger = get_logger("opsicommon.general")
encoding = sys.getfilesystemencoding()
get_object_type: Callable | None = None
from_json: Callable | None = None

_HARDWARE_ID_REGEX = re.compile(r"^[a-fA-F0-9]{4}$")
_OPSI_TIMESTAMP_REGEX = re.compile(r"^(\d{4})-?(\d{2})-?(\d{2})\s?(\d{2}):?(\d{2}):?(\d{2})\.?\d*$")
_OPSI_DATE_REGEX = re.compile(r"^(\d{4})-?(\d{2})-?(\d{2})$")
_FQDN_REGEX = re.compile(r"^[a-z0-9][a-z0-9\-]{,63}\.((\w+\-+)|(\w+\.))*\w{1,63}\.\w{2,16}\.?$")
_HARDWARE_ADDRESS_REGEX = re.compile(
	r"^([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})$"
)
_NETMASK_REGEX = re.compile(
	r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"  # pylint: disable=line-too-long
)
_URL_REGEX = re.compile(r"^[a-z0-9]+:\/\/[/a-zA-Z0-9@:%._\+~#?&=\[\]]+")
_OPSI_HOST_KEY_REGEX = re.compile(r"^[0-9a-f]{32}$")
_PRODUCT_VERSION_REGEX = re.compile(r"^[a-zA-Z0-9.]{1,32}$")
_PACKAGE_VERSION_REGEX = re.compile(r"^[a-zA-Z0-9.]{1,16}$")
_PRODUCT_ID_REGEX = re.compile(r"^[a-z0-9-_\.]{1,128}$")
_PACKAGE_CUSTOM_NAME_REGEX = re.compile(r"^[a-zA-Z0-9]+$")
_PRODUCT_PROPERTY_ID_REGEX = re.compile(r"^\S+$")
_CONFIG_ID_REGEX = re.compile(r"^\S+$")
_GROUP_ID_REGEX = re.compile(r"^[a-z0-9][a-z0-9-_. ]*$")
_OBJECT_ID_REGEX = re.compile(r"^[a-z0-9][a-z0-9-_. ]*$")
_EMAIL_REGEX = re.compile(r"^(([A-Za-z0-9]+_+)|([A-Za-z0-9]+\-+)|([A-Za-z0-9]+\.+)|([A-Za-z0-9]+\++))*[A-Za-z0-9]+@((\w+\-+)|(\w+\.))*\w*")
_DOMAIN_REGEX = re.compile(r"^((\w+\-+)|(\w+\.))*\w{1,63}\.\w{2,16}\.?$")
_HOSTNAME_REGEX = re.compile(r"^[a-z0-9][a-z0-9\-]*$")
_LICENSE_CONTRACT_ID_REGEX = re.compile(r"^[a-z0-9][a-z0-9-_. :]*$")
_SOFTWARE_LICENSE_ID_REGEX = re.compile(r"^[a-z0-9][a-z0-9-_. :]*$")
_LICENSE_POOL_ID_REGEX = re.compile(r"^[a-z0-9][a-z0-9-_. :]*$")
_LANGUAGE_CODE_REGEX = re.compile(r"^([a-z]{2,3})[-_]?([a-z]{4})?[-_]?([a-z]{2})?$")
_ARCHITECTURE_REGEX = re.compile(r"^(x86|x64)$")


def forceList(var: Any) -> list[Any]:  # pylint: disable=invalid-name
	if not isinstance(var, (set, list, tuple, types.GeneratorType)):
		return [var]

	return list(var)


def forceString(var: Any) -> str:  # pylint: disable=too-many-return-statements,invalid-name
	if isinstance(var, str):
		return var
	if os.name == "nt" and isinstance(var, WindowsError):
		try:
			return f"[Error {var.args[0]}] {var.args[1]}"
		except Exception:  # pylint: disable=broad-except
			return str(var)
	try:
		if isinstance(var, bytes):
			return var.decode()
	except Exception:  # pylint: disable=broad-except
		pass

	try:
		var = repr(var)
		if isinstance(var, str):
			return var
		return str(var, "utf-8", "replace")
	except Exception:  # pylint: disable=broad-except
		pass

	return str(var)


forceUnicode = forceString


def forceStringLower(var: Any) -> str:  # pylint: disable=invalid-name
	return forceString(var).lower()


forceUnicodeLower = forceStringLower


def forceStringUpper(var: Any) -> str:  # pylint: disable=invalid-name
	return forceString(var).upper()


forceUnicodeUpper = forceStringUpper


def forceStringList(var: Any) -> list[str]:  # pylint: disable=invalid-name
	return [forceString(element) for element in forceList(var)]


forceUnicodeList = forceStringList


def forceDictList(var: Any) -> list[dict]:  # pylint: disable=invalid-name
	return [forceDict(element) for element in forceList(var)]


def forceUnicodeLowerList(var: Any) -> list[str]:  # pylint: disable=invalid-name
	return [forceUnicodeLower(element) for element in forceList(var)]


def forceUUID(var: Any) -> UUID:  # pylint: disable=invalid-name
	if isinstance(var, UUID):
		return var
	return UUID(forceString(var))


def forceUUIDString(var: Any) -> str:  # pylint: disable=invalid-name
	return str(forceUUID(var))


def forceBool(var: Any) -> bool:  # pylint: disable=invalid-name
	if isinstance(var, bool):
		return var
	if isinstance(var, str):
		if len(var) <= 5:  # longest word is 5 characters ("false")
			low_value = var.lower()
			if low_value in ("true", "yes", "on", "1"):
				return True
			if low_value in ("false", "no", "off", "0"):
				return False

	return bool(var)


def forceBoolList(var: Any) -> list[bool]:  # pylint: disable=invalid-name
	return [forceBool(element) for element in forceList(var)]


def forceInt(var: Any) -> int:  # pylint: disable=invalid-name
	if isinstance(var, int):
		return var
	try:
		return int(var)
	except Exception as err:
		raise ValueError(f"Bad int value '{var}': {err}") from err


def forceIntList(var: Any) -> list[int]:  # pylint: disable=invalid-name
	return [forceInt(element) for element in forceList(var)]


def forceUnsignedInt(var: Any) -> int:  # pylint: disable=invalid-name
	var = forceInt(var)
	if var < 0:
		var = -1 * var
	return var


def forceOct(var: Any) -> int:  # pylint: disable=invalid-name
	if isinstance(var, int):
		return var

	try:
		oct_value = ""
		for idx, val_str in enumerate(forceString(var)):
			val = forceInt(val_str)
			if val > 7:
				raise ValueError(f"{val} is too big")
			if idx == 0 and val != "0":
				oct_value += "0"
			oct_value += str(val)

		oct_value_int = int(oct_value, 8)
		return oct_value_int
	except Exception as err:  # pylint: disable=broad-except
		raise ValueError(f"Bad oct value {var}: {err}") from err


def forceFloat(var: Any) -> float:  # pylint: disable=invalid-name
	if isinstance(var, float):
		return var

	try:
		return float(var)
	except Exception as err:  # pylint: disable=broad-except
		raise ValueError(f"Bad float value '{var}': {err}") from err


def forceDict(var: Any) -> dict:  # pylint: disable=invalid-name
	if var is None:
		return {}
	if isinstance(var, dict):
		return var
	raise ValueError(f"Not a dict '{var}'")


def forceTime(var: Any) -> Union[time.struct_time, datetime.datetime]:  # pylint: disable=invalid-name
	"""
	Convert `var` to a time.struct_time.

	If no conversion is possible a `ValueError` will be raised.
	"""
	if isinstance(var, time.struct_time):
		return var
	if isinstance(var, datetime.datetime):
		var = time.mktime(var.timetuple()) + var.microsecond / 1e6

	if isinstance(var, (int, float)):
		return time.localtime(var)

	raise ValueError(f"Not a time {var}")


def forceHardwareVendorId(var: Any) -> str:  # pylint: disable=invalid-name
	var = forceUnicodeUpper(var)
	if not re.search(_HARDWARE_ID_REGEX, var):
		raise ValueError(f"Bad hardware vendor id '{var}'")
	return var


def forceHardwareDeviceId(var: Any) -> str:  # pylint: disable=invalid-name
	var = forceUnicodeUpper(var)
	if not re.search(_HARDWARE_ID_REGEX, var):
		raise ValueError(f"Bad hardware device id '{var}'")
	return var


def forceOpsiTimestamp(var: Any) -> str:  # pylint: disable=invalid-name
	"""
	Make `var` an opsi-compatible timestamp.

	This is a string with the format "YYYY-MM-DD HH:MM:SS".

	If a conversion is not possible a `ValueError` will be raised.
	"""
	if not var:
		return "0000-00-00 00:00:00"
	if isinstance(var, datetime.datetime):
		return forceUnicode(var.strftime("%Y-%m-%d %H:%M:%S"))

	var = forceUnicode(var)
	match = re.search(_OPSI_TIMESTAMP_REGEX, var)
	if not match:
		match = re.search(_OPSI_DATE_REGEX, var)
		if not match:
			raise ValueError(f"Bad opsi timestamp: {var}")
		return f"{match.group(1)}-{match.group(2)}-{match.group(3)} 00:00:00"
	return f"{match.group(1)}-{match.group(2)}-{match.group(3)}" f" {match.group(4)}:{match.group(5)}:{match.group(6)}"


def forceFqdn(var: Any) -> str:  # pylint: disable=invalid-name
	var = forceObjectId(var)
	if not _FQDN_REGEX.search(var):
		raise ValueError(f"Bad fqdn: '{var}'")
	if var.endswith("."):
		var = var[:-1]
	return var


forceHostId = forceFqdn


def forceHostIdList(var: Any) -> list[str]:  # pylint: disable=invalid-name
	return [forceHostId(element) for element in forceList(var)]


def forceHardwareAddress(var: Any) -> str:  # pylint: disable=invalid-name
	var = forceUnicodeLower(var)
	if not var:
		return var

	match = re.search(_HARDWARE_ADDRESS_REGEX, var)
	if not match:
		raise ValueError(f"Invalid hardware address: {var}")

	return (f"{match.group(1)}:{match.group(2)}:{match.group(3)}:" f"{match.group(4)}:{match.group(5)}:{match.group(6)}").lower()


def forceIPAddress(var: Any) -> str:  # pylint: disable=invalid-name
	if not isinstance(var, (ipaddress.IPv4Address, ipaddress.IPv6Address, str)):
		raise ValueError(f"Invalid ip address: '{var}'")
	var = ipaddress.ip_address(var)
	if isinstance(var, ipaddress.IPv6Address) and var.ipv4_mapped:
		return var.ipv4_mapped.compressed
	return var.compressed


forceIpAddress = forceIPAddress


def forceHostAddress(var: Any) -> str:  # pylint: disable=invalid-name
	var = forceUnicodeLower(var)
	try:
		try:
			try:
				var = forceIpAddress(var)
			except Exception:  # pylint: disable=broad-except
				var = forceFqdn(var)
		except Exception:  # pylint: disable=broad-except
			var = forceHostname(var)
	except Exception as err:  # pylint: disable=broad-except
		raise ValueError(f"Invalid host address: '{var}'") from err
	return var


def forceNetmask(var: Any) -> str:  # pylint: disable=invalid-name
	var = forceUnicodeLower(var)
	if not re.search(_NETMASK_REGEX, var):
		raise ValueError(f"Invalid netmask: '{var}'")
	return var


def forceNetworkAddress(var: Any) -> str:  # pylint: disable=invalid-name
	if not isinstance(var, (ipaddress.IPv4Network, ipaddress.IPv6Network, str)):
		raise ValueError(f"Invalid network address: '{var}'")
	return ipaddress.ip_network(var).compressed


def forceUrl(var: Any) -> str:  # pylint: disable=invalid-name
	"""
	Forces ``var`` to be an valid URL.

	:rtype: str
	"""
	var = forceUnicode(var)
	if not _URL_REGEX.search(var):
		raise ValueError(f"Bad url: '{var}'")
	return var


def forceOpsiHostKey(var: Any) -> str:  # pylint: disable=invalid-name
	var = forceUnicodeLower(var)
	if not re.search(_OPSI_HOST_KEY_REGEX, var):
		raise ValueError(f"Bad opsi host key: {var}")
	return var


def forceProductVersion(var: Any) -> str:  # pylint: disable=invalid-name
	var = forceUnicode(var)
	if not _PRODUCT_VERSION_REGEX.search(var):
		raise ValueError(f"Bad product version: '{var}'")
	return var


def forceProductVersionList(var: Any) -> list[str]:  # pylint: disable=invalid-name
	return [forceProductVersion(element) for element in forceList(var)]


def forcePackageVersion(var: Any) -> str:  # pylint: disable=invalid-name
	var = forceUnicode(var)
	if not _PACKAGE_VERSION_REGEX.search(var):
		raise ValueError(f"Bad package version: '{var}'")
	return var


def forcePackageVersionList(var: Any) -> list[str]:  # pylint: disable=invalid-name
	return [forcePackageVersion(element) for element in forceList(var)]


def forceProductId(var: Any) -> str:  # pylint: disable=invalid-name
	var = forceObjectId(var)
	if not _PRODUCT_ID_REGEX.search(var):
		raise ValueError(f"Bad product id: '{var}'")
	return var


def forceProductIdList(var: Any) -> list[str]:  # pylint: disable=invalid-name
	return [forceProductId(element) for element in forceList(var)]


def forcePackageCustomName(var: Any) -> str:  # pylint: disable=invalid-name
	var = forceUnicodeLower(var)
	if not _PACKAGE_CUSTOM_NAME_REGEX.search(var):
		raise ValueError(f"Bad package custom name: '{var}'")
	return var


def forceProductType(var: Any) -> str:  # pylint: disable=invalid-name
	lower_var = forceUnicodeLower(var)
	if lower_var in ("localboot", "localbootproduct"):
		return "LocalbootProduct"
	if lower_var in ("netboot", "netbootproduct"):
		return "NetbootProduct"
	raise ValueError(f"Unknown product type: '{var}'")


def forceProductPropertyId(var: Any) -> str:  # pylint: disable=invalid-name
	var = forceUnicodeLower(var)
	if not _PRODUCT_PROPERTY_ID_REGEX.search(var):
		raise ValueError(f"Bad product property id: '{var}'")
	return var


def forceConfigId(var: Any) -> str:  # pylint: disable=invalid-name
	var = forceUnicodeLower(var)
	if not _CONFIG_ID_REGEX.search(var):
		raise ValueError(f"Bad config id: '{var}'")
	return var


def forceProductPropertyType(var: Any) -> str:  # pylint: disable=invalid-name
	value = forceUnicodeLower(var)
	if value in ("unicode", "unicodeproductproperty"):
		return "UnicodeProductProperty"
	if value in ("bool", "boolproductproperty"):
		return "BoolProductProperty"
	raise ValueError(f"Unknown product property type: '{var}'")


def forceProductPriority(var: Any) -> int:  # pylint: disable=invalid-name
	var = forceInt(var)
	if var < -100:
		return -100
	if var > 100:
		return 100
	return var


def forceFilename(var: Any) -> str:  # pylint: disable=invalid-name
	return forceUnicode(var)


def forceProductTargetConfiguration(var: Any) -> str:  # pylint: disable=invalid-name
	var = forceUnicodeLower(var)
	if var and var not in ("installed", "always", "forbidden", "undefined"):
		raise ValueError(f"Bad product target configuration: '{var}'")
	return var


def forceInstallationStatus(var: Any) -> str:  # pylint: disable=invalid-name
	var = forceUnicodeLower(var)
	if var and var not in ("installed", "not_installed", "unknown"):
		raise ValueError(f"Bad installation status: '{var}'")
	return var


def forceActionRequest(var: Any) -> str:  # pylint: disable=invalid-name
	var = forceUnicodeLower(var)
	if var:
		if var == "undefined":
			var = None
		elif var not in ("setup", "uninstall", "update", "always", "once", "custom", "none"):
			raise ValueError(f"Bad action request: '{var}'")
	return var


def forceActionRequestList(var: Any) -> list[str]:  # pylint: disable=invalid-name
	return [forceActionRequest(element) for element in forceList(var)]


def forceActionProgress(var: Any) -> str:  # pylint: disable=invalid-name
	return forceUnicode(var)


def forceActionResult(var: Any) -> Optional[str]:  # pylint: disable=invalid-name
	var = forceUnicodeLower(var)
	if not var:
		return None
	if var not in ("failed", "successful", "none"):
		raise ValueError(f"Bad action result: '{var}'")
	return var


def forceRequirementType(var: Any) -> Optional[str]:  # pylint: disable=invalid-name
	var = forceUnicodeLower(var)
	if not var:
		return None
	if var not in ("before", "after"):
		raise ValueError(f"Bad requirement type: '{var}'")
	return var


def forceObjectClass(var: Any, objectClass: Type[BaseObjectT]) -> BaseObjectT:  # pylint: disable=invalid-name
	global get_object_type  # pylint: disable=invalid-name, global-statement
	global from_json  # pylint: disable=invalid-name, global-statement

	if isinstance(var, objectClass):
		return var

	if isinstance(var, str) and var.startswith("{"):
		if not from_json:
			from opsicommon.utils import (  # pylint: disable=import-outside-toplevel,redefined-outer-name
				from_json,
			)

		try:
			return from_json(var)  # type: ignore[misc]
		except Exception as err:  # pylint: disable=broad-except
			raise ValueError(f"{var!r} is not a {objectClass}: {err}") from err

	if isinstance(var, dict):
		if not get_object_type:
			from opsicommon.objects import (  # pylint: disable=import-outside-toplevel,redefined-outer-name
				get_object_type,
			)
		try:
			_class = objectClass
			if "type" in var:
				try:
					_class = get_object_type(var["type"])  # type: ignore[misc]
				except KeyError as err:  # pylint: disable=broad-except
					raise ValueError(f"Invalid object type: {var['type']}") from err
				if not issubclass(_class, objectClass):
					raise ValueError(type(_class))
			return _class.fromHash(var)
		except Exception as err:  # pylint: disable=broad-except
			raise ValueError(f"{var!r} is not a {objectClass}: {err}") from err

	raise ValueError(f"{var!r} is not a {objectClass}")


def forceObjectClassList(var: Any, objectClass: Type[BaseObjectT]) -> list[BaseObjectT]:  # pylint: disable=invalid-name
	return [forceObjectClass(element, objectClass) for element in forceList(var)]


def forceGroupId(var: Any) -> str:  # pylint: disable=invalid-name
	var = forceObjectId(var)
	if not _GROUP_ID_REGEX.search(var):
		raise ValueError(f"Bad group id: '{var}'")
	return var


def forceGroupType(var: Any) -> str:  # pylint: disable=invalid-name
	lower_value = forceUnicodeLower(var)

	if lower_value == "hostgroup":
		return "HostGroup"
	if lower_value == "productgroup":
		return "ProductGroup"
	raise ValueError(f"Unknown group type: '{var}'")


def forceGroupTypeList(var: Any) -> list[str]:  # pylint: disable=invalid-name
	return [forceGroupType(element) for element in forceList(var)]


def forceGroupIdList(var: Any) -> list[str]:  # pylint: disable=invalid-name
	return [forceGroupId(element) for element in forceList(var)]


def forceObjectId(var: Any) -> str:  # pylint: disable=invalid-name
	var = forceUnicodeLower(var).strip()
	if not _OBJECT_ID_REGEX.search(var):
		raise ValueError(f"Bad object id: '{var}'")
	return var


def forceObjectIdList(var: Any) -> list[str]:  # pylint: disable=invalid-name
	return [forceObjectId(element) for element in forceList(var)]


def forceEmailAddress(var: Any) -> str:  # pylint: disable=invalid-name
	var = forceUnicodeLower(var)
	if not _EMAIL_REGEX.search(var):
		raise ValueError(f"Bad email address: '{var}'")
	return var


def forceDomain(var: Any) -> str:  # pylint: disable=invalid-name
	var = forceUnicodeLower(var)
	if not _DOMAIN_REGEX.search(var):
		raise ValueError(f"Bad domain: '{var}'")
	return var


def forceHostname(var: Any) -> str:  # pylint: disable=invalid-name
	var = forceUnicodeLower(var)
	if not _HOSTNAME_REGEX.search(var):
		raise ValueError(f"Bad hostname: '{var}'")
	return var


def forceLicenseContractId(var: Any) -> str:  # pylint: disable=invalid-name
	var = forceUnicodeLower(var)
	if not _LICENSE_CONTRACT_ID_REGEX.search(var):
		raise ValueError(f"Bad license contract id: '{var}'")
	return var


def forceLicenseContractIdList(var: Any) -> list[str]:  # pylint: disable=invalid-name
	return [forceLicenseContractId(element) for element in forceList(var)]


def forceSoftwareLicenseId(var: Any) -> str:  # pylint: disable=invalid-name
	var = forceUnicodeLower(var)
	if not _SOFTWARE_LICENSE_ID_REGEX.search(var):
		raise ValueError(f"Bad software license id: '{var}'")
	return var


def forceSoftwareLicenseIdList(var: Any) -> list[str]:  # pylint: disable=invalid-name
	return [forceSoftwareLicenseId(element) for element in forceList(var)]


def forceLicensePoolId(var: Any) -> str:  # pylint: disable=invalid-name
	var = forceUnicodeLower(var)
	if not _LICENSE_POOL_ID_REGEX.search(var):
		raise ValueError(f"Bad license pool id: '{var}'")
	return var


def forceLicensePoolIdList(var: Any) -> list[str]:  # pylint: disable=invalid-name
	return [forceLicensePoolId(element) for element in forceList(var)]


def forceAuditState(var: Any) -> int:  # pylint: disable=invalid-name
	var = forceInt(var)
	if var not in (0, 1):
		raise ValueError(f"Bad audit state value: {var}")
	return var


def forceLanguageCode(var: Any) -> str:  # pylint: disable=invalid-name
	var = forceUnicodeLower(var)
	match = _LANGUAGE_CODE_REGEX.search(var)
	if not match:
		raise ValueError(f"Bad language code: '{var}'")
	var = match.group(1)
	if match.group(2):
		var = f"{var}-{match.group(2).capitalize()}"
	if match.group(3):
		var = f"{var}-{match.group(3).upper()}"
	return var


def forceLanguageCodeList(var: Any) -> list[str]:  # pylint: disable=invalid-name
	return [forceLanguageCode(element) for element in forceList(var)]


def forceArchitecture(var: Any) -> str:  # pylint: disable=invalid-name
	var = forceUnicodeLower(var)
	if not _ARCHITECTURE_REGEX.search(var):
		raise ValueError(f"Bad architecture: '{var}'")
	return var


def forceArchitectureList(var: Any) -> list[str]:  # pylint: disable=invalid-name
	return [forceArchitecture(element) for element in forceList(var)]


def forceUniqueList(_list: list[Any]) -> list[Any]:  # pylint: disable=invalid-name
	# Keep list order!
	return sorted(set(_list), key=_list.index)


def args(*vars: Any, **typeVars: Any) -> Callable:  # pylint: disable=redefined-builtin
	"""Function to populate an object with passed on keyword args.
	This is intended to be used as a decorator.
	Classes using this decorator must explicitly inherit from object or a subclass of object.

	.. code-block:: python

		@args()			#works
		class Foo(object):
			pass

		@args()			#works
		class Bar(Foo):
			pass

		@args()			#does not work
		class Foo():
			pass

		@args()			#does not work
		class Foo:
			pass
	"""
	vars_list = list(vars)

	def wrapper(cls: Type) -> Any:
		def new(typ: Type, *args: Any, **kwargs: Any) -> Any:  # pylint: disable=redefined-builtin,redefined-outer-name
			if getattr(cls, "__base__", None) in (object, None):
				obj = object.__new__(typ)  # Suppress deprecation warning
			else:
				obj = cls.__base__.__new__(typ, *args, **kwargs)

			vars_list.extend(list(typeVars.keys()))
			kwargs_cpy = kwargs.copy()

			for var in vars_list:
				var_name = var.lstrip("_")
				if var_name in kwargs_cpy:
					if var in typeVars:
						func = typeVars[var]
						kwargs_cpy[var] = func(kwargs_cpy[var_name])
					else:
						kwargs_cpy[var] = kwargs_cpy[var_name]
				else:
					kwargs_cpy[var] = None

			for key, value in kwargs_cpy.items():
				if getattr(obj, key, None) is None:
					setattr(obj, key, value)

			return obj

		cls.__new__ = staticmethod(new)  # type: ignore[assignment]
		return cls

	return wrapper
