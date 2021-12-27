# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
Type forcing features.

This module contains various methods to ensure force a special type
on an object.
"""

import datetime
import ipaddress
import os
import re
import sys
import time
import types

from opsicommon.logging import logger

if os.name != 'nt':
	WindowsError = RuntimeError

__all__ = (
	'args', 'forceActionProgress', 'forceActionRequest',
	'forceActionRequestList', 'forceActionResult', 'forceArchitecture',
	'forceArchitectureList', 'forceAuditState', 'forceBool', 'forceBoolList',
	'forceConfigId', 'forceDict', 'forceDictList', 'forceDomain',
	'forceEmailAddress', 'forceFilename', 'forceFloat', 'forceFqdn',
	'forceGroupId', 'forceGroupIdList', 'forceGroupType', 'forceGroupTypeList',
	'forceHardwareAddress', 'forceHardwareDeviceId', 'forceHardwareVendorId',
	'forceHostAddress', 'forceHostId', 'forceHostIdList', 'forceHostname',
	'forceIPAddress', 'forceInstallationStatus', 'forceInt', 'forceIntList',
	'forceIpAddress', 'forceLanguageCode', 'forceLanguageCodeList',
	'forceLicenseContractId', 'forceLicenseContractIdList', 'forceLicensePoolId',
	'forceLicensePoolIdList', 'forceList', 'forceNetmask',
	'forceNetworkAddress', 'forceObjectClass', 'forceObjectClassList',
	'forceObjectId', 'forceObjectIdList', 'forceOct', 'forceOpsiHostKey',
	'forceOpsiTimestamp', 'forcePackageCustomName', 'forcePackageVersion',
	'forcePackageVersionList', 'forceProductId', 'forceProductIdList',
	'forceProductPriority', 'forceProductPropertyId',
	'forceProductPropertyType', 'forceProductTargetConfiguration',
	'forceProductType', 'forceProductVersion', 'forceProductVersionList',
	'forceRequirementType', 'forceSoftwareLicenseId',
	'forceSoftwareLicenseIdList', 'forceTime', 'forceUnicode',
	'forceUnicodeList', 'forceUnicodeLower', 'forceUnicodeLowerList',
	'forceUnicodeUpper', 'forceUniqueList', 'forceUnsignedInt', 'forceUrl'
)

encoding = sys.getfilesystemencoding()

_HARDWARE_ID_REGEX = re.compile(r'^[a-fA-F0-9]{4}$')
_OPSI_TIMESTAMP_REGEX = re.compile(r'^(\d{4})-?(\d{2})-?(\d{2})\s?(\d{2}):?(\d{2}):?(\d{2})\.?\d*$')
_OPSI_DATE_REGEX = re.compile(r'^(\d{4})-?(\d{2})-?(\d{2})$')
_FQDN_REGEX = re.compile(r'^[a-z0-9][a-z0-9\-]{,63}\.((\w+\-+)|(\w+\.))*\w{1,63}\.\w{2,16}\.?$')
_HARDWARE_ADDRESS_REGEX = re.compile(r'^([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})$')  # pylint: disable=line-too-long
_NETMASK_REGEX = re.compile(r'^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')  # pylint: disable=line-too-long
_URL_REGEX = re.compile(r'^[a-z0-9]+:\/\/[/a-zA-Z0-9@:%._\+~#?&=\[\]]+')
_OPSI_HOST_KEY_REGEX = re.compile(r'^[0-9a-f]{32}$')
_PRODUCT_VERSION_REGEX = re.compile(r'^[a-zA-Z0-9.]{1,32}$')
_PACKAGE_VERSION_REGEX = re.compile(r'^[a-zA-Z0-9.]{1,16}$')
_PRODUCT_ID_REGEX = re.compile(r'^[a-z0-9-_\.]{1,128}$')
_PACKAGE_CUSTOM_NAME_REGEX = re.compile(r'^[a-zA-Z0-9]+$')
_PRODUCT_PROPERTY_ID_REGEX = re.compile(r'^\S+$')
_CONFIG_ID_REGEX = re.compile(r'^\S+$')
_GROUP_ID_REGEX = re.compile(r'^[a-z0-9][a-z0-9-_. ]*$')
_OBJECT_ID_REGEX = re.compile(r'^[a-z0-9][a-z0-9-_. ]*$')
_EMAIL_REGEX = re.compile(r'^(([A-Za-z0-9]+_+)|([A-Za-z0-9]+\-+)|([A-Za-z0-9]+\.+)|([A-Za-z0-9]+\++))*[A-Za-z0-9]+@((\w+\-+)|(\w+\.))*\w*')
_DOMAIN_REGEX = re.compile(r'^((\w+\-+)|(\w+\.))*\w{1,63}\.\w{2,16}\.?$')
_HOSTNAME_REGEX = re.compile(r'^[a-z0-9][a-z0-9\-]*$')
_LICENSE_CONTRACT_ID_REGEX = re.compile(r'^[a-z0-9][a-z0-9-_. :]*$')
_SOFTWARE_LICENSE_ID_REGEX = re.compile(r'^[a-z0-9][a-z0-9-_. :]*$')
_LICENSE_POOL_ID_REGEX = re.compile(r'^[a-z0-9][a-z0-9-_. :]*$')
_LANGUAGE_CODE_REGEX = re.compile(r'^([a-z]{2,3})[-_]?([a-z]{4})?[-_]?([a-z]{2})?$')
_ARCHITECTURE_REGEX = re.compile(r'^(x86|x64)$')


def forceList(var):
	if not isinstance(var, (set, list, tuple, types.GeneratorType)):
		return [var]

	return list(var)


def forceUnicode(var):  # pylint: disable=too-many-return-statements
	if isinstance(var, str):
		return var
	if os.name == 'nt' and isinstance(var, WindowsError):
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
		var = var.__repr__()
		if isinstance(var, str):
			return var
		return str(var, 'utf-8', 'replace')
	except Exception:  # pylint: disable=broad-except
		pass

	return str(var)


def forceUnicodeLower(var):
	return forceUnicode(var).lower()


def forceUnicodeUpper(var):
	return forceUnicode(var).upper()


def forceUnicodeList(var):
	return [forceUnicode(element) for element in forceList(var)]


def forceDictList(var):
	return [forceDict(element) for element in forceList(var)]


def forceUnicodeLowerList(var):
	return [forceUnicodeLower(element) for element in forceList(var)]


def forceBool(var):
	if isinstance(var, bool):
		return var
	if isinstance(var, str):
		if len(var) <= 5:  # longest word is 5 characters ("false")
			lowValue = var.lower()
			if lowValue in ('true', 'yes', 'on', '1'):
				return True
			if lowValue in ('false', 'no', 'off', '0'):
				return False

	return bool(var)


def forceBoolList(var):
	return [forceBool(element) for element in forceList(var)]


def forceInt(var):
	if isinstance(var, int):
		return var
	try:
		return int(var)
	except Exception as err:
		raise ValueError(f"Bad int value '{var}': {err}") from err


def forceIntList(var):
	return [forceInt(element) for element in forceList(var)]


def forceUnsignedInt(var):
	var = forceInt(var)
	if var < 0:
		var = -1 * var
	return var


def forceOct(var):
	if isinstance(var, int):
		return var

	try:
		octValue = ''
		for idx, val in enumerate(forceUnicode(var)):
			val = forceInt(val)
			if val > 7:
				raise ValueError(f"{val} is too big")
			if idx == 0 and val != '0':
				octValue += '0'
			octValue += str(val)

		octValue = int(octValue, 8)
		return octValue
	except Exception as err:  # pylint: disable=broad-except
		raise ValueError(f"Bad oct value {var}: {err}") from err


def forceFloat(var):
	if isinstance(var, float):
		return var

	try:
		return float(var)
	except Exception as err:  # pylint: disable=broad-except
		raise ValueError(f"Bad float value '{var}': {err}") from err


def forceDict(var):
	if var is None:
		return {}
	if isinstance(var, dict):
		return var
	raise ValueError(f"Not a dict '{var}'")


def forceTime(var):
	"""
	Convert `var` to a time.struct_time.

	If no conversion is possible a `ValueError` will be raised.
	"""
	if isinstance(var, time.struct_time):
		return var
	if isinstance(var, datetime.datetime):
		var = time.mktime(var.timetuple()) + var.microsecond / 1E6

	if isinstance(var, (int, float)):
		return time.localtime(var)

	raise ValueError(f"Not a time {var}")


def forceHardwareVendorId(var):
	var = forceUnicodeUpper(var)
	if not re.search(_HARDWARE_ID_REGEX, var):
		raise ValueError(f"Bad hardware vendor id '{var}'")
	return var


def forceHardwareDeviceId(var):
	var = forceUnicodeUpper(var)
	if not re.search(_HARDWARE_ID_REGEX, var):
		raise ValueError(f"Bad hardware device id '{var}'")
	return var


def forceOpsiTimestamp(var):
	"""
	Make `var` an opsi-compatible timestamp.

	This is a string with the format "YYYY-MM-DD HH:MM:SS".

	If a conversion is not possible a `ValueError` will be raised.
	"""
	if not var:
		return '0000-00-00 00:00:00'
	if isinstance(var, datetime.datetime):
		return forceUnicode(var.strftime('%Y-%m-%d %H:%M:%S'))

	var = forceUnicode(var)
	match = re.search(_OPSI_TIMESTAMP_REGEX, var)
	if not match:
		match = re.search(_OPSI_DATE_REGEX, var)
		if not match:
			raise ValueError(f"Bad opsi timestamp: {var}")
		return f"{match.group(1)}-{match.group(2)}-{match.group(3)} 00:00:00"
	return (
		f"{match.group(1)}-{match.group(2)}-{match.group(3)}"
		f" {match.group(4)}:{match.group(5)}:{match.group(6)}"
	)


def forceFqdn(var):
	var = forceObjectId(var)
	if not _FQDN_REGEX.search(var):
		raise ValueError(f"Bad fqdn: '{var}'")
	if var.endswith('.'):
		var = var[:-1]
	return var

forceHostId = forceFqdn


def forceHostIdList(var):
	return [forceHostId(element) for element in forceList(var)]


def forceHardwareAddress(var):
	var = forceUnicodeLower(var)
	if not var:
		return var

	match = re.search(_HARDWARE_ADDRESS_REGEX, var)
	if not match:
		raise ValueError(f"Invalid hardware address: {var}")

	return (
		f"{match.group(1)}:{match.group(2)}:{match.group(3)}:"
		f"{match.group(4)}:{match.group(5)}:{match.group(6)}"
	).lower()

def forceIPAddress(var):
	if not isinstance(var, (ipaddress.IPv4Address, ipaddress.IPv6Address, str)):
		raise ValueError(f"Invalid ip address: '{var}'")
	var = ipaddress.ip_address(var)
	if isinstance(var, ipaddress.IPv6Address) and var.ipv4_mapped:
		return var.ipv4_mapped.compressed
	return var.compressed

forceIpAddress = forceIPAddress


def forceHostAddress(var):
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


def forceNetmask(var):
	var = forceUnicodeLower(var)
	if not re.search(_NETMASK_REGEX, var):
		raise ValueError(f"Invalid netmask: '{var}'")
	return var


def forceNetworkAddress(var):
	if not isinstance(var, (ipaddress.IPv4Network, ipaddress.IPv6Network, str)):
		raise ValueError(f"Invalid network address: '{var}'")
	return ipaddress.ip_network(var).compressed


def forceUrl(var):
	"""
	Forces ``var`` to be an valid URL.

	:rtype: str
	"""
	var = forceUnicode(var)
	if not _URL_REGEX.search(var):
		raise ValueError(f"Bad url: '{var}'")
	return var


def forceOpsiHostKey(var):
	var = forceUnicodeLower(var)
	if not re.search(_OPSI_HOST_KEY_REGEX, var):
		raise ValueError(f"Bad opsi host key: {var}")
	return var


def forceProductVersion(var):
	var = forceUnicode(var)
	if not _PRODUCT_VERSION_REGEX.search(var):
		raise ValueError(f"Bad product version: '{var}'")
	return var


def forceProductVersionList(var):
	return [forceProductVersion(element) for element in forceList(var)]


def forcePackageVersion(var):
	var = forceUnicode(var)
	if not _PACKAGE_VERSION_REGEX.search(var):
		raise ValueError(f"Bad package version: '{var}'")
	return var


def forcePackageVersionList(var):
	return [forcePackageVersion(element) for element in forceList(var)]


def forceProductId(var):
	var = forceObjectId(var)
	if not _PRODUCT_ID_REGEX.search(var):
		raise ValueError(f"Bad product id: '{var}'")
	return var


def forceProductIdList(var):
	return [forceProductId(element) for element in forceList(var)]


def forcePackageCustomName(var):
	var = forceUnicodeLower(var)
	if not _PACKAGE_CUSTOM_NAME_REGEX.search(var):
		raise ValueError(f"Bad package custom name: '{var}'")
	return var


def forceProductType(var):
	lowercaseVar = forceUnicodeLower(var)
	if lowercaseVar in ('localboot', 'localbootproduct'):
		return 'LocalbootProduct'
	if lowercaseVar in ('netboot', 'netbootproduct'):
		return 'NetbootProduct'
	raise ValueError(f"Unknown product type: '{var}'")


def forceProductPropertyId(var):
	var = forceUnicodeLower(var)
	if not _PRODUCT_PROPERTY_ID_REGEX.search(var):
		raise ValueError(f"Bad product property id: '{var}'")
	return var


def forceConfigId(var):
	var = forceUnicodeLower(var)
	if not _CONFIG_ID_REGEX.search(var):
		raise ValueError(f"Bad config id: '{var}'")
	return var


def forceProductPropertyType(var):
	value = forceUnicodeLower(var)
	if value in ('unicode', 'unicodeproductproperty'):
		return 'UnicodeProductProperty'
	if value in ('bool', 'boolproductproperty'):
		return 'BoolProductProperty'
	raise ValueError(f"Unknown product property type: '{var}'")


def forceProductPriority(var):
	var = forceInt(var)
	if var < -100:
		return -100
	if var > 100:
		return 100
	return var


def forceFilename(var):
	return forceUnicode(var)


def forceProductTargetConfiguration(var):
	var = forceUnicodeLower(var)
	if var and var not in ('installed', 'always', 'forbidden', 'undefined'):
		raise ValueError(f"Bad product target configuration: '{var}'")
	return var


def forceInstallationStatus(var):
	var = forceUnicodeLower(var)
	if var and var not in ('installed', 'not_installed', 'unknown'):
		raise ValueError(f"Bad installation status: '{var}'")
	return var


def forceActionRequest(var):
	var = forceUnicodeLower(var)
	if var:
		if var == 'undefined':
			var = None
		elif var not in ('setup', 'uninstall', 'update', 'always', 'once', 'custom', 'none'):
			raise ValueError(f"Bad action request: '{var}'")
	return var


def forceActionRequestList(var):
	return [forceActionRequest(element) for element in forceList(var)]


def forceActionProgress(var):
	return forceUnicode(var)


def forceActionResult(var):
	var = forceUnicodeLower(var)
	if var and var not in ('failed', 'successful', 'none'):
		raise ValueError(f"Bad action result: '{var}'")
	return var


def forceRequirementType(var):
	var = forceUnicodeLower(var)
	if not var:
		return None
	if var not in ('before', 'after'):
		raise ValueError(f"Bad requirement type: '{var}'")
	return var


def forceObjectClass(var, objectClass):
	if isinstance(var, objectClass):
		return var

	exception = None
	if isinstance(var, str) and var.lstrip().startswith('{'):
		from OPSI.Util import from_json  # pylint: disable=import-outside-toplevel
		try:
			var = from_json(var)
		except Exception as err:  # pylint: disable=broad-except
			exception = err
			logger.debug("Failed to get object from json %s: %s", var, err)

	if isinstance(var, dict):
		if 'type' not in var:
			raise ValueError(f"Key 'type' missing in hash {var}")

		import OPSI.Object  # pylint: disable=import-outside-toplevel,unused-import
		try:
			_class = eval('OPSI.Object.%s' % var['type'])  # pylint: disable=eval-used
			if issubclass(_class, objectClass):
				var = _class.fromHash(var)
		except AttributeError as err:
			if "module 'OPSI.Object' has no attribute" in str(err):
				err = ValueError(f"Invalild object type: {var['type']}")

			exception = err
			logger.debug("Failed to get object from dict %s: %s", var, err)
		except Exception as err:  # pylint: disable=broad-except
			exception = err
			logger.debug("Failed to get object from dict %s: %s", var, err)

	if not isinstance(var, objectClass):
		if exception is None:
			raise ValueError(f"'{var}' is not a {objectClass}")
		raise ValueError(f"'{var}' is not a {objectClass}: {exception}")

	return var


def forceObjectClassList(var, objectClass):
	return [forceObjectClass(element, objectClass) for element in forceList(var)]


def forceGroupId(var):
	var = forceObjectId(var)
	if not _GROUP_ID_REGEX.search(var):
		raise ValueError(f"Bad group id: '{var}'")
	return var


def forceGroupType(var):
	lowercaseValue = forceUnicodeLower(var)

	if lowercaseValue == 'hostgroup':
		return 'HostGroup'
	if lowercaseValue == 'productgroup':
		return 'ProductGroup'
	raise ValueError(f"Unknown group type: '{var}'")


def forceGroupTypeList(var):
	return [forceGroupType(element) for element in forceList(var)]


def forceGroupIdList(var):
	return [forceGroupId(element) for element in forceList(var)]


def forceObjectId(var):
	var = forceUnicodeLower(var).strip()
	if not _OBJECT_ID_REGEX.search(var):
		raise ValueError(f"Bad object id: '{var}'")
	return var


def forceObjectIdList(var):
	return [forceObjectId(element) for element in forceList(var)]


def forceEmailAddress(var):
	var = forceUnicodeLower(var)
	if not _EMAIL_REGEX.search(var):
		raise ValueError(f"Bad email address: '{var}'")
	return var


def forceDomain(var):
	var = forceUnicodeLower(var)
	if not _DOMAIN_REGEX.search(var):
		raise ValueError(f"Bad domain: '{var}'")
	return var


def forceHostname(var):
	var = forceUnicodeLower(var)
	if not _HOSTNAME_REGEX.search(var):
		raise ValueError(f"Bad hostname: '{var}'")
	return var


def forceLicenseContractId(var):
	var = forceUnicodeLower(var)
	if not _LICENSE_CONTRACT_ID_REGEX.search(var):
		raise ValueError(f"Bad license contract id: '{var}'")
	return var


def forceLicenseContractIdList(var):
	return [forceLicenseContractId(element) for element in forceList(var)]


def forceSoftwareLicenseId(var):
	var = forceUnicodeLower(var)
	if not _SOFTWARE_LICENSE_ID_REGEX.search(var):
		raise ValueError(f"Bad software license id: '{var}'")
	return var


def forceSoftwareLicenseIdList(var):
	return [forceSoftwareLicenseId(element) for element in forceList(var)]


def forceLicensePoolId(var):
	var = forceUnicodeLower(var)
	if not _LICENSE_POOL_ID_REGEX.search(var):
		raise ValueError(f"Bad license pool id: '{var}'")
	return var


def forceLicensePoolIdList(var):
	return [forceLicensePoolId(element) for element in forceList(var)]


def forceAuditState(var):
	var = forceInt(var)
	if var not in (0, 1):
		raise ValueError(f"Bad audit state value: {var}")
	return var


def forceLanguageCode(var):
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


def forceLanguageCodeList(var):
	return [forceLanguageCode(element) for element in forceList(var)]


def forceArchitecture(var):
	var = forceUnicodeLower(var)
	if not _ARCHITECTURE_REGEX.search(var):
		raise ValueError(f"Bad architecture: '{var}'")
	return var


def forceArchitectureList(var):
	return [forceArchitecture(element) for element in forceList(var)]


def forceUniqueList(_list):
	cleanedList = []
	for entry in _list:
		if entry not in cleanedList:
			cleanedList.append(entry)
	return cleanedList


def args(*vars, **typeVars):  # pylint: disable=redefined-builtin
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
	vars = list(vars)

	def wrapper(cls):
		def new(typ, *args, **kwargs):  # pylint: disable=redefined-builtin,redefined-outer-name
			if getattr(cls, "__base__", None) in (object, None):
				obj = object.__new__(typ)  # Suppress deprecation warning
			else:
				obj = cls.__base__.__new__(typ, *args, **kwargs)

			vars.extend(list(typeVars.keys()))
			ka = kwargs.copy()

			for var in vars:
				varName = var.lstrip("_")
				if varName in ka:
					if var in typeVars:
						func = typeVars[var]
						ka[var] = func(ka[varName])
					else:
						ka[var] = ka[varName]
				else:
					ka[var] = None

			for key, value in ka.items():
				if getattr(obj, key, None) is None:
					setattr(obj, key, value)

			return obj

		cls.__new__ = staticmethod(new)
		return cls

	return wrapper
