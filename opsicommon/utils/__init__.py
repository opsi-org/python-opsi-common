# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
General utility functions.

This module holds various utility functions for the work with opsi.
This includes functions for (de)serialisation, converting classes from
or to JSON, working with librsync and more.
"""

import base64
import binascii
import codecs
import ipaddress
import json
import os
import random
import re
import shutil
import socket
import struct
import sys
import time
import types
import secrets
import subprocess
from collections import namedtuple
from hashlib import md5
from itertools import islice
from functools import lru_cache

import packaging.version as packver

try:
	# PyCryptodome from pypi installs into Crypto
	from Crypto.Cipher import Blowfish
	from Crypto.PublicKey import RSA
	from Crypto.Util.number import bytes_to_long
except (ImportError, OSError):
	# pyright: reportMissingImports=false
	# python3-pycryptodome installs into Cryptodome
	from Cryptodome.Cipher import Blowfish
	from Cryptodome.PublicKey import RSA
	from Cryptodome.Util.number import bytes_to_long

from opsicommon.logging import logger
from opsicommon.types import (
	forceBool, forceFilename, forceFqdn, forceUnicode,
	_PRODUCT_VERSION_REGEX, _PACKAGE_VERSION_REGEX
)

__all__ = (
	"BLOWFISH_IV", "RANDOM_DEVICE", "UNIT_REGEX",
	"CryptoError", "BlowfishError", "PickleString",
	"blowfishDecrypt", "blowfishEncrypt",
	"chunk", "compareVersions", "deserialize",
	"findFiles", "findFilesGenerator", "formatFileSize", "fromJson", "generateOpsiHostKey",
	"getfqdn", "ipAddressInNetwork", "isRegularExpressionPattern",
	"md5sum", "objectToBash", "objectToBeautifiedText", "objectToHtml",
	"randomString", "removeDirectory", "removeUnit",
	"replaceSpecialHTMLCharacters", "serialize", "timestamp", "toJson",
	"getPublicKey", "Singleton"
)

BLOWFISH_IV = b"OPSI1234"
RANDOM_DEVICE = "/dev/urandom"
UNIT_REGEX = re.compile(r'^(\d+\.*\d*)\s*(\w{0,4})$')
_ACCEPTED_CHARACTERS = (
	"abcdefghijklmnopqrstuvwxyz"
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"0123456789"
)

Version = namedtuple('Version', 'product package')


class CryptoError(ValueError):
	pass


class BlowfishError(CryptoError):
	pass


class PickleString(str):

	def __getstate__(self):
		return base64.standard_b64encode(self)

	def __setstate__(self, state):
		self = base64.standard_b64decode(state)  # pylint: disable=self-cls-assignment


def formatFileSize(sizeInBytes):
	if sizeInBytes < 1024:
		return f"{sizeInBytes:0.0f}"
	if sizeInBytes < 1048576:  # 1024**2
		return f"{sizeInBytes / 1024:0.0f}K"
	if sizeInBytes < 1073741824:  # 1024**3
		return f"{sizeInBytes / 1048576:0.0f}M"
	if sizeInBytes < 1099511627776:  # 1024**4
		return f"{sizeInBytes / 1073741824:0.0f}G"
	return f"{sizeInBytes / 1099511627776:0.0f}T"


OBJECT_CLASSES = None
BaseObject = None  # pylint: disable=invalid-name
def deserialize(obj, preventObjectCreation=False):
	"""
	Deserialization of `obj`.

	This function will deserialize objects from JSON into opsi compatible objects.
	In case `obj` is a list contained elements are deserialized.
	In case `obj` is a dict the values are deserialized.

	In case `obj` is a dict and holds a key *type* and `preventObjectCreation`
	is `True` it will be tried to create an opsi object instance from it

	:type obj: object
	:type preventObjectCreation: bool
	"""
	if isinstance(obj, list):
		return [deserialize(element, preventObjectCreation=preventObjectCreation) for element in obj]

	global OBJECT_CLASSES  # pylint: disable=global-statement,invalid-name,global-variable-not-assigned
	if OBJECT_CLASSES is None:
		from opsicommon.objects import OBJECT_CLASSES  # pylint: disable=redefined-outer-name,import-outside-toplevel
	global BaseObject  # pylint: disable=global-statement,invalid-name,global-variable-not-assigned
	if BaseObject is None:
		from opsicommon.objects import BaseObject  # pylint: disable=redefined-outer-name,import-outside-toplevel

	if isinstance(obj, dict):
		if (
			not preventObjectCreation and
			"type" in obj and
			obj["type"] in OBJECT_CLASSES and
			issubclass(OBJECT_CLASSES[obj['type']], BaseObject)
		):
			try:
				return OBJECT_CLASSES[obj['type']].fromHash(obj)
			except Exception as err:  # pylint: disable=broad-except
				logger.error(err, exc_info=True)
				raise ValueError(f"Failed to create object from dict {obj}: {err}") from err

		return {
			key: deserialize(value, preventObjectCreation=preventObjectCreation)
			for key, value in obj.items()
		}

	return obj


def serialize(obj):
	"""
	Serialize `obj`.

	It will turn an object into a JSON-compatible format -
	consisting of strings, dicts, lists or numbers.

	:return: a JSON-compatible serialisation of the input.
	"""
	if isinstance(obj, str):
		return obj

	try:
		return obj.serialize()
	except AttributeError:
		if isinstance(obj, (list, set, types.GeneratorType)):
			return [serialize(tempObject) for tempObject in obj]
		if isinstance(obj, dict):
			return {key: serialize(value) for key, value in obj.items()}

	return obj


def fromJson(obj, objectType=None, preventObjectCreation=False):
	if isinstance(obj, bytes):
		# Allow decoding errors (workaround for opsi-script bug)
		obj = obj.decode("utf-8", "replace")
	obj = json.loads(obj)
	if isinstance(obj, dict) and objectType:
		obj['type'] = objectType
	return deserialize(obj, preventObjectCreation=preventObjectCreation)


def toJson(obj, ensureAscii=False):
	return json.dumps(serialize(obj), ensure_ascii=ensureAscii)


def md5sum(filename):
	""" Returns the md5sum of the given file. """
	md5object = md5()

	with open(filename, 'rb') as fileToHash:
		for data in iter(lambda: fileToHash.read(524288), b''):
			md5object.update(data)

	return md5object.hexdigest()


def randomString(length, characters=_ACCEPTED_CHARACTERS):
	"""
	Generates a random string for a given length.

	:param characters: The characters to choose from. This defaults to 0-9a-Z.
	"""
	return ''.join(random.choice(characters) for _ in range(length))


def generateOpsiHostKey(forcePython=False):  # pylint: disable=unused-argument
	"""
	Generates an random opsi host key.

	On Python 3.5 or lower this will try to make use of an existing
	random device.
	As a fallback the generation is done in plain Python.

	:param forcePython: Force the usage of Python for host key generation.
	:rtype: str
	"""
	return secrets.token_hex(16)


def timestamp(secs=0, dateOnly=False):
	''' Returns a timestamp of the current system time format: YYYY-mm-dd[ HH:MM:SS] '''
	if not secs:
		secs = time.time()
	if dateOnly:
		return time.strftime("%Y-%m-%d", time.localtime(secs))
	return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(secs))


def objectToBeautifiedText(obj):
	return json.dumps(serialize(obj), indent=4, ensure_ascii=False)


def objectToBash(obj, bashVars=None, level=0):  # pylint: disable=too-many-branches
	"""
	Converts `obj` into bash-compatible format.

	:type bashVars: dict
	:type level: int
	:rtype: dict
	"""
	if bashVars is None:
		bashVars = {}

	if level == 0:
		obj = serialize(obj)
		varName = "RESULT"
		compress = True
	else:
		varName = f"RESULT{level}"
		compress = False

	try:
		obj = obj.serialize()
	except AttributeError:
		pass

	try:
		append = bashVars[varName].append
	except KeyError:
		emptyList = []
		bashVars[varName] = emptyList
		append = emptyList.append

	if isinstance(obj, (list, set)):
		append('(\n')
		for element in obj:
			if isinstance(element, (dict, list)):
				level += 1
				objectToBash(element, bashVars, level)
				append(f'RESULT{level}=${{RESULT{level}[*]}}')
			else:
				objectToBash(element, bashVars, level)
			append('\n')
		append(')')
	elif isinstance(obj, dict):
		append('(\n')
		for (key, value) in obj.items():
			append(f'{key}=')
			if isinstance(value, (dict, list)):
				level += 1
				objectToBash(value, bashVars, level)
				append(f'${{RESULT{level}[*]}}')
			else:
				objectToBash(value, bashVars, level)
			append('\n')
		append(')')
	elif obj is None:
		append('""')
	else:
		append(f'"{obj}"')

	if compress:
		for key, value in bashVars.items():
			bashVars[key] = ''.join(value)

	return bashVars


def objectToHtml(obj, level=0):  # pylint: disable=too-many-branches
	if level == 0:
		obj = serialize(obj)

	html = []
	append = html.append

	if isinstance(obj, (list, set)):
		append('[')
		if len(obj) > 0:
			append('<div style="padding-left: 3em;">')
			for i, currentElement in enumerate(obj):
				append(objectToHtml(currentElement, level + 1))
				if i < len(obj) - 1:
					append(',<br />\n')
			append('</div>')
		append(']')
	elif isinstance(obj, dict):
		append('{')
		if len(obj) > 0:
			append('<div style="padding-left: 3em;">')
			for i, (key, value) in enumerate(obj.items()):
				append('<font class="json_key">')
				append(objectToHtml(key))
				append('</font>: ')
				append(objectToHtml(value, level + 1))
				if i < len(obj) - 1:
					append(',<br />\n')
			append('</div>')
		append('}')
	elif isinstance(obj, bool):
		append(str(obj).lower())
	elif obj is None:
		append('null')
	else:
		if isinstance(obj, str):
			append(replaceSpecialHTMLCharacters(obj).join(('"', '"')))
		else:
			append(replaceSpecialHTMLCharacters(obj))

	return ''.join(html)


def replaceSpecialHTMLCharacters(text):
	return str(text) \
		.replace('\r', '')\
		.replace('\t', '   ')\
		.replace('&', '&amp;')\
		.replace('"', '&quot;')\
		.replace("'", '&apos;')\
		.replace(' ', '&nbsp;')\
		.replace('<', '&lt;')\
		.replace('>', '&gt;')\
		.replace('\n', '<br />\n')


def combineVersions(obj):
	"""
	Returns the combination of product and package version.

	:type obj: Product, ProductOnClient, ProductOnDepot
	:return: The version.
	:rtype: str
	"""
	return f"{obj.productVersion}-{obj.packageVersion}"


def compareVersions(v1, condition, v2):  # pylint: disable=invalid-name,too-many-locals
	"""
	Compare the versions `v1` and `v2` with the given `condition`.

	`condition` may be one of `==`, `<`, `<=`, `>`, `>=`.

	:raises ValueError: If invalid value for version or condition if given.
	:rtype: bool
	:return: If the comparison matches this will return True.
	"""
	# Kept removePartAfterWave to not break current behaviour
	def removePartAfterWave(versionString):
		if "~" in versionString:
			return versionString[:versionString.find("~")]
		return versionString

	first = removePartAfterWave(v1)
	second = removePartAfterWave(v2)
	for version in (first, second):
		parts = version.split("-")
		if (
			not _PRODUCT_VERSION_REGEX.search(parts[0]) or
			(len(parts) == 2 and not _PACKAGE_VERSION_REGEX.search(parts[1])) or
			len(parts) > 2
		):
			raise ValueError(f"Bad package version provided: '{version}'")

	try:
		#dont use packver.parse() here as it produces LegacyVersions if some letters are contained (else Versions)
		#in comparisson, LegacyVersion is always smaller than Version (Problem for 20.09 and 21.h1)
		first = packver.LegacyVersion(first)
		second = packver.LegacyVersion(second)
	except packver.InvalidVersion as version_error:
		raise ValueError("Invalid version provided to compareVersions") from version_error

	if condition in ("==", "=") or not condition:
		result = first == second
	elif condition == "<":
		result = first < second
	elif condition == "<=":
		result = first <= second
	elif condition == ">":
		result = first > second
	elif condition == ">=":
		result = first >= second
	else:
		raise ValueError(f"Bad condition {condition} provided to compareVersions")

	if result:
		logger.debug("Fulfilled condition: %s %s %s", v1, condition, v2)
	else:
		logger.debug("Unfulfilled condition: %s %s %s", v1, condition, v2)
	return result


def removeUnit(value: str) -> int:  # pylint: disable=invalid-name,too-many-return-statements
	'''
	Take a string representing a byte-based size and return the
	value in bytes.

	:param value: str
	:returns: `value` in bytes.
	:rtype: int or float
	'''
	value = str(value)
	match = UNIT_REGEX.search(value)
	if not match:
		return value

	if '.' in match.group(1):
		value = float(match.group(1))
	else:
		value = int(match.group(1))

	unit = match.group(2)
	mult = 1000

	if unit.lower().endswith('hz'):
		unit = unit[:-2]
	elif unit.lower().endswith('bits'):
		mult = 1024
		unit = unit[:-4]
	elif unit.lower().endswith('b'):
		mult = 1024
		unit = unit[:-1]
	elif unit.lower().endswith(('s', 'v')):
		unit = unit[:-1]

	if unit.endswith('n'):
		return float(value) / (mult * mult)
	if unit.endswith('m'):
		return float(value) / mult
	if unit.lower().endswith('k'):
		return value * mult
	if unit.endswith('M'):
		return value * mult * mult
	if unit.endswith('G'):
		return value * mult * mult * mult

	return value


def blowfishEncrypt(key, cleartext):
	"""
	Takes `cleartext` string, returns hex-encoded,
	blowfish-encrypted string.

	:type key: str
	:type cleartext: str
	:raises BlowfishError: In case things go wrong.
	:rtype: str
	"""
	if not key:
		raise BlowfishError("Missing key")

	key = _prepareBlowfishKey(key)
	cleartext = forceUnicode(cleartext)
	cleartext = cleartext.encode("utf-8")
	while len(cleartext) % 8 != 0:
		# Fill up with \0 until length is a mutiple of 8
		cleartext += b"\x00"

	blowfish = Blowfish.new(key, Blowfish.MODE_CBC, BLOWFISH_IV)
	try:
		crypt = blowfish.encrypt(cleartext)
	except Exception as err:
		logger.debug(err, exc_info=True)
		raise BlowfishError("Failed to encrypt") from err

	return crypt.hex()


def blowfishDecrypt(key, crypt):
	"""
	Takes hex-encoded, blowfish-encrypted string,
	returns cleartext string.

	:type key: str
	:param crypt: The encrypted text as hex.
	:type crypt: str
	:raises BlowfishError: In case things go wrong.
	:rtype: str
	"""
	if not key:
		raise BlowfishError("Missing key")

	key = _prepareBlowfishKey(key)
	crypt = bytes.fromhex(crypt)

	blowfish = Blowfish.new(key, Blowfish.MODE_CBC, BLOWFISH_IV)
	try:
		cleartext = blowfish.decrypt(crypt)
	except Exception as err:
		logger.debug(err, exc_info=True)
		raise BlowfishError("Failed to decrypt") from err

	# Remove possible \0-chars
	cleartext = cleartext.rstrip(b'\0')

	try:
		return cleartext.decode("utf-8")
	except Exception as err:
		logger.error(err)
		raise BlowfishError("Failed to convert decrypted text to unicode.") from err


def _prepareBlowfishKey(key: str) -> bytes:
	"Transform the key into hex."
	try:
		key = forceUnicode(key).encode()
		return codecs.decode(key, "hex")
	except (binascii.Error, Exception) as err:
		raise BlowfishError(f"Unable to prepare key: {err}") from err


def findFilesGenerator(  # pylint: disable=too-many-branches,too-many-locals,too-many-arguments,too-many-statements
	directory, prefix='',
	excludeDir=None, excludeFile=None, includeDir=None, includeFile=None,
	returnDirs=True, returnLinks=True, followLinks=False,
	repository=None
):
	directory = forceFilename(directory)
	prefix = forceUnicode(prefix)

	if excludeDir:
		if not isRegularExpressionPattern(excludeDir):
			excludeDir = re.compile(forceUnicode(excludeDir))
	else:
		excludeDir = None

	if excludeFile:
		if not isRegularExpressionPattern(excludeFile):
			excludeFile = re.compile(forceUnicode(excludeFile))
	else:
		excludeFile = None

	if includeDir:
		if not isRegularExpressionPattern(includeDir):
			includeDir = re.compile(forceUnicode(includeDir))
	else:
		includeDir = None

	if includeFile:
		if not isRegularExpressionPattern(includeFile):
			includeFile = re.compile(forceUnicode(includeFile))
	else:
		includeFile = None

	returnDirs = forceBool(returnDirs)
	returnLinks = forceBool(returnLinks)
	followLinks = forceBool(followLinks)

	if repository:
		islink = repository.islink
		isdir = repository.isdir
		listdir = repository.listdir
	else:
		islink = os.path.islink
		isdir = os.path.isdir
		listdir = os.listdir

	for entry in listdir(directory):
		pp = os.path.join(prefix, entry)
		dp = os.path.join(directory, entry)
		isLink = False
		if islink(dp):
			isLink = True
			if not returnLinks and not followLinks:
				continue
		if isdir(dp) and (not isLink or followLinks):
			if excludeDir and re.search(excludeDir, entry):
				logger.debug("Excluding dir '%s' and containing files", entry)
				continue
			if includeDir:
				if not re.search(includeDir, entry):
					continue
				logger.debug("Including dir '%s' and containing files", entry)
			if returnDirs:
				yield pp
			yield from findFilesGenerator(
				directory=dp,
				prefix=pp,
				excludeDir=excludeDir,
				excludeFile=excludeFile,
				includeDir=includeDir,
				includeFile=includeFile,
				returnDirs=returnDirs,
				returnLinks=returnLinks,
				followLinks=followLinks,
				repository=repository
			)
			continue

		if excludeFile and re.search(excludeFile, entry):
			if isLink:
				logger.debug("Excluding link '%s'", entry)
			else:
				logger.debug("Excluding file '%s'", entry)
			continue

		if includeFile:
			if not re.search(includeFile, entry):
				continue
			if isLink:
				logger.debug("Including link '%s'", entry)
			else:
				logger.debug("Including file '%s'", entry)
		yield pp

def findFiles(  # pylint: disable=too-many-arguments
	directory, prefix='',
	excludeDir=None, excludeFile=None, includeDir=None, includeFile=None,
	returnDirs=True, returnLinks=True, followLinks=False,
	repository=None
):
	return list(
		findFilesGenerator(
			directory, prefix,
			excludeDir, excludeFile, includeDir, includeFile,
			returnDirs, returnLinks, followLinks,
			repository
		)
	)

if sys.version_info >= (3, 7):
	def isRegularExpressionPattern(object):  # pylint: disable=redefined-builtin
		return isinstance(object, re.Pattern)
else:
	def isRegularExpressionPattern(object):  # pylint: disable=redefined-builtin
		return "SRE_Pattern" in str(type(object))


def ipAddressInNetwork(ipAddress, networkAddress):
	"""
	Checks if the given IP address is in the given network range.
	Returns ``True`` if the given address is part of the network.
	Returns ``False`` if the given address is not part of the network.

	:param ipAddress: The IP which we check.
	:type ipAddress: str
	:param networkAddress: The network address written with slash notation.
	:type networkAddress: str
	"""
	if not isinstance(ipAddress, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
		ipAddress = ipaddress.ip_address(ipAddress)
	if isinstance(ipAddress, ipaddress.IPv6Address) and ipAddress.ipv4_mapped:
		ipAddress = ipAddress.ipv4_mapped

	if not isinstance(networkAddress, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
		networkAddress = ipaddress.ip_network(networkAddress)

	return ipAddress in networkAddress


def getfqdn(name='', conf=None):
	"""
	Get the fqdn.

	If ``name`` is not given it will try various ways to get a valid
	fqdn from the current host.
	If ``conf`` but no name is given it will try to read the FQDN from
	the specified configuration file.
	"""
	if not name:
		try:
			return forceFqdn(os.environ["OPSI_HOSTNAME"])
		except KeyError:
			# Not set in environment.
			pass
		except ValueError:
			# Not a fqdn
			pass

		# lazy import to avoid circular dependency
		from OPSI.Util.Config import getGlobalConfig  # pylint: disable=import-outside-toplevel

		if conf is not None:
			hostname = getGlobalConfig('hostname', conf)
		else:
			hostname = getGlobalConfig('hostname')

		if hostname:
			return forceFqdn(hostname)

	return forceFqdn(socket.getfqdn(name))


def removeDirectory(directory):
	"""
	Removing an directory.

	If this fails with shutil it will try to use system calls.

	.. versionadded:: 4.0.5.1


	:param directory: Path to the directory
	:tye directory: str
	"""
	logger.debug('Removing directory: %s', directory)
	try:
		shutil.rmtree(directory)
	except UnicodeDecodeError:
		# See http://bugs.python.org/issue3616
		logger.info(
			'Client data directory seems to contain filenames '
			'with unicode characters. Trying fallback.'
		)

		# late import to avoid circular dependency
		import OPSI.System  # pylint: disable=import-outside-toplevel
		OPSI.System.execute("rm -rf {directory}")


def chunk(iterable, size):
	"""
	Returns chunks (parts) of a specified `size` from `iterable`.
	It will not pad (fill) the chunks.

	This works lazy and therefore can be used with any iterable without
	much overhead.

	Original recipe from http://stackoverflow.com/a/22045226
	"""
	it = iter(iterable)
	return iter(lambda: tuple(islice(it, size)), ())


@lru_cache(maxsize=4)
def getPublicKey(data):
	# Key type can be found in 4:11.
	rest = data[11:]
	count = 0
	mp = []
	for _ in range(2):
		length = struct.unpack('>L', rest[count:count + 4])[0]
		mp.append(bytes_to_long(rest[count + 4:count + 4 + length]))
		count += 4 + length

	return RSA.construct((mp[1], mp[0]))

class Singleton(type):
	_instances = {}
	def __call__(cls, *args, **kwargs):
		if cls not in cls._instances:
			cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
		return cls._instances[cls]

def monkeypatch_subprocess_for_frozen():
	from subprocess import Popen as Popen_orig
	class Popen_patched(Popen_orig):
		def __init__(self, *args, **kwargs):
			if kwargs.get("env") is None:
				kwargs["env"] = os.environ.copy()
			lp_orig = kwargs["env"].get("LD_LIBRARY_PATH_ORIG")
			if lp_orig is not None:
				# Restore the original, unmodified value
				kwargs["env"]["LD_LIBRARY_PATH"] = lp_orig
			else:
				# This happens when LD_LIBRARY_PATH was not set.
				# Remove the env var as a last resort
				kwargs["env"].pop("LD_LIBRARY_PATH", None)

			super().__init__(*args, **kwargs)

	subprocess.Popen = Popen_patched
