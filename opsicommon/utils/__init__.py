# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
General utility functions.
"""

import time
import types
import secrets
try:
	import orjson as json  # pyright: reportMissingModuleSource=false
except ImportError:
	import json

from opsicommon.logging import logger


OBJECT_CLASSES = None
BaseObject = None  # pylint: disable=invalid-name
def deserialize(obj, prevent_object_creation=False):  # pylint: disable=invalid-name
	"""
	Deserialization of `obj`.

	This function will deserialize objects from JSON into opsi compatible objects.
	In case `obj` is a list contained elements are deserialized.
	In case `obj` is a dict the values are deserialized.

	In case `obj` is a dict and holds a key *type* and `prevent_object_creation`
	is `True` it will be tried to create an opsi object instance from it

	:type obj: object
	:type prevent_object_creation: bool
	"""
	if isinstance(obj, list):
		return [deserialize(element, prevent_object_creation=prevent_object_creation) for element in obj]

	global OBJECT_CLASSES  # pylint: disable=global-statement,invalid-name,global-variable-not-assigned
	if OBJECT_CLASSES is None:
		from opsicommon.objects import OBJECT_CLASSES  # pylint: disable=redefined-outer-name,import-outside-toplevel
	global BaseObject  # pylint: disable=global-statement,invalid-name,global-variable-not-assigned
	if BaseObject is None:
		from opsicommon.objects import BaseObject  # pylint: disable=redefined-outer-name,import-outside-toplevel

	if isinstance(obj, dict):
		if (
			not prevent_object_creation and
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
			key: deserialize(value, prevent_object_creation=prevent_object_creation)
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


def combine_versions(obj):
	"""
	Returns the combination of product and package version.

	:type obj: Product, ProductOnClient, ProductOnDepot
	:return: The version.
	:rtype: str
	"""
	return f"{obj.productVersion}-{obj.packageVersion}"


def from_json(obj, object_type=None, prevent_object_creation=False):
	if isinstance(obj, bytes):
		# Allow decoding errors (workaround for opsi-script bug)
		obj = obj.decode("utf-8", "replace")
	obj = json.loads(obj)
	if isinstance(obj, dict) and object_type:
		obj['type'] = object_type
	return deserialize(obj, prevent_object_creation=prevent_object_creation)


def to_json(obj, ensure_ascii=False):
	return json.dumps(serialize(obj), ensure_ascii=ensure_ascii)


def generate_opsi_host_key():
	"""
	Generates an random opsi host key.

	On Python 3.5 or lower this will try to make use of an existing
	random device.
	As a fallback the generation is done in plain Python.
	"""
	return secrets.token_hex(16)


def timestamp(secs=0, date_only=False):
	''' Returns a timestamp of the current system time format: YYYY-mm-dd[ HH:MM:SS] '''
	if not secs:
		secs = time.time()
	if date_only:
		return time.strftime("%Y-%m-%d", time.localtime(secs))
	return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(secs))

class Singleton(type):
	_instances = {}
	def __call__(cls, *args, **kwargs):
		if cls not in cls._instances:
			cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
		return cls._instances[cls]
