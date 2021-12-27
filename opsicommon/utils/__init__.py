# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
General utility functions.
"""

import types

from opsicommon.logging import logger


OBJECT_CLASSES = None
BaseObject = None  # pylint: disable=invalid-name
def deserialize(obj, preventObjectCreation=False):  # pylint: disable=invalid-name
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
