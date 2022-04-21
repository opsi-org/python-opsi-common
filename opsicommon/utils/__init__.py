# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
General utility functions.
"""

import functools
import json
import os
import secrets
import subprocess
import time
import types
from datetime import date, datetime
from typing import Any, Dict

import requests
from frozendict import frozendict

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
		from opsicommon.objects import (  # pylint: disable=redefined-outer-name,import-outside-toplevel
			OBJECT_CLASSES,
		)
	global BaseObject  # pylint: disable=global-statement,invalid-name,global-variable-not-assigned
	if BaseObject is None:
		from opsicommon.objects import (  # pylint: disable=redefined-outer-name,import-outside-toplevel
			BaseObject,
		)

	if isinstance(obj, dict):
		if (
			not prevent_object_creation
			and "type" in obj
			and isinstance(obj["type"], str)
			and obj["type"] in OBJECT_CLASSES
			and issubclass(OBJECT_CLASSES[obj["type"]], BaseObject)
		):
			try:
				return OBJECT_CLASSES[obj["type"]].fromHash(obj)
			except Exception as err:  # pylint: disable=broad-except
				logger.error(err, exc_info=True)
				raise ValueError(f"Failed to create object from dict {obj}: {err}") from err

		return {key: deserialize(value, prevent_object_creation=prevent_object_creation) for key, value in obj.items()}

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
		if isinstance(obj, (datetime, date)):
			return obj.isoformat()
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
		obj["type"] = object_type
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
	"""Returns a timestamp of the current system time format: YYYY-mm-dd[ HH:MM:SS]"""
	if not secs:
		secs = time.time()
	if date_only:
		return time.strftime("%Y-%m-%d", time.localtime(secs))
	return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(secs))


class Singleton(type):
	_instances: Dict[type, Any] = {}

	def __call__(cls, *args, **kwargs):
		if cls not in cls._instances:
			cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
		return cls._instances[cls]


def prepare_proxy_environment(hostname, proxy_url="system", no_proxy_addresses=None, session=None):  # pylint: disable=too-many-branches
	"""
	proxy_url can be:
	* an explicid url like http://10.10.10.1:8080
	* the string "system" in which case the os environment determines proxy behaviour
	* emptystring or None to disable proxy usage.
	If session is given its proxy settings are adapted. Else a new session is created and returned.
	"""

	def add_protocol(host, protocol="http"):
		if not host or "://" in host:
			return host
		logger.debug("Adding schema '%s://' to form proxy url from host '%s'", protocol, host)
		return "://".join((protocol, host))

	if no_proxy_addresses is None:
		no_proxy_addresses = []
	if session is None:
		session = requests.Session()
	if proxy_url:
		# Use a proxy
		if proxy_url.lower() == "system":
			# Making sure system proxy has correct form
			if os.environ.get("http_proxy"):
				os.environ["http_proxy"] = add_protocol(os.environ.get("http_proxy", ""))
			if os.environ.get("https_proxy"):
				os.environ["https_proxy"] = add_protocol(os.environ.get("https_proxy", ""))  # protocol=https?
		else:
			proxy_url = add_protocol(proxy_url)
			if hostname in no_proxy_addresses:
				logger.info("Not using proxy for address %s", hostname)
			else:
				session.proxies.update(
					{
						"http": proxy_url,
						"https": proxy_url,
					}
				)
				for key in ("http_proxy", "https_proxy"):
					if key in os.environ:
						del os.environ[key]

		no_proxy = [x.strip() for x in os.environ.get("no_proxy", "").split(",") if x.strip()]
		if no_proxy != ["*"]:
			no_proxy.extend(no_proxy_addresses)
		os.environ["no_proxy"] = ",".join(set(no_proxy))
	else:
		# Do not use a proxy
		os.environ["no_proxy"] = "*"

	logger.info(
		"Using proxy settings: http_proxy=%r, https_proxy=%r, no_proxy=%r",
		proxy_url if proxy_url and proxy_url.lower() != "system" else os.environ.get("http_proxy"),
		proxy_url if proxy_url and proxy_url.lower() != "system" else os.environ.get("https_proxy"),
		os.environ.get("no_proxy"),
	)
	return session


class PopenFrozen(subprocess.Popen):
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


def monkeypatch_subprocess_for_frozen():
	subprocess.Popen = PopenFrozen


def frozen_lru_cache(*decorator_args):
	"""
	This decorator is intended to be used as drop-in replacement for functools.lru_cache.
	It mitigates the weakness of not being able to handle dictionary type arguments by freezing them.
	"""

	def inner(func):
		def func_with_serialized_params(*args, **kwargs):
			_args = tuple([frozendict(arg) if isinstance(arg, dict) else arg for arg in args])
			_kwargs = {k: frozendict(v) if isinstance(v, dict) else v for k, v in kwargs.items()}
			return func(*_args, **_kwargs)

		return func_with_serialized_params

	if len(decorator_args) == 1 and callable(decorator_args[0]):
		# No arguments, this is the decorator
		return functools.lru_cache()(inner)(decorator_args[0])
	return (functools.lru_cache(*decorator_args))(inner)
