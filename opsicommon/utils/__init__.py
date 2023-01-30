# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
General utility functions.
"""

import functools
import json
import os
import platform
import secrets
import subprocess
import tempfile
import time
import types
from contextlib import contextmanager
from datetime import date, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Generator, Type, Union

import msgspec
import requests

from opsicommon.logging import get_logger

if platform.system().lower() == "windows":
	OPSI_TMP_DIR = None  # default %TEMP% of user
else:
	OPSI_TMP_DIR = Path("/var/lib/opsi/tmp")


if TYPE_CHECKING:
	from opsicommon.objects import BaseObject as TBaseObject
	from opsicommon.objects import Product, ProductOnClient, ProductOnDepot

OBJECT_CLASSES: dict[str, Type["TBaseObject"]] = {}
BaseObject: Type["TBaseObject"] | None = None  # pylint: disable=invalid-name

logger = get_logger("opsicommon.general")


def deserialize(obj: Any, prevent_object_creation: bool = False) -> Any:  # pylint: disable=invalid-name
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
	if not OBJECT_CLASSES:
		from opsicommon.objects import (  # pylint: disable=redefined-outer-name,import-outside-toplevel
			OBJECT_CLASSES,
		)
	global BaseObject  # pylint: disable=global-statement,invalid-name,global-variable-not-assigned
	if BaseObject is None:
		from opsicommon.objects import (  # pylint: disable=redefined-outer-name,import-outside-toplevel
			BaseObject,
		)

	if BaseObject is None:
		raise RuntimeError("Failed to import BaseObject")

	if isinstance(obj, dict):
		if (
			not prevent_object_creation
			and "type" in obj
			and isinstance(obj["type"], str)
			and obj["type"] in OBJECT_CLASSES
			and issubclass(OBJECT_CLASSES[obj["type"]], BaseObject)
		):
			try:
				return OBJECT_CLASSES[obj["type"]].fromHash(obj)  # type: ignore[attr-defined]
			except Exception as err:  # pylint: disable=broad-except
				logger.error(err, exc_info=True)
				raise ValueError(f"Failed to create object from dict {obj}: {err}") from err

		return {key: deserialize(value, prevent_object_creation=prevent_object_creation) for key, value in obj.items()}

	return obj


def serialize(obj: Any) -> Any:
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


# For typing: need Union here and cannot use |-syntax when working with strings (not importing Types)
def combine_versions(obj: Union["Product", "ProductOnClient", "ProductOnDepot"]) -> str:
	"""
	Returns the combination of product and package version.

	:type obj: Product, ProductOnClient, ProductOnDepot
	:return: The version.
	:rtype: str
	"""
	return f"{obj.productVersion}-{obj.packageVersion}"


json_decoder = msgspec.json.Decoder()
json_encoder = msgspec.json.Encoder()


def from_json(obj: str | bytes, object_type: str | None = None, prevent_object_creation: bool = False) -> Any:
	if isinstance(obj, str):
		obj = obj.encode("utf-8")
	obj = json_decoder.decode(obj)
	if isinstance(obj, dict) and object_type:
		obj["type"] = object_type
	return deserialize(obj, prevent_object_creation=prevent_object_creation)


def to_json(obj: Any) -> str:
	return json_encoder.encode(serialize(obj)).decode("utf-8")


def generate_opsi_host_key() -> str:
	"""
	Generates an random opsi host key.

	On Python 3.5 or lower this will try to make use of an existing
	random device.
	As a fallback the generation is done in plain Python.
	"""
	return secrets.token_hex(16)


def timestamp(secs: float = 0.0, date_only: bool = False) -> str:
	"""Returns a timestamp of the current system time format: YYYY-mm-dd[ HH:MM:SS]"""
	if not secs:
		secs = time.time()
	if date_only:
		return time.strftime("%Y-%m-%d", time.localtime(secs))
	return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(secs))


class Singleton(type):
	_instances: dict[type, type] = {}

	def __call__(cls: "Singleton", *args: Any, **kwargs: Any) -> type:
		if cls not in cls._instances:
			cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
		return cls._instances[cls]


def prepare_proxy_environment(  # pylint: disable=too-many-branches
	hostname: str,
	proxy_url: str | None = "system",
	no_proxy_addresses: list[str] | None = None,
	session: requests.Session | None = None
) -> requests.Session:
	"""
	proxy_url can be:
	* an explicid url like http://10.10.10.1:8080
	* the string "system" in which case the os environment determines proxy behaviour
	* emptystring or None to disable proxy usage.
	If session is given its proxy settings are adapted. Else a new session is created and returned.
	"""

	def add_protocol(host: str, protocol: str = "http") -> str:
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
	def __init__(self, *args: Any, **kwargs: Any) -> None:
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


def monkeypatch_subprocess_for_frozen() -> None:
	subprocess.Popen = PopenFrozen  # type: ignore[misc]


def frozen_lru_cache(*decorator_args: Any) -> Callable:
	"""
	This decorator is intended to be used as drop-in replacement for functools.lru_cache.
	It mitigates the weakness of not being able to handle dictionary type arguments by freezing them.
	"""
	if len(decorator_args) == 1 and callable(decorator_args[0]):
		# No arguments, this is the decorator
		cache = functools.lru_cache()
	else:
		cache = functools.lru_cache(*decorator_args)

	def inner(func: Callable) -> Callable:
		def deserialise(value: str) -> Any:
			try:
				return json.loads(value)
			except Exception:  # pylint: disable=broad-except
				return value

		def func_with_serialized_params(*args: Any, **kwargs: Any) -> Callable:
			_args = tuple([deserialise(arg) for arg in args])  # pylint: disable=consider-using-generator
			_kwargs = {k: deserialise(v) for k, v in kwargs.items()}
			return func(*_args, **_kwargs)

		cached_function = cache(func_with_serialized_params)

		@functools.wraps(func)
		def lru_decorator(*args: Any, **kwargs: Any) -> Callable:
			_args = tuple([json.dumps(arg, sort_keys=True) if type(arg) in (list, dict) else arg for arg in args])  # pylint: disable=consider-using-generator
			_kwargs = {k: json.dumps(v, sort_keys=True) if type(v) in (list, dict) else v for k, v in kwargs.items()}
			return cached_function(*_args, **_kwargs)

		lru_decorator.cache_info = cached_function.cache_info  # type: ignore[attr-defined]
		lru_decorator.cache_clear = cached_function.cache_clear  # type: ignore[attr-defined]
		return lru_decorator

	if len(decorator_args) == 1 and callable(decorator_args[0]):
		# No arguments, this is the decorator
		return inner(decorator_args[0])
	return inner


@contextmanager
def make_temp_dir(base: Path | None = None) -> Generator[Path, None, None]:
	if not base:
		base = OPSI_TMP_DIR
	try:
		if base and not base.exists():
			base.mkdir(parents=True)
	except PermissionError as error:
		logger.error("Failed to create temporary directory at %s, falling back to default: %s", base, error)
		base = None
	with tempfile.TemporaryDirectory(dir=base) as tmp_dir_name:
		yield Path(tmp_dir_name)
