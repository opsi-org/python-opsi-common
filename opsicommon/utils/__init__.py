# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
General utility functions.
"""

from __future__ import annotations

import functools
import gzip
import json
import os
import platform
import re
import secrets
import subprocess
import tempfile
import time
import zlib
from contextlib import contextmanager
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network
from pathlib import Path
from types import EllipsisType
from typing import TYPE_CHECKING, Any, Callable, Generator, Iterable, Literal, Type, Union

import lz4.frame  # type: ignore[import]
from packaging.version import InvalidVersion, Version
from typing_extensions import deprecated

from opsicommon.logging import get_logger
from opsicommon.system.subprocess import patch_popen
from opsicommon.types import _PACKAGE_VERSION_REGEX, _PRODUCT_VERSION_REGEX

if platform.system().lower() == "windows":
	OPSI_TMP_DIR = None  # default %TEMP% of user
else:
	OPSI_TMP_DIR = Path("/var/lib/opsi/tmp")

if TYPE_CHECKING:
	from requests import Session

	from opsicommon.objects import BaseObject as TBaseObject
	from opsicommon.objects import Product, ProductOnClient, ProductOnDepot

OBJECT_CLASSES: dict[str, Type[TBaseObject]] = {}
BaseObject: Type[TBaseObject] | None = None

logger = get_logger("opsicommon.general")


# For typing: need Union here and cannot use |-syntax when working with strings (not importing Types)
def combine_versions(obj: Union["Product", "ProductOnClient", "ProductOnDepot"]) -> str:
	"""
	Returns the combination of product and package version.

	:type obj: Product, ProductOnClient, ProductOnDepot
	:return: The version.
	:rtype: str
	"""
	return f"{obj.productVersion}-{obj.packageVersion}"


def generate_opsi_host_key() -> str:
	"""
	Generates an random opsi host key.

	On Python 3.5 or lower this will try to make use of an existing
	random device.
	As a fallback the generation is done in plain Python.
	"""
	return secrets.token_hex(16)


def timestamp(secs: float = 0.0, date_only: bool = False) -> str:
	"""Returns a timestamp of the current system time in format YYYY-mm-dd[ HH:MM:SS]"""
	if not secs:
		secs = time.time()
	if date_only:
		return time.strftime("%Y-%m-%d", time.localtime(secs))
	return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(secs))


__now = datetime.now
__utc = timezone.utc


def utc_timestamp(date_only: bool = False) -> str:
	"""Returns a UTC timestamp in format YYYY-mm-dd[ HH:MM:SS]"""
	now = __now(tz=__utc)
	if date_only:
		return now.strftime("%Y-%m-%d")
	return now.strftime("%Y-%m-%d %H:%M:%S")


def unix_timestamp(*, millis: bool = False, add_seconds: float = 0.0) -> float:
	"""
	Returns the current unix timestamp (UTC).
	If `millis` is True, the timestamp is in milliseconds.
	`add_seconds` can be used to add or subtract seconds from the current time.
	"""
	# Do not use time.time() as the behaviour can be platform and timezone dependent
	unix_ts = __now(tz=__utc).timestamp() + add_seconds
	if millis:
		return unix_ts * 1000
	return unix_ts


class Singleton(type):
	_instances: dict[type, type] = {}

	def __call__(cls: "Singleton", *args: Any, **kwargs: Any) -> type:
		if cls not in cls._instances:
			cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
		return cls._instances[cls]


def update_environment_from_config_files(files: list[Path] | None = None) -> None:
	"""
	Updates the environment variables from the config files.
	"""
	if platform.system().lower() == "linux":
		if files is None:  # allow empty list
			files = [Path("/etc/environment"), Path("/etc/sysconfig/proxy"), Path("/etc/default")]
		# debian/ubuntu, suse, redhat/centos
		for path in files:
			if not path.exists() or not path.is_file():
				continue
			logger.debug("Updating environment from %s", path)
			with path.open("r", encoding="utf-8") as handle:
				for line in handle:
					line = line.strip()
					if not line or line.startswith("#"):
						continue
					key, value = line.split("=", 1)
					key = key.lstrip("export").strip().lower()
					value = value.strip(" '\"\t")
					if value and key in ("http_proxy", "https_proxy", "no_proxy") and not os.environ.get(key):
						os.environ[key] = value.strip()

	# on windows, services that use WinHTTP API will use the global (netsh) proxy settings
	# https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpgetdefaultproxyconfiguration

	# on macos, services use the system proxy settings (networksetup -setwebproxy)
	# https://apple.stackexchange.com/questions/226544/how-to-set-proxy-on-os-x-terminal-permanently


def prepare_proxy_environment(
	hostname: str, proxy_url: str | None = "system", no_proxy_addresses: list[str] | None = None, session: Session | None = None
) -> Session:
	"""
	proxy_url can be:
	* an explicid url like http://10.10.10.1:8080
	* the string "system" in which case the os environment determines proxy behaviour
	* emptystring or None to disable proxy usage.
	If session is given its proxy settings are adapted. Else a new session is created and returned.
	"""
	for env_var in ("CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE"):
		if env_var in os.environ:
			os.environ.pop(env_var)

	def add_protocol(host: str, protocol: str = "http") -> str:
		if not host or "://" in host:
			return host
		logger.debug("Adding schema '%s://' to form proxy url from host '%s'", protocol, host)
		return "://".join((protocol, host))

	if no_proxy_addresses is None:
		no_proxy_addresses = ["::1", "127.0.0.1", "ip6-localhost", "localhost"]
	if session is None:
		# Import is slow
		from requests import Session

		session = Session()
	if proxy_url:
		try:
			update_environment_from_config_files()
		except Exception as error:
			logger.error("Failed to update environment from config files: %s", error)
		# Use a proxy
		no_proxy = [x.strip() for x in os.environ.get("no_proxy", "").split(",") if x.strip()]
		if proxy_url.lower() == "system":
			# Making sure system proxy has correct form
			if os.environ.get("http_proxy"):
				os.environ["http_proxy"] = add_protocol(os.environ.get("http_proxy", ""))
			if os.environ.get("https_proxy"):
				os.environ["https_proxy"] = add_protocol(os.environ.get("https_proxy", ""))
			if no_proxy != ["*"]:
				no_proxy.extend(no_proxy_addresses)
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
			no_proxy = no_proxy_addresses

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


@deprecated("Use opsicommon.system.subprocess.patch_popen() instead")
def monkeypatch_subprocess_for_frozen() -> None:
	patch_popen()


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
			except Exception:
				return value

		def func_with_serialized_params(*args: Any, **kwargs: Any) -> Callable:
			_args = tuple([deserialise(arg) for arg in args])
			_kwargs = {k: deserialise(v) for k, v in kwargs.items()}
			return func(*_args, **_kwargs)

		cached_function = cache(func_with_serialized_params)

		@functools.wraps(func)
		def lru_decorator(*args: Any, **kwargs: Any) -> Callable:
			_args = tuple([json.dumps(arg, sort_keys=True) if type(arg) in (list, dict) else arg for arg in args])
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
		logger.info("Failed to create temporary directory at %s, falling back to default: %s", base, error)
		base = None
	with tempfile.TemporaryDirectory(dir=base) as tmp_dir_name:
		yield Path(tmp_dir_name)


def _legacy_cmpkey(version: str) -> tuple[str, ...]:
	_legacy_version_component_re = re.compile(r"(\d+ | [a-z]+ | \.| -)", re.VERBOSE)
	_legacy_version_replacement_map = {
		"pre": "c",
		"preview": "c",
		"-": "final-",
		"rc": "c",
		"dev": "@",
	}

	def _parse_version_parts(instring: str) -> Generator[str, None, None]:
		for part in _legacy_version_component_re.split(instring):
			part = _legacy_version_replacement_map.get(part, part)

			if not part or part == ".":
				continue

			if part[:1] in "0123456789":
				# pad for numeric comparison
				yield part.zfill(8)
			else:
				yield "*" + part

		# ensure that alpha/beta/candidate are before final
		yield "*final"

	parts: list[str] = []
	for part in _parse_version_parts(version.lower()):
		if part.startswith("*"):
			# remove "-" before a prerelease tag
			if part < "*final":
				while parts and parts[-1] == "*final-":
					parts.pop()

			# remove trailing zeros from each series of numeric parts
			while parts and parts[-1] == "00000000":
				parts.pop()

		parts.append(part)

	return tuple(parts)


# Inspired by packaging.version.LegacyVersion (deprecated)
class LegacyVersion(Version):
	def __init__(self, version: str):
		self._version = str(version)  # type: ignore[assignment]
		self._key = _legacy_cmpkey(self._version)  # type: ignore[assignment,arg-type]

	def __str__(self) -> str:
		return str(self._version)


def compare_versions(version1: str, condition: Literal["==", "=", "<", "<=", ">", ">="], version2: str) -> bool:
	"""
	Compare the versions `v1` and `v2` with the given `condition`.

	`condition` may be one of `==`, `=`, `<`, `<=`, `>`, `>=`.

	:raises ValueError: If invalid value for version or condition if given.
	:rtype: bool
	:return: If the comparison matches this will return True.
	"""
	# Remove part after wave to not break old behaviour
	version1 = version1.split("~", 1)[0]
	version2 = version2.split("~", 1)[0]
	for version in (version1, version2):
		parts = version.split("-")
		if (
			not _PRODUCT_VERSION_REGEX.search(parts[0])
			or (len(parts) == 2 and not _PACKAGE_VERSION_REGEX.search(parts[1]))
			or len(parts) > 2
		):
			raise ValueError(f"Bad package version provided: '{version}'")

	try:
		# Don't use packaging.version.parse() here as packaging.version.Version cannot handle legacy formats
		first = LegacyVersion(version1)
		second = LegacyVersion(version2)
	except InvalidVersion as version_error:
		raise ValueError("Invalid version provided to compare_versions") from version_error

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
		raise ValueError(f"Bad condition {condition} provided to compare_versions")

	logger.debug("%s condition: %s %s %s", "Fullfilled" if result else "Unfulfilled", version1, condition, version2)
	return result


def ip_address_in_network(address: str | IPv4Address | IPv6Address, network: str | IPv4Network | IPv6Network) -> bool:
	"""
	Checks if the given IP address is in the given network range.
	Returns ``True`` if the given address is part of the network.
	Returns ``False`` if the given address is not part of the network.

	:param address: The IP which we check.
	:type address: str
	:param network: The network address written with slash notation.
	:type network: str
	"""
	if not isinstance(address, (IPv4Address, IPv6Address)):
		address = ip_address(address)
	if isinstance(address, IPv6Address) and address.ipv4_mapped:
		address = address.ipv4_mapped

	if not isinstance(network, (IPv4Network, IPv6Network)):
		network = ip_network(network)

	return address in network


def execute(
	cmd: list[str], allow_exit_codes: list[int | EllipsisType] | tuple[int | EllipsisType] | None = None
) -> subprocess.CompletedProcess:
	allow_exit_codes = allow_exit_codes or [0]
	logger.info("Executing: %s", cmd)
	try:
		proc = subprocess.run(cmd, shell=False, check=False, capture_output=True, text=True, encoding="utf-8")
		out = proc.stderr + proc.stdout
		logger.debug("Command %s output: %s", cmd, out)
		if ... not in allow_exit_codes and proc.returncode not in allow_exit_codes:
			err = f"Command failed: {proc.returncode} - {out}"
			raise RuntimeError(err)
		return proc
	except FileNotFoundError as exc:
		err = f"Command {cmd[0]!r} not found"
		raise RuntimeError(err) from exc


def retry(
	retries: int = 3, wait: float = 0, exceptions: Iterable[Type[Exception]] | None = None, caught_exceptions: list[Exception] | None = None
) -> Callable:
	"""
	Decorator to retry a function.
	:param retries: Number of retries
	:param wait: Time to wait between retries
	:param exceptions: Exception to catch, if None catch all exceptions
	"""
	attempts = 1 + retries

	def decorator(func: Callable) -> Callable:
		def wrapper(*args: Any, **kwargs: Any) -> Any:
			for attempt in range(1, attempts + 1):
				try:
					return func(*args, **kwargs)
				except Exception as exc:
					logger.warning("Attempt %d of %d failed with [%s] %s", attempt, attempts, exc.__class__.__name__, exc)
					if attempt == attempts:
						logger.debug("No retry because the maximum number of %d attempts has been reached", attempts)
						raise
					if exceptions and not any(isinstance(exc, exc_type) for exc_type in exceptions):
						logger.debug("No retry because excetion type %s is not in %s", exc.__class__.__name__, exceptions)
						raise
					if caught_exceptions is not None:
						caught_exceptions.append(exc)
					if wait > 0:
						time.sleep(wait)

		return wrapper

	return decorator


def decompress_data(data: bytes, compression: Literal["lz4", "deflate", "gz", "gzip"]) -> bytes:
	compressed_size = len(data)

	decompress_start = time.perf_counter()
	if compression == "lz4":
		data = lz4.frame.decompress(data)
	elif compression == "deflate":
		data = zlib.decompress(data)
	elif compression in ("gz", "gzip"):
		data = gzip.decompress(data)
	else:
		raise ValueError(f"Unhandled compression {compression!r}")
	decompress_end = time.perf_counter()

	uncompressed_size = len(data)
	get_logger().debug(
		"%s decompression ratio: %d => %d = %0.2f%%, time: %0.2fms",
		compression,
		compressed_size,
		uncompressed_size,
		100 - 100 * (compressed_size / uncompressed_size),
		1000 * (decompress_end - decompress_start),
	)
	return data


def compress_data(
	data: bytes, compression: Literal["lz4", "deflate", "gz", "gzip"], compression_level: int = 0, lz4_block_linked: bool = True
) -> bytes:
	uncompressed_size = len(data)

	compress_start = time.perf_counter()
	if compression == "lz4":
		data = lz4.frame.compress(data, compression_level=compression_level, block_linked=lz4_block_linked)
	elif compression == "deflate":
		data = zlib.compress(data)
	elif compression in ("gz", "gzip"):
		data = gzip.compress(data)
	else:
		raise ValueError(f"Unhandled compression {compression!r}")
	compress_end = time.perf_counter()

	compressed_size = len(data)
	logger.debug(
		"%s compression ratio: %d => %d = %0.2f%%, time: %0.2fms",
		compression,
		uncompressed_size,
		compressed_size,
		100 - 100 * (compressed_size / uncompressed_size),
		1000 * (compress_end - compress_start),
	)
	return data
