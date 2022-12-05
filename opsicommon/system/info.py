# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
system.info
"""

import platform
from functools import lru_cache
from typing import Iterable


@lru_cache
def is_linux() -> bool:
	return platform.system().lower() == "linux"


@lru_cache
def is_windows() -> bool:
	return platform.system().lower() == "windows"


@lru_cache
def is_macos() -> bool:
	return platform.system().lower() == "darwin"


@lru_cache
def linux_distro_id() -> str:
	return platform.freedesktop_os_release()["ID"]


@lru_cache
def linux_distro_id_like() -> set[str]:
	info = platform.freedesktop_os_release()
	ids = {info["ID"]}
	# IDs are space separated and ordered by precedence
	for _id in info.get("ID_LIKE", "").split():
		ids.add(_id)
	return ids


def linux_distro_id_like_contains(search: str | Iterable[str]) -> bool:
	"""
	Returns true if any string in ID_LIKE contains one of the search strings passed in `search`.
	"""
	if isinstance(search, str):
		search = [search]  # pylint: disable=use-tuple-over-list
	for did in linux_distro_id_like():
		for entry in search:
			if entry in did:
				return True
	return False


@lru_cache
def is_deb_based() -> bool:
	return bool(linux_distro_id_like().intersection({"debian", "ubuntu", "univention"}))


@lru_cache
def is_rpm_based() -> bool:
	return bool(
		linux_distro_id_like().intersection(
			{"almalinux", "amzn", "rhel", "rocky", "ol", "opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles"}
		)
	)


@lru_cache
def is_pacman_based() -> bool:
	return bool(linux_distro_id_like().intersection({"arch", "manjaro"}))
