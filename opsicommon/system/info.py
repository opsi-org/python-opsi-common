# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
system.info
"""

import platform
from functools import lru_cache


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
