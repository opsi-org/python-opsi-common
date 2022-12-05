# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import os
import pathlib
import platform
import re
from unittest.mock import patch

import pytest
from opsicommon.system import info  # pylint: disable=unused-import
from opsicommon.system.info import (
	is_deb_based,
	is_linux,
	is_macos,
	is_pacman_based,
	is_rpm_based,
	is_windows,
	linux_distro_id,
	linux_distro_id_like,
	linux_distro_id_like_contains,
)


def test_is_windows() -> None:
	assert is_windows() == bool(os.name == "nt")


def test_is_linux() -> None:
	assert is_linux() == bool(platform.system() == "Linux")


def test_is_macos() -> None:
	assert is_macos() == bool(platform.system() == "Darwin")


@pytest.mark.linux
def test_linux_distro_id() -> None:
	data = pathlib.Path("/etc/os-release").read_text(encoding="utf-8")
	did = re.search(r"^ID=(.*)$", data, flags=re.MULTILINE).group(1)  # type: ignore[union-attr]
	assert linux_distro_id() == did


@pytest.mark.linux
def test_linux_distro_id_like() -> None:
	data = pathlib.Path("/etc/os-release").read_text(encoding="utf-8")
	ids = [re.search(r"^ID=(.*)$", data, flags=re.MULTILINE).group(1)]  # type: ignore[union-attr]
	match = re.search(r"^ID_LIKE=(.*)$", data, flags=re.MULTILINE)
	if match:
		ids.extend(match.group(1).split())
	assert linux_distro_id_like() == set(ids)


@pytest.mark.parametrize(
	"id_like, search, expected",
	(
		({"ubuntu", "debian"}, "debian", True),
		({"ubuntu", "debian"}, "suse", False),
		({"debian"}, "debian", True),
		({"ubuntu", "debian"}, ["other", "debian"], True),
		({"ubuntu", "debian"}, ["other", "other2"], False),
		({"ubuntu", "debian"}, {"other", "debian"}, True),
		({"opensuse-leap", "opensuse-tumbleweed"}, ("opensuse", "sles"), True),
		({"opensuse-leap", "opensuse-tumbleweed"}, "opensuse", True),
	),
)
def test_linux_distro_id_like_contains(id_like: set[str], search: str, expected: bool) -> None:
	linux_distro_id_like.cache_clear()
	with patch("opsicommon.system.info.linux_distro_id_like", lambda: id_like):
		assert linux_distro_id_like_contains(search) is expected


@pytest.mark.parametrize(
	"id_like, package_system, expected",
	(
		({"ubuntu", "debian"}, "deb", True),
		({"ubuntu", "debian"}, "rpm", False),
		({"ubuntu", "debian"}, "pacman", False),
		({"amzn"}, "deb", False),
		({"amzn"}, "rpm", True),
		({"amzn"}, "pacman", False),
		({"unknown", "arch"}, "deb", False),
		({"unknown", "arch"}, "rpm", False),
		({"unknown", "arch"}, "pacman", True),
	),
)
def test_linux_is_based(id_like: set[str], package_system: str, expected: bool) -> None:
	linux_distro_id_like.cache_clear()
	is_deb_based.cache_clear()
	is_pacman_based.cache_clear()
	is_rpm_based.cache_clear()
	with patch("opsicommon.system.info.linux_distro_id_like", lambda: id_like):
		func = getattr(info, f"is_{package_system}_based")
		assert func() is expected
