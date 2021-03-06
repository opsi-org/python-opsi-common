# -*- coding: utf-8 -*-

# opsiclientd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2010-2021 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import os
import platform
import warnings
import urllib3

import pytest
from _pytest.logging import LogCaptureHandler


def emit(*args, **kwargs) -> None:  # pylint: disable=unused-argument
	pass


LogCaptureHandler.emit = emit  # type: ignore[attr-defined,assignment]


@pytest.hookimpl()
def pytest_configure(config):
	# https://pypi.org/project/pytest-asyncio
	# When the mode is auto, all discovered async tests are considered
	# asyncio-driven even if they have no @pytest.mark.asyncio marker.
	config.option.asyncio_mode = "auto"
	# register custom markers
	config.addinivalue_line("markers", "docker_linux: mark test to run only on linux in docker")
	config.addinivalue_line("markers", "not_in_docker: mark test to run only if not running in docker")
	config.addinivalue_line("markers", "admin_permissions: mark test to run only if user has admin permissions")
	config.addinivalue_line("markers", "windows: mark test to run only on windows")
	config.addinivalue_line("markers", "linux: mark test to run only on linux")
	config.addinivalue_line("markers", "darwin: mark test to run only on darwin")
	config.addinivalue_line("markers", "posix: mark test to run only on posix")


@pytest.fixture(autouse=True)
def disable_insecure_request_warning():
	warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)


def running_in_docker():
	if not os.path.exists("/proc/self/cgroup"):
		return False
	with open("/proc/self/cgroup", "r", encoding="utf-8") as file:
		for line in file.readlines():
			if line.split(":")[2].startswith("/docker/"):
				return True
	return False


def admin_permissions():
	try:
		return os.geteuid() == 0
	except AttributeError:
		import ctypes  # pylint: disable=import-outside-toplevel

		return ctypes.windll.shell32.IsUserAnAdmin() != 0


PLATFORM = platform.system().lower()
RUNNING_IN_DOCKER = running_in_docker()
ADMIN_PERMISSIONS = admin_permissions()


def pytest_runtest_setup(item):
	supported_platforms = []
	for marker in item.iter_markers():
		if marker.name == "docker_linux" and not RUNNING_IN_DOCKER:  # pylint: disable=loop-global-usage
			pytest.skip("Must run in docker")  # pylint: disable=dotted-import-in-loop
			return
		if marker.name == "not_in_docker" and RUNNING_IN_DOCKER:  # pylint: disable=loop-global-usage
			pytest.skip("Cannot run in docker")  # pylint: disable=dotted-import-in-loop
			return
		if marker.name == "admin_permissions" and not ADMIN_PERMISSIONS:  # pylint: disable=loop-global-usage
			pytest.skip("No admin permissions")  # pylint: disable=dotted-import-in-loop
			return
		if marker.name in ("windows", "linux", "darwin", "posix"):
			if marker.name == "posix":
				supported_platforms.extend(["linux", "darwin"])
			else:
				supported_platforms.append(marker.name)

	if supported_platforms and PLATFORM not in supported_platforms:
		pytest.skip(f"Cannot run on {PLATFORM}")
