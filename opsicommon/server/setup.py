# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
server setup tasks
"""

import platform
import subprocess

from ..config import OpsiConfig
from ..logging import get_logger
from .rights import set_rights

if platform.system().lower() == "linux":
	import grp
	import pwd


logger = get_logger("opsi.general")


def create_group(groupname: str, system: bool = False) -> None:
	logger.notice("Creating group: %s", groupname)
	cmd = ["groupadd"]
	if system:
		cmd.append("--system")
	cmd.append(groupname)
	logger.info("Running command: %s", cmd)
	subprocess.check_output(cmd, stderr=subprocess.STDOUT)


def create_user(username: str, primary_groupname: str, home: str, shell: str, system: bool = False) -> None:
	logger.notice("Creating user: %s", username)
	cmd = ["useradd", "-g", primary_groupname, "-d", home, "-s", shell]
	if system:
		cmd.append("--system")
	cmd.append(username)
	logger.info("Running command: %s", cmd)
	subprocess.check_output(cmd, stderr=subprocess.STDOUT)


def modify_user(username: str, home: str | None = None, shell: str | None = None) -> None:
	if not home and not shell:
		return
	logger.notice("Modifying user: %s (home=%s, shell=%s)", username, home, shell)
	cmd = ["usermod"]
	if home:
		cmd += ["-d", home]
	if shell:
		cmd += ["-s", shell]
	cmd.append(username)
	logger.info("Running command: %s", cmd)
	subprocess.check_output(cmd, stderr=subprocess.STDOUT)


def add_user_to_group(username: str, groupname: str) -> None:
	logger.notice("Adding user '%s' to group '%s'", username, groupname)
	cmd = ["usermod", "-a", "-G", groupname, username]  # pylint: disable=use-tuple-over-list
	logger.info("Running command: %s", cmd)
	subprocess.check_output(cmd, stderr=subprocess.STDOUT)


def set_primary_group(username: str, groupname: str) -> None:
	logger.notice("Setting primary group of user '%s' to '%s'", username, groupname)
	cmd = ["usermod", "-g", groupname, username]  # pylint: disable=use-tuple-over-list
	logger.info("Running command: %s", cmd)
	subprocess.check_output(cmd, stderr=subprocess.STDOUT)


def get_groups() -> dict[str, grp.struct_group]:
	return {group.gr_name: group for group in grp.getgrall()}


def get_users() -> dict[str, pwd.struct_passwd]:
	return {user.pw_name: user for user in pwd.getpwall()}


def setup_users_and_groups(ignore_errors: bool = False) -> None:
	logger.info("Setup users and groups")
	opsi_config = OpsiConfig()
	try:
		grp.getgrnam(opsi_config.get("groups", "admingroup"))
	except KeyError:
		try:
			create_group(groupname=opsi_config.get("groups", "admingroup"), system=False)
		except Exception as err:  # pylint: disable=broad-except
			if not ignore_errors:
				raise
			logger.info(err)

	try:
		grp.getgrnam(opsi_config.get("groups", "fileadmingroup"))
	except KeyError:
		try:
			create_group(groupname=opsi_config.get("groups", "fileadmingroup"), system=True)
		except Exception as err:  # pylint: disable=broad-except
			if not ignore_errors:
				raise
			logger.info(err)

	try:
		pwd.getpwnam(opsi_config.get("depot_user", "username"))
	except KeyError:
		try:
			create_user(
				username=opsi_config.get("depot_user", "username"),
				primary_groupname=opsi_config.get("groups", "fileadmingroup"),
				home=opsi_config.get("depot_user", "home"),
				shell="/bin/false",
				system=True,
			)
		except Exception as err:  # pylint: disable=broad-except
			if not ignore_errors:
				raise
			logger.info(err)


def setup_file_permissions(path: str = "/") -> None:
	set_rights(path)


def setup(ignore_errors: bool = False) -> None:
	logger.notice("Running setup")
	setup_users_and_groups(ignore_errors)
	setup_file_permissions()
