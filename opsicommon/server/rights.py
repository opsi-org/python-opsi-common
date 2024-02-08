# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
server rights
"""

import os
import platform
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Optional

from opsicommon.config import OpsiConfig, get_opsiconfd_user
from opsicommon.logging import get_logger
from opsicommon.system.info import linux_distro_id_like_contains
from opsicommon.utils import Singleton

_HAS_ROOT_RIGHTS = False
if platform.system().lower() == "linux":
	import grp
	import pwd
	import stat

	_HAS_ROOT_RIGHTS = os.geteuid() == 0


logger = get_logger("opsi.general")


@dataclass
class FilePermission:
	path: str | Path
	username: str | None
	groupname: str | None
	file_permissions: int

	@staticmethod
	@lru_cache(maxsize=None)
	def username_to_uid(username: str) -> int:
		return pwd.getpwnam(username)[2]

	@staticmethod
	@lru_cache(maxsize=None)
	def groupname_to_gid(groupname: str) -> int:
		try:
			return grp.getgrnam(groupname)[2]
		except KeyError as err:
			logger.debug(err)
		return -1

	@property
	def uid(self) -> int:
		if not self.username:
			return -1
		return self.username_to_uid(self.username)

	@property
	def gid(self) -> int:
		if not self.groupname:
			return -1
		return self.groupname_to_gid(self.groupname)

	def chmod(self, path: str | Path, stat_res: Optional[os.stat_result] = None) -> None:
		stat_res = stat_res or os.stat(path, follow_symlinks=False)
		cur_mode = stat_res.st_mode & 0o7777
		if cur_mode != self.file_permissions:
			logger.trace("%s: %o != %o", path, cur_mode, self.file_permissions)
			os.chmod(path, self.file_permissions, follow_symlinks=not stat.S_ISLNK(stat_res.st_mode))

	def chown(self, path: str | Path, stat_res: Optional[os.stat_result] = None) -> None:
		stat_res = stat_res or os.stat(path, follow_symlinks=False)
		# Unprivileged user cannot change file owner
		uid = self.uid if _HAS_ROOT_RIGHTS else -1
		if uid not in (-1, stat_res.st_uid) or self.gid not in (-1, stat_res.st_gid):
			logger.trace("%s: %d:%d != %d:%d", path, stat_res.st_uid, stat_res.st_gid, uid, self.gid)
			os.chown(path, uid, self.gid, follow_symlinks=not stat.S_ISLNK(stat_res.st_mode))

	def apply(self, path: str | Path) -> None:
		stat_res = os.stat(path, follow_symlinks=False)
		self.chmod(path, stat_res)
		self.chown(path, stat_res)


@dataclass
class DirPermission(FilePermission):
	dir_permissions: int
	recursive: bool = True
	correct_links: bool = False
	modify_file_exe: bool = True

	def chmod(self, path: str | Path, stat_res: Optional[os.stat_result] = None) -> None:
		stat_res = stat_res or os.stat(path, follow_symlinks=False)
		if stat.S_ISLNK(stat_res.st_mode) and not self.correct_links:
			return

		cur_mode = stat_res.st_mode & 0o7777
		new_mode = self.file_permissions
		if stat.S_ISDIR(stat_res.st_mode):
			new_mode = self.dir_permissions
		elif stat.S_ISREG(stat_res.st_mode) and not self.modify_file_exe:
			# Do not modify executable flag
			if cur_mode & 0o100 and new_mode & 0o400:
				# User: executable bit currently set and new mode readable
				new_mode |= 0o100
			if cur_mode & 0o010 and new_mode & 0o040:
				# Group: executable bit currently set and new mode readable
				new_mode |= 0o010
			if cur_mode & 0o001 and new_mode & 0o004:
				# Other: executable bit currently set and new mode readable
				new_mode |= 0o001

		if cur_mode != new_mode:
			logger.trace("%s: %o != %o", path, cur_mode, new_mode)
			os.chmod(path, new_mode, follow_symlinks=not stat.S_ISLNK(stat_res.st_mode))

	def chown(self, path: str | Path, stat_res: Optional[os.stat_result] = None) -> None:
		stat_res = stat_res or os.stat(path, follow_symlinks=False)
		if stat.S_ISLNK(stat_res.st_mode) and not self.correct_links:
			return None
		return super().chown(path, stat_res)


class PermissionRegistry(metaclass=Singleton):
	_initialized = False

	def __init__(self) -> None:
		if self._initialized:
			return
		self._initialized = True
		self._permissions: dict[str, FilePermission] = {}
		self.reinit()

	def reinit(self) -> None:
		self._permissions = {}
		self.register_default_permissions()

	def register_permission(self, *permission: FilePermission) -> None:
		for perm in permission:
			self._permissions[str(perm.path)] = perm

	def remove_permissions(self) -> None:
		self._permissions = {}

	@property
	def permissions(self) -> dict[str, FilePermission]:
		return self._permissions

	def register_default_permissions(self) -> None:
		opsiconfd_user = get_opsiconfd_user()
		opsi_config = OpsiConfig()
		admin_group = opsi_config.get("groups", "admingroup")
		fileadmin_group = opsi_config.get("groups", "fileadmingroup")
		depot_user = opsi_config.get("depot_user", "username")

		self.register_permission(
			DirPermission("/etc/opsi", opsiconfd_user, admin_group, 0o660, 0o770),
			DirPermission("/var/log/opsi", opsiconfd_user, admin_group, 0o660, 0o770),
			DirPermission("/var/lib/opsi", opsiconfd_user, fileadmin_group, 0o660, 0o770),
		)
		self.register_permission(
			DirPermission("/etc/opsi/ssl", opsiconfd_user, admin_group, 0o600, 0o750),
			FilePermission("/etc/opsi/ssl/opsi-ca-cert.pem", opsiconfd_user, admin_group, 0o644),
		)
		self.register_permission(
			DirPermission("/var/lib/opsi/public", opsiconfd_user, fileadmin_group, 0o664, 0o2775, modify_file_exe=False),
			DirPermission("/var/lib/opsi/depot", opsiconfd_user, fileadmin_group, 0o660, 0o2770, modify_file_exe=False),
			DirPermission("/var/lib/opsi/repository", opsiconfd_user, fileadmin_group, 0o660, 0o2770),
			DirPermission("/var/lib/opsi/workbench", opsiconfd_user, fileadmin_group, 0o660, 0o2770, modify_file_exe=False),
		)

		pxe_dir = "/tftpboot/linux"
		if linux_distro_id_like_contains(("sles", "opensuse")):
			pxe_dir = "/var/lib/tftpboot/opsi"
		self.register_permission(DirPermission(pxe_dir, opsiconfd_user, fileadmin_group, 0o664, 0o775))

		ssh_dir = os.path.join(opsi_config.get("depot_user", "home"), ".ssh")
		self.register_permission(
			DirPermission(
				ssh_dir,
				depot_user,
				fileadmin_group,
				0o640,
				0o750,
				recursive=False,
			),
			FilePermission(
				os.path.join(ssh_dir, "id_rsa"),
				depot_user,
				fileadmin_group,
				0o640,
			),
			FilePermission(
				os.path.join(ssh_dir, "id_rsa.pub"),
				depot_user,
				fileadmin_group,
				0o644,
			),
			FilePermission(
				os.path.join(ssh_dir, "authorized_keys"),
				depot_user,
				fileadmin_group,
				0o600,
			),
		)


def set_rights(start_path: str | Path = "/") -> None:
	start_path = str(start_path)
	logger.debug("Setting rights on %s", start_path)
	permissions = PermissionRegistry().permissions
	permissions_to_process = []
	parent = None
	for path in sorted(list(permissions)):
		if not os.path.relpath(path, start_path).startswith(".."):
			# Sub path of start_path
			permissions_to_process.append(permissions[path])
		elif not os.path.relpath(start_path, path).startswith(".."):
			if not parent or len(parent.path) < len(path):
				parent = permissions[path]

	if parent:
		permissions_to_process.append(parent)

	processed_path = set()
	for permission in permissions_to_process:
		path = start_path
		if not os.path.relpath(permission.path, start_path).startswith(".."):
			# permission.path is sub path of start_path
			path = str(permission.path)

		if path in processed_path or not os.path.lexists(path):
			continue
		processed_path.add(path)

		modify_file_exe = isinstance(permission, DirPermission) and permission.modify_file_exe
		recursive = isinstance(permission, DirPermission) and permission.recursive and os.path.isdir(path)

		logger.info("Setting rights %son '%s'", "recursively " if recursive else "", path)
		permission.apply(path)

		if not recursive:
			continue

		for root, dirs, files in os.walk(path, topdown=True):
			# logger.debug("Processing '%s'", root)
			for name in files:
				abspath = os.path.join(root, name)
				if abspath in permissions:
					continue
				if not modify_file_exe and os.path.islink(abspath):
					continue
				permission.apply(abspath)

			remove_dirs = []
			for name in dirs:
				abspath = os.path.join(root, name)
				if abspath in permissions:
					remove_dirs.append(name)
					continue
				permission.apply(abspath)

			if remove_dirs:
				for name in remove_dirs:
					dirs.remove(name)
