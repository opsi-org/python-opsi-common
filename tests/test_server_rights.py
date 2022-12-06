# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
test_server_rights
"""

import grp
import os
import pwd
from pathlib import Path

import pytest
from opsicommon.server.rights import (
	DirPermission,
	FilePermission,
	PermissionRegistry,
	set_rights,
)


@pytest.fixture
def some_secondary_group_name() -> str:
	user_id = os.getuid()
	user = pwd.getpwuid(user_id)
	primary_gid = user.pw_gid
	for gid in os.getgrouplist(user.pw_name, primary_gid):  # pylint: disable=dotted-import-in-loop
		if gid != primary_gid:
			return grp.getgrgid(gid).gr_name  # pylint: disable=dotted-import-in-loop
	pytest.skip("No group for test found. Aborting.")
	return ""


def test_permission_registry() -> None:
	registry = PermissionRegistry()
	permission_count = len(registry.permissions)
	assert permission_count > 0

	registry.remove_permissions()
	assert len(registry.permissions) == 0

	registry.register_permission(DirPermission("/tmp", None, None, 0o600, 0o700, recursive=True))
	assert len(registry.permissions) == 1

	registry.register_default_permissions()
	assert len(registry.permissions) == permission_count + 1

	registry.register_permission(DirPermission("/tmp", None, None, 0o600, 0o700, recursive=True))
	assert len(registry.permissions) == permission_count + 1

	registry.reinit()
	assert len(registry.permissions) == permission_count


def test_set_rights_recursive(  # pylint: disable=too-many-locals
	tmp_path: Path, some_secondary_group_name: str  # pylint: disable=redefined-outer-name
) -> None:
	registry = PermissionRegistry()

	user_id = os.getuid()
	user = pwd.getpwuid(user_id)
	primary_gid = user.pw_gid
	username = user.pw_name
	some_secondary_group_id = grp.getgrnam(some_secondary_group_name).gr_gid

	dir1 = os.path.join(tmp_path, "dir1")
	fil1 = os.path.join(dir1, "fil1")
	fil2 = os.path.join(dir1, "fil2")
	dir2 = os.path.join(dir1, "dir2")
	fil3 = os.path.join(dir2, "fil3")
	fil4 = os.path.join(dir2, "fil4")
	dir3 = os.path.join(dir1, "dir3")
	fil5 = os.path.join(dir3, "fil5")
	fil6 = os.path.join(dir3, "fil6")
	fil7 = os.path.join(dir3, "fil7")
	dir4 = os.path.join(dir2, "dir4")

	for path in (dir1, dir2, dir3, dir4):
		os.mkdir(path)  # pylint: disable=dotted-import-in-loop
		os.chmod(path, 0o707)  # pylint: disable=dotted-import-in-loop
	for path in (fil1, fil2, fil3, fil4, fil5, fil6, fil7):
		open(path, "wb").close()  # pylint: disable=consider-using-with
		os.chmod(path, 0o606)  # pylint: disable=dotted-import-in-loop

	for permission in (
		DirPermission(dir1, username, some_secondary_group_name, 0o666, 0o777, recursive=True),
		DirPermission(dir2, None, None, 0o600, 0o700, recursive=True),
		FilePermission(fil1, None, None, 0o660),
		FilePermission(fil6, None, None, 0o660),
		FilePermission(fil7, username, some_secondary_group_name, 0o606),
	):
		registry.register_permission(permission)

	set_rights(dir1)

	for path in (dir1, dir2, dir3, dir4, fil1, fil2, fil3, fil4, fil5, fil6, fil7):
		assert os.stat(path).st_uid == user_id  # pylint: disable=dotted-import-in-loop

	for path in (dir1, dir3, fil2, fil5, fil7):
		assert os.stat(path).st_gid == some_secondary_group_id  # pylint: disable=dotted-import-in-loop
	for path in (dir2, dir4, fil1, fil3, fil4, fil6):
		assert os.stat(path).st_gid == primary_gid  # pylint: disable=dotted-import-in-loop

	assert os.stat(dir1).st_mode & 0o7777 == 0o777
	assert os.stat(fil1).st_mode & 0o7777 == 0o660
	assert os.stat(fil2).st_mode & 0o7777 == 0o666
	assert os.stat(dir2).st_mode & 0o7777 == 0o700
	assert os.stat(fil3).st_mode & 0o7777 == 0o600
	assert os.stat(fil4).st_mode & 0o7777 == 0o600
	assert os.stat(dir3).st_mode & 0o7777 == 0o777
	assert os.stat(fil5).st_mode & 0o7777 == 0o666
	assert os.stat(fil6).st_mode & 0o7777 == 0o660
	assert os.stat(fil7).st_mode & 0o7777 == 0o606
	assert os.stat(dir4).st_mode & 0o7777 == 0o700


def test_set_rights_modify_file_exe(tmp_path: Path) -> None:
	registry = PermissionRegistry()

	dir1 = os.path.join(tmp_path, "dir1")
	fil1 = os.path.join(dir1, "fil1")
	fil2 = os.path.join(dir1, "fil2")
	fil3 = os.path.join(dir1, "fil3")

	for path in (dir1,):
		os.mkdir(path)  # pylint: disable=dotted-import-in-loop
		os.chmod(path, 0o777)  # pylint: disable=dotted-import-in-loop
	for path in (fil1, fil2, fil3):
		open(path, "wb").close()  # pylint: disable=consider-using-with
	os.chmod(fil1, 0o666)
	os.chmod(fil2, 0o775)
	os.chmod(fil3, 0o777)

	registry.register_permission(DirPermission(dir1, None, None, 0o666, 0o770, modify_file_exe=False))

	set_rights(dir1)

	assert os.stat(dir1).st_mode & 0o7777 == 0o770
	assert os.stat(fil1).st_mode & 0o7777 == 0o666
	assert os.stat(fil2).st_mode & 0o7777 == 0o777
	assert os.stat(fil3).st_mode & 0o7777 == 0o777

	os.chmod(fil1, 0o666)
	os.chmod(fil2, 0o775)
	os.chmod(fil3, 0o777)

	registry.register_permission(DirPermission(dir1, None, None, 0o660, 0o770, modify_file_exe=False))

	set_rights(dir1)

	assert os.stat(dir1).st_mode & 0o7777 == 0o770
	assert os.stat(fil1).st_mode & 0o7777 == 0o660
	assert os.stat(fil2).st_mode & 0o7777 == 0o770
	assert os.stat(fil3).st_mode & 0o7777 == 0o770

	os.chmod(fil1, 0o666)
	os.chmod(fil2, 0o775)
	os.chmod(fil3, 0o777)

	registry.register_permission(DirPermission(dir1, None, None, 0o660, 0o770, modify_file_exe=True))

	set_rights(dir1)

	assert os.stat(dir1).st_mode & 0o7777 == 0o770
	assert os.stat(fil1).st_mode & 0o7777 == 0o660
	assert os.stat(fil2).st_mode & 0o7777 == 0o660
	assert os.stat(fil3).st_mode & 0o7777 == 0o660


def test_set_rights_file_in_dir(tmp_path: Path) -> None:
	registry = PermissionRegistry()
	registry.remove_permissions()

	dir1 = os.path.join(tmp_path, "dir1")
	dir2 = os.path.join(dir1, "dir2")
	fil1 = os.path.join(dir2, "fil1")
	fil2 = os.path.join(dir2, "fil2")

	for path in (dir1, dir2):
		os.mkdir(path)  # pylint: disable=dotted-import-in-loop
		os.chmod(path, 0o777)  # pylint: disable=dotted-import-in-loop
	for path in (fil1, fil2):
		open(path, "wb").close()  # pylint: disable=consider-using-with
		os.chmod(path, 0o666)  # pylint: disable=dotted-import-in-loop

	registry.register_permission(
		DirPermission(dir1, None, None, 0o660, 0o770, recursive=True), DirPermission(dir2, None, None, 0o600, 0o700, recursive=True)
	)

	set_rights(fil1)
	assert os.stat(fil1).st_mode & 0o7777 == 0o600
	assert os.stat(fil2).st_mode & 0o7777 == 0o666

	set_rights(fil2)
	assert os.stat(fil2).st_mode & 0o7777 == 0o600
