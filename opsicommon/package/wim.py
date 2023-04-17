# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
WIM handling
"""

from datetime import datetime, timezone
from pathlib import Path
from subprocess import run, PIPE, STDOUT
from dataclasses import dataclass, fields
from types import UnionType, GenericAlias
from typing import Any, cast

from opsicommon.system.info import is_linux, is_unix
from opsicommon.logging.logging import get_logger

logger = get_logger("opsicommon.package")


def wim_capture(
	source: Path,
	wim_file: Path,
	*,
	image_name: str | None,
	image_description: str | None,
	boot: bool = False,
	dereference: bool = False,
	unix_data: bool = True,
) -> None:
	cmd = ["wimlib-imagex", "capture", str(source), str(wim_file)]
	if image_name or image_description:
		cmd.append(image_name or "")
		if image_description:
			cmd.append(image_description)
	if boot:
		cmd.append("--boot")
	if dereference and is_unix():
		cmd.append("--dereference")
	if unix_data and is_linux():
		cmd.append("--unix-data")

	logger.info("Executing %s", cmd)
	proc = run(cmd, shell=False, check=False, text=True, stdout=PIPE, stderr=STDOUT)
	logger.debug("Command returncode: %d, output %s", proc.returncode, proc.stdout)
	if proc.returncode != 0:
		raise RuntimeError(f"Failed to execute wimlib-imagex: {proc.returncode} - {proc.stdout}")


@dataclass(kw_only=True)
class WIMImageWindowsInfo:  # pylint: disable=too-many-instance-attributes
	architecture: str
	product_name: str
	edition_id: str
	installation_type: str
	product_type: str
	product_suite: str
	hal: str
	languages: list[str]
	default_language: str
	system_root: str
	major_version: int
	minor_version: int
	build: int
	service_pack_build: int
	service_pack_level: int


@dataclass(kw_only=True)
class WIMImageInfo:  # pylint: disable=too-many-instance-attributes
	index: int
	name: str
	directory_count: int
	file_count: int
	creation_time: datetime
	last_modification_time: datetime
	total_bytes: int
	hard_link_bytes: int = 0
	wimboot_compatible: bool = False
	description: str | None = None
	display_name: str | None = None
	display_description: str | None = None
	windows_info: WIMImageWindowsInfo | None = None


@dataclass(kw_only=True)
class WIMInfo:  # pylint: disable=too-many-instance-attributes
	guid: str
	version: int
	part_number: int
	total_parts: int
	image_count: int
	chunk_size: int
	boot_index: int
	size: int
	compression: str | None = None
	images: list[WIMImageInfo]


def wim_info(wim_file: Path) -> WIMInfo:  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
	cmd = ["wimlib-imagex", "info", str(wim_file)]

	logger.info("Executing %s", cmd)
	proc = run(cmd, shell=False, check=False, text=True, stdout=PIPE, stderr=STDOUT)
	logger.debug("Command returncode: %d, output %s", proc.returncode, proc.stdout)
	if proc.returncode != 0:
		raise RuntimeError(f"Failed to execute wimlib-imagex: {proc.returncode} - {proc.stdout}")

	image_index = 0
	info_data: dict[str, Any] = {}
	image_info_data: dict[int, dict[str, Any]] = {}
	win_image_info_data: dict[int, dict[str, Any]] = {}
	info_attrs = {f.name: f.type for f in fields(WIMInfo)}
	image_info_attrs = {f.name: f.type for f in fields(WIMImageInfo)}
	win_image_info_attrs = {f.name: f.type for f in fields(WIMImageWindowsInfo)}

	for line in proc.stdout.splitlines():
		line = line.strip()
		if not line or ":" not in line:
			continue
		attr, val = line.split(":", 1)
		attr = attr.strip().lower().replace(" ", "_")
		val = cast(Any, val.strip())

		if attr == "index":
			image_index = int(val)
			image_info_data[image_index] = {}
			win_image_info_data[image_index] = {}

		attr_type = info_attrs.get(attr)
		data = info_data
		if image_index > 0:
			attr_type = image_info_attrs.get(attr)
			data = image_info_data[image_index]
			if not attr_type:
				attr_type = win_image_info_attrs.get(attr)
				data = win_image_info_data[image_index]

		if not attr_type:
			continue

		if attr == "part_number":
			data["part_number"], data["total_parts"] = [int(v) for v in val.split("/", 1)]
		else:
			if isinstance(attr_type, UnionType):
				attr_type = attr_type.__args__[0]

			if isinstance(attr_type, GenericAlias):
				attr_type = attr_type.__args__[0]
				val = [attr_type(v.strip()) for v in val.split(" ")]
			elif attr == "guid" and val.startswith("0x"):
				val = val[2:]
			elif attr_type is int and val.startswith("0x"):
				val = cast(Any, int(val, base=16))
			elif attr_type is bool:
				val = cast(Any, val in ("yes", "1"))
			elif attr_type is int and val.endswith("bytes"):
				val = cast(Any, int(val.replace("bytes", "").strip()))
			elif attr_type is datetime:
				# Fri Jul 10 16:37:14 2015 UTC
				tmp = val.split(" ", 2)
				mon = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec").index(tmp[1]) + 1
				val = cast(Any, datetime.strptime(f"{mon} {tmp[2]}", "%m %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc))
			elif attr_type is list[str]:
				val = cast(Any, val.split(" "))
			else:
				val = attr_type(val)
			data[attr] = val

	info_data["images"] = []
	for index, data in image_info_data.items():
		windows_info = win_image_info_data.get(index)
		if windows_info:
			data["windows_info"] = WIMImageWindowsInfo(**windows_info)
		info_data["images"].append(WIMImageInfo(**data))
	return WIMInfo(**info_data)  # type: ignore[arg-type]  # pylint: disable=missing-kwoa
