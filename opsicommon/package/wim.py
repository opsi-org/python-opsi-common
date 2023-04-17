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

import xml.etree.ElementTree as ET

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
class ImageInfo:  # pylint: disable=too-many-instance-attributes
	index: int
	name: str
	description: str | None
	dir_count: int
	file_count: int
	creation_time: datetime
	modification_time: datetime
	total_bytes: int
	hardlink_bytes: int


@dataclass(kw_only=True)
class WIMInfo:  # pylint: disable=too-many-instance-attributes
	guid: str
	part_number: int
	total_parts: int
	image_count: int
	boot_index: int
	total_bytes: int
	images: list[ImageInfo]


def _win_64bit_time_to_utc_datetime(highpart: str | int, lowpart: str | int) -> datetime:
	if isinstance(highpart, str):
		highpart = int(highpart, base=16)
	if isinstance(lowpart, str):
		lowpart = int(lowpart, base=16)
	unix_timestamp = (((highpart << 32) + lowpart) - 116444736000000000) / 10000000
	return datetime.fromtimestamp(unix_timestamp, tz=timezone.utc)


def _get_child_text(node: ET.Element, name: str, default: str) -> str:
	child = node.find(name)
	if child is not None and child.text is not None:
		return child.text
	return default


def _get_child_datetime(node: ET.Element, name: str, default: datetime) -> datetime:
	child = node.find(name)
	if child is None:
		return default
	highpart = node.find("HIGHPART")
	lowpart = node.find("LOWPART")
	if highpart and highpart.text and lowpart and lowpart.text:
		return _win_64bit_time_to_utc_datetime(highpart.text, lowpart.text)
	return default


def wim_info(wim_file: Path) -> WIMInfo:
	cmd = ["wimlib-imagex", "info", str(wim_file), "--xml", "--header"]
	logger.info("Executing %s", cmd)
	proc = run(cmd, shell=False, check=False, stdout=PIPE, stderr=PIPE)
	stderr = proc.stderr.decode("utf-8")
	logger.debug("Command returncode: %d, stderr %s", proc.returncode, stderr)
	if proc.returncode != 0:
		raise RuntimeError(f"Failed to execute wimlib-imagex: {proc.returncode} - {stderr}")

	idx = proc.stdout.index(b"\xff\xfe")
	if not idx:
		raise RuntimeError(f"Failed to parse wimlib-imagex output: {proc.stdout.decode('utf-8', 'replace')}")

	header = proc.stdout[:idx].decode("utf-8")
	xml = proc.stdout[idx:].decode("utf-16")
	root = ET.fromstring(xml)
	images = []
	for image in root.findall("IMAGE"):
		images.append(
			ImageInfo(
				index=int(image.attrib["INDEX"]),
				name=_get_child_text(image, "NAME", ""),
				description=_get_child_text(image, "DESCRIPTION", ""),
				dir_count=int(
					_get_child_text(image, "DIRCOUNT", "0"),
				),
				file_count=int(
					_get_child_text(image, "FILECOUNT", "0"),
				),
				total_bytes=int(
					_get_child_text(image, "TOTALBYTES", "0"),
				),
				hardlink_bytes=int(
					_get_child_text(image, "HARDLINKBYTES", "0"),
				),
				creation_time=_get_child_datetime(image, "CREATIONTIME", datetime.now()),
				modification_time=_get_child_datetime(image, "MODIFICATIONTIME", datetime.now()),
			)
		)

	attrs = {f.name: f.type for f in fields(WIMInfo)}
	kwargs = {
		"images": images,
		"total_bytes": int(
			_get_child_text(root, "TOTALBYTES", "0"),
		),
	}
	for line in header.splitlines():
		line = line.strip()
		if not line or "=" not in line:
			continue
		key, val = line.split("=", 1)
		key = key.strip().lower().replace(" ", "_")
		if key not in attrs:
			continue
		kwargs[key] = attrs[key](val.strip())

	return WIMInfo(**kwargs)  # type: ignore[arg-type]  # pylint: disable=missing-kwoa
