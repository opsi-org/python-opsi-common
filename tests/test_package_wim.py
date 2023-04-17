# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
test_package_wim
"""

from datetime import datetime, timezone
from pathlib import Path
from subprocess import run, CalledProcessError
from unittest.mock import patch, PropertyMock

import pytest
from opsicommon.package.wim import wim_capture, wim_info, WIMImageInfo, WIMImageWindowsInfo, WIMInfo

WIMLIB_MISSING = False
WIMLIB_ERROR = ""
try:
	run(["wimlib-imagex", "--version"], check=True, capture_output=True, text=True)
except (FileNotFoundError, CalledProcessError) as err:
	WIMLIB_MISSING = True
	WIMLIB_ERROR = str(err)


WIM_INFO = """
WIM Information:
----------------
Path:           install.wim
GUID:           0x292286177a0f97458bb3bb4ea4f590f8
Version:        68864
Image Count:    2
Compression:    LZX
Chunk Size:     32768 bytes
Part Number:    1/1
Boot Index:     0
Size:           3391478970 bytes
Attributes:     Integrity info, Relative path junction

Available Images:
-----------------
Index:                  1
Name:                   Windows 10 Pro N
Description:            Windows 10 Pro N
Display Name:           Windows 10 Pro N
Display Description:    Windows 10 Pro N
Directory Count:        19175
File Count:             91744
Total Bytes:            13147213334
Hard Link Bytes:        5789415254
Creation Time:          Fri Jul 10 16:37:14 2015 UTC
Last Modification Time: Fri Jul 10 16:37:49 2015 UTC
Architecture:           x86_64
Product Name:           Microsoft® Windows® Operating System
Edition ID:             ProfessionalN
Installation Type:      Client
HAL:                    acpiapic
Product Type:           WinNT
Product Suite:          Terminal Server
Languages:              de-DE
Default Language:       de-DE
System Root:            WINDOWS
Major Version:          10
Minor Version:          0
Build:                  10240
Service Pack Build:     16384
Service Pack Level:     0
Flags:                  ProfessionalN
WIMBoot compatible:     no

Index:                  2
Name:                   Windows 10 Home N
Description:            Windows 10 Home N
Display Name:           Windows 10 Home N
Display Description:    Windows 10 Home N
Directory Count:        19059
File Count:             91075
Total Bytes:            13119745008
Hard Link Bytes:        5748302305
Creation Time:          Fri Jul 10 16:42:12 2015 UTC
Last Modification Time: Fri Jul 10 16:42:35 2015 UTC
Architecture:           x86_64
Product Name:           Microsoft® Windows® Operating System
Edition ID:             CoreN
Installation Type:      Client
HAL:                    acpiapic
Product Type:           WinNT
Product Suite:          Terminal Server
Languages:              de-DE
Default Language:       de-DE
System Root:            WINDOWS
Major Version:          10
Minor Version:          0
Build:                  10240
Service Pack Build:     16384
Service Pack Level:     0
Flags:                  CoreN
WIMBoot compatible:     no
"""


def test_wim_info() -> None:
	class Proc:  # pylint: disable=too-few-public-methods
		stdout = WIM_INFO
		returncode = 0

	with patch("opsicommon.package.wim.run", PropertyMock(return_value=Proc())):
		info = wim_info("fake.wim")
		assert info == WIMInfo(
			guid="292286177a0f97458bb3bb4ea4f590f8",
			version=68864,
			part_number=1,
			total_parts=1,
			image_count=2,
			chunk_size=32768,
			boot_index=0,
			size=3391478970,
			compression="LZX",
			images=[
				WIMImageInfo(
					index=1,
					name="Windows 10 Pro N",
					directory_count=19175,
					file_count=91744,
					creation_time=datetime.fromisoformat("2015-07-10T16:37:14Z"),
					last_modification_time=datetime.fromisoformat("2015-07-10T16:37:49Z"),
					total_bytes=13147213334,
					hard_link_bytes=5789415254,
					wimboot_compatible=False,
					description="Windows 10 Pro N",
					display_description="Windows 10 Pro N",
					display_name="Windows 10 Pro N",
					windows_info=WIMImageWindowsInfo(
						architecture="x86_64",
						product_name="Microsoft® Windows® Operating System",
						edition_id="ProfessionalN",
						installation_type="Client",
						product_type="WinNT",
						product_suite="Terminal Server",
						hal="acpiapic",
						languages=["de-DE"],
						default_language="de-DE",
						system_root="WINDOWS",
						major_version=10,
						minor_version=0,
						build=10240,
						service_pack_build=16384,
						service_pack_level=0,
					),
				),
				WIMImageInfo(
					index=2,
					name="Windows 10 Home N",
					directory_count=19059,
					file_count=91075,
					creation_time=datetime.fromisoformat("2015-07-10T16:42:12Z"),
					last_modification_time=datetime.fromisoformat("2015-07-10T16:42:35Z"),
					total_bytes=13119745008,
					hard_link_bytes=5748302305,
					wimboot_compatible=False,
					description="Windows 10 Home N",
					display_description="Windows 10 Home N",
					display_name="Windows 10 Home N",
					windows_info=WIMImageWindowsInfo(
						architecture="x86_64",
						product_name="Microsoft® Windows® Operating System",
						edition_id="CoreN",
						installation_type="Client",
						product_type="WinNT",
						product_suite="Terminal Server",
						hal="acpiapic",
						languages=["de-DE"],
						default_language="de-DE",
						system_root="WINDOWS",
						major_version=10,
						minor_version=0,
						build=10240,
						service_pack_build=16384,
						service_pack_level=0,
					),
				),
			],
		)


@pytest.mark.skipif(WIMLIB_MISSING, reason=WIMLIB_ERROR)
def test_wim_capture(tmp_path: Path) -> None:
	wim_file = tmp_path / "test.wim"
	source = tmp_path / "source"
	(source / "testdir1").mkdir(parents=True)
	(source / "testdir2").mkdir()
	(source / "testfile1").write_text("opsi")
	(source / "testdir1" / "testfile2").write_text("opsi")
	wim_capture(
		tmp_path, wim_file, image_name="image name", image_description="image description", boot=True, dereference=True, unix_data=True
	)
	assert wim_file.exists()

	info = wim_info(wim_file)
	assert info.boot_index == 1
	assert len(info.guid) == 32
	assert info.image_count == 1
	assert info.part_number == 1
	assert info.total_parts == 1
	assert info.size > 0
	assert len(info.images) == 1

	img = info.images[0]
	assert img.index == 1
	assert img.name == "image name"
	assert img.description == "image description"
	assert img.directory_count == 4
	assert img.file_count == 2
	assert img.hard_link_bytes == 0
	print(img.creation_time.tzinfo)
	assert abs((img.creation_time - datetime.now(tz=timezone.utc)).total_seconds()) < 10
	assert abs((img.last_modification_time - datetime.now(tz=timezone.utc)).total_seconds()) < 10
