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


WIM_INFO_WIN10 = """
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


WIM_INFO_WIN11 = """
WIM Information:
----------------
Path:           install.wim
GUID:           0xce35b4fd1961994d840f371c26c44d93
Version:        68864
Image Count:    10
Compression:    LZX
Chunk Size:     32768 bytes
Part Number:    1/1
Boot Index:     0
Size:           4691546479 bytes
Attributes:     Relative path junction

Available Images:
-----------------
Index:                  1
Name:                   Windows 11 Education
Description:            Windows 11 Education
Display Name:           Windows 11 Education
Display Description:    Windows 11 Education
Directory Count:        23285
File Count:             104336
Total Bytes:            16509227097
Hard Link Bytes:        7343709159
Creation Time:          Sat Aug 06 09:27:06 2022 UTC
Last Modification Time: Sat Aug 06 09:50:55 2022 UTC
Architecture:           x86_64
Product Name:           Microsoft® Windows® Operating System
Edition ID:             Education
Installation Type:      Client
Product Type:           WinNT
Product Suite:          Terminal Server
Languages:              de-DE
Default Language:       de-DE
System Root:            WINDOWS
Major Version:          10
Minor Version:          0
Build:                  22621
Service Pack Build:     382
Service Pack Level:     0
Flags:                  Education
WIMBoot compatible:     no

Index:                  2
Name:                   Windows 11 Education N
Description:            Windows 11 Education N
Display Name:           Windows 11 Education N
Display Description:    Windows 11 Education N
Directory Count:        22586
File Count:             99181
Total Bytes:            15856937140
Hard Link Bytes:        7073218382
Creation Time:          Sat Aug 06 09:29:32 2022 UTC
Last Modification Time: Sat Aug 06 09:51:15 2022 UTC
Architecture:           x86_64
Product Name:           Microsoft® Windows® Operating System
Edition ID:             EducationN
Installation Type:      Client
Product Type:           WinNT
Product Suite:          Terminal Server
Languages:              de-DE
Default Language:       de-DE
System Root:            WINDOWS
Major Version:          10
Minor Version:          0
Build:                  22621
Service Pack Build:     382
Service Pack Level:     0
Flags:                  EducationN
WIMBoot compatible:     no

Index:                  3
Name:                   Windows 11 Enterprise
Description:            Windows 11 Enterprise
Display Name:           Windows 11 Enterprise
Display Description:    Windows 11 Enterprise
Directory Count:        23285
File Count:             104341
Total Bytes:            16509351612
Hard Link Bytes:        7343709159
Creation Time:          Sat Aug 06 09:37:47 2022 UTC
Last Modification Time: Sat Aug 06 09:51:34 2022 UTC
Architecture:           x86_64
Product Name:           Microsoft® Windows® Operating System
Edition ID:             Enterprise
Installation Type:      Client
Product Type:           WinNT
Product Suite:          Terminal Server
Languages:              de-DE
Default Language:       de-DE
System Root:            WINDOWS
Major Version:          10
Minor Version:          0
Build:                  22621
Service Pack Build:     382
Service Pack Level:     0
Flags:                  Enterprise
WIMBoot compatible:     no

Index:                  4
Name:                   Windows 11 Enterprise N
Description:            Windows 11 Enterprise N
Display Name:           Windows 11 Enterprise N
Display Description:    Windows 11 Enterprise N
Directory Count:        22586
File Count:             99178
Total Bytes:            15856861105
Hard Link Bytes:        7073218382
Creation Time:          Sat Aug 06 09:23:16 2022 UTC
Last Modification Time: Sat Aug 06 09:51:52 2022 UTC
Architecture:           x86_64
Product Name:           Microsoft® Windows® Operating System
Edition ID:             EnterpriseN
Installation Type:      Client
Product Type:           WinNT
Product Suite:          Terminal Server
Languages:              de-DE
Default Language:       de-DE
System Root:            WINDOWS
Major Version:          10
Minor Version:          0
Build:                  22621
Service Pack Build:     382
Service Pack Level:     0
Flags:                  EnterpriseN
WIMBoot compatible:     no

Index:                  5
Name:                   Windows 11 Pro
Description:            Windows 11 Pro
Display Name:           Windows 11 Pro
Display Description:    Windows 11 Pro
Directory Count:        23285
File Count:             104332
Total Bytes:            16507300701
Hard Link Bytes:        7343709159
Creation Time:          Sat Aug 06 09:18:25 2022 UTC
Last Modification Time: Sat Aug 06 09:52:12 2022 UTC
Architecture:           x86_64
Product Name:           Microsoft® Windows® Operating System
Edition ID:             Professional
Installation Type:      Client
Product Type:           WinNT
Product Suite:          Terminal Server
Languages:              de-DE
Default Language:       de-DE
System Root:            WINDOWS
Major Version:          10
Minor Version:          0
Build:                  22621
Service Pack Build:     382
Service Pack Level:     0
Flags:                  Professional
WIMBoot compatible:     no

Index:                  6
Name:                   Windows 11 Pro N
Description:            Windows 11 Pro N
Display Name:           Windows 11 Pro N
Display Description:    Windows 11 Pro N
Directory Count:        22586
File Count:             99176
Total Bytes:            15857883527
Hard Link Bytes:        7073218382
Creation Time:          Sat Aug 06 09:18:50 2022 UTC
Last Modification Time: Sat Aug 06 09:52:30 2022 UTC
Architecture:           x86_64
Product Name:           Microsoft® Windows® Operating System
Edition ID:             ProfessionalN
Installation Type:      Client
Product Type:           WinNT
Product Suite:          Terminal Server
Languages:              de-DE
Default Language:       de-DE
System Root:            WINDOWS
Major Version:          10
Minor Version:          0
Build:                  22621
Service Pack Build:     382
Service Pack Level:     0
Flags:                  ProfessionalN
WIMBoot compatible:     no

Index:                  7
Name:                   Windows 11 Pro Education
Description:            Windows 11 Pro Education
Display Name:           Windows 11 Pro Education
Display Description:    Windows 11 Pro Education
Directory Count:        23285
File Count:             104334
Total Bytes:            16509177307
Hard Link Bytes:        7343709159
Creation Time:          Sat Aug 06 09:22:51 2022 UTC
Last Modification Time: Sat Aug 06 09:52:49 2022 UTC
Architecture:           x86_64
Product Name:           Microsoft® Windows® Operating System
Edition ID:             ProfessionalEducation
Installation Type:      Client
Product Type:           WinNT
Product Suite:          Terminal Server
Languages:              de-DE
Default Language:       de-DE
System Root:            WINDOWS
Major Version:          10
Minor Version:          0
Build:                  22621
Service Pack Build:     382
Service Pack Level:     0
Flags:                  ProfessionalEducation
WIMBoot compatible:     no

Index:                  8
Name:                   Windows 11 Pro Education N
Description:            Windows 11 Pro Education N
Display Name:           Windows 11 Pro Education N
Display Description:    Windows 11 Pro Education N
Directory Count:        22586
File Count:             99179
Total Bytes:            15856886450
Hard Link Bytes:        7073218382
Creation Time:          Sat Aug 06 09:25:20 2022 UTC
Last Modification Time: Sat Aug 06 09:53:07 2022 UTC
Architecture:           x86_64
Product Name:           Microsoft® Windows® Operating System
Edition ID:             ProfessionalEducationN
Installation Type:      Client
Product Type:           WinNT
Product Suite:          Terminal Server
Languages:              de-DE
Default Language:       de-DE
System Root:            WINDOWS
Major Version:          10
Minor Version:          0
Build:                  22621
Service Pack Build:     382
Service Pack Level:     0
Flags:                  ProfessionalEducationN
WIMBoot compatible:     no

Index:                  9
Name:                   Windows 11 Pro for Workstations
Description:            Windows 11 Pro for Workstations
Display Name:           Windows 11 Pro for Workstations
Display Description:    Windows 11 Pro for Workstations
Directory Count:        23285
File Count:             104335
Total Bytes:            16509202202
Hard Link Bytes:        7343709159
Creation Time:          Sat Aug 06 09:24:59 2022 UTC
Last Modification Time: Sat Aug 06 09:53:26 2022 UTC
Architecture:           x86_64
Product Name:           Microsoft® Windows® Operating System
Edition ID:             ProfessionalWorkstation
Installation Type:      Client
Product Type:           WinNT
Product Suite:          Terminal Server
Languages:              de-DE
Default Language:       de-DE
System Root:            WINDOWS
Major Version:          10
Minor Version:          0
Build:                  22621
Service Pack Build:     382
Service Pack Level:     0
Flags:                  ProfessionalWorkstation
WIMBoot compatible:     no

Index:                  10
Name:                   Windows 11 Pro N for Workstations
Description:            Windows 11 Pro N for Workstations
Display Name:           Windows 11 Pro N for Workstations
Display Description:    Windows 11 Pro N for Workstations
Directory Count:        22586
File Count:             99180
Total Bytes:            15856911795
Hard Link Bytes:        7073218382
Creation Time:          Sat Aug 06 09:27:28 2022 UTC
Last Modification Time: Sat Aug 06 09:53:44 2022 UTC
Architecture:           x86_64
Product Name:           Microsoft® Windows® Operating System
Edition ID:             ProfessionalWorkstationN
Installation Type:      Client
Product Type:           WinNT
Product Suite:          Terminal Server
Languages:              de-DE
Default Language:       de-DE
System Root:            WINDOWS
Major Version:          10
Minor Version:          0
Build:                  22621
Service Pack Build:     382
Service Pack Level:     0
Flags:                  ProfessionalWorkstationN
WIMBoot compatible:     no
"""


def test_wim_info() -> None:
	class Proc:  # pylint: disable=too-few-public-methods
		stdout = WIM_INFO_WIN10
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
					creation_time=datetime(2015, 7, 10, 16, 37, 14, tzinfo=timezone.utc),
					last_modification_time=datetime(2015, 7, 10, 16, 37, 49, tzinfo=timezone.utc),
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
					creation_time=datetime(2015, 7, 10, 16, 42, 12, tzinfo=timezone.utc),
					last_modification_time=datetime(2015, 7, 10, 16, 42, 35, tzinfo=timezone.utc),
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

	Proc.stdout = WIM_INFO_WIN11

	with patch("opsicommon.package.wim.run", PropertyMock(return_value=Proc())):
		info = wim_info("fake.wim")
		assert info
		assert info.guid == "ce35b4fd1961994d840f371c26c44d93"
		assert info.version == 68864
		assert len(info.images) == 10


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
