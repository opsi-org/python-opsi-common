# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
test_system_network
"""

import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import psutil
import pytest

from opsicommon.system.subprocess import patch_popen
from opsicommon.utils import monkeypatch_subprocess_for_frozen

from .helpers import environment


@pytest.mark.linux
@pytest.mark.parametrize(
	"ld_library_path_orig, ld_library_path, executable_path, expected_ld_library_path",
	(
		# LD_LIBRARY_PATH_ORIG is set to a valid value, LD_LIBRARY_PATH must be set to that value
		("/orig/ld/path", "/usr/lib/opsi_component", "/usr/lib/opsi_component/bin/executable", "/orig/ld/path"),
		("/orig/ld/path", "/some/path:/usr/lib/opsiclientd:/usr/lib/opsiconfd", "/usr/lib/opsi_component/bin/executable", "/orig/ld/path"),
		# LD_LIBRARY_PATH_ORIG is not set, LD_LIBRARY_PATH must be removed
		(None, "/usr/lib/opsi_component", "/usr/lib/opsi_component/bin/executable", None),
		# LD_LIBRARY_PATH_ORIG is empty, LD_LIBRARY_PATH must be removed
		("", "/usr/lib/opsi_component", "/usr/lib/opsi_component/bin/executable", None),
		# LD_LIBRARY_PATH_ORIG is empty, LD_LIBRARY_PATH is valid and must be kept
		("", "/some/path", "/usr/lib/opsi_component/bin/executable", "/some/path"),
		# LD_LIBRARY_PATH_ORIG is empty, LD_LIBRARY_PATH is valid and must be kept
		("", "/some/path: /other/path", "/usr/lib/opsi_component/bin/executable", "/some/path:/other/path"),
		# LD_LIBRARY_PATH_ORIG is not set, executable path must be removed fom LD_LIBRARY_PATH
		("", "/some/path:/usr/lib/opsi_component", "/usr/lib/opsi_component/bin/executable", "/some/path"),
		# LD_LIBRARY_PATH_ORIG is not set, hardcoded excludes must be removed fom LD_LIBRARY_PATH
		("", "/some/path:/usr/lib/opsiclientd:/usr/lib/opsiconfd", "/usr/lib/opsi_component/bin/executable", "/some/path"),
	),
)
def test_ld_library_path(ld_library_path_orig: str, ld_library_path: str, executable_path: str, expected_ld_library_path: str) -> None:
	frozen = getattr(sys, "frozen", False)
	setattr(sys, "frozen", True)
	try:
		with pytest.deprecated_call():
			monkeypatch_subprocess_for_frozen()
		env_vars = {"_MEIPASS2": "/tmp/foobar"}
		if ld_library_path_orig is not None:
			env_vars["LD_LIBRARY_PATH_ORIG"] = ld_library_path_orig
		if ld_library_path is not None:
			env_vars["LD_LIBRARY_PATH"] = ld_library_path
		with patch("opsicommon.system.subprocess._get_executable_path", lambda: Path(executable_path)), environment(**env_vars):
			assert os.environ.get("LD_LIBRARY_PATH_ORIG") == ld_library_path_orig
			assert os.environ.get("LD_LIBRARY_PATH") == ld_library_path
			with subprocess.Popen(["sleep", "1"]) as proc:
				ps_proc = psutil.Process(proc.pid)
				proc_env = ps_proc.environ()
				assert proc_env.get("LD_LIBRARY_PATH_ORIG") == ld_library_path_orig
				assert proc_env.get("LD_LIBRARY_PATH") == expected_ld_library_path
				assert proc_env.get("_MEIPASS2") is None
				proc.wait()
			assert os.environ.get("LD_LIBRARY_PATH_ORIG") == ld_library_path_orig
			assert os.environ.get("LD_LIBRARY_PATH") == ld_library_path
			assert os.environ.get("_MEIPASS2") == "/tmp/foobar"
	finally:
		setattr(sys, "frozen", frozen)


def test_path_cleanup() -> None:
	path = ["/usr/local/sbin", "", "/usr/local/bin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "", "/bin"]
	clean_path = ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"]
	cmd = ["sleep", "2"]
	if os.name == "nt":
		path = [
			r"C:\Program Files (x86)\Python311-32\Scripts",
			r"C:\Program Files (x86)\Python311-32",
			r"C:\Program Files (x86)\Python311-32",
			r"",
			r"C:\WINDOWS\system32",
			r"C:\WINDOWS",
			r"",
			r"C:\WINDOWS\System32\Wbem",
			r"C:\WINDOWS\System32\WindowsPowerShell\v1.0",
			r"C:\Program Files (x86)\Git\cmd",
			r"C:\Program Files (x86)\opsi.org\opsi-client-agent\opsiclientd_bin\pywin32_system32",
			r"C:\Program Files (x86)\opsi.org\opsi-client-agent\opsiclientd_bin\pywin32_system32",
			r"C:\WINDOWS",
		]
		clean_path = [
			r"C:\Program Files (x86)\Python311-32\Scripts",
			r"C:\Program Files (x86)\Python311-32",
			r"C:\WINDOWS\system32",
			r"C:\WINDOWS",
			r"C:\WINDOWS\System32\Wbem",
			r"C:\WINDOWS\System32\WindowsPowerShell\v1.0",
			r"C:\Program Files (x86)\Git\cmd",
		]
		cmd = ["timeout", "2"]
	patch_popen()
	with environment(PATH=os.pathsep.join(path)):
		assert os.environ["PATH"].split(os.pathsep) == path
		with subprocess.Popen(cmd, shell=False) as proc:
			ps_proc = psutil.Process(proc.pid)
			proc_env = ps_proc.environ()
			# print("Process environment:", proc_env)
			assert proc_env["PATH"].split(os.pathsep) == clean_path
			proc.wait()
		assert os.environ["PATH"].split(os.pathsep) == path
