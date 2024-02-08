# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
test_system_network
"""

import os
import subprocess

import psutil
import pytest
from opsicommon.system.subprocess import patch_popen
from opsicommon.utils import monkeypatch_subprocess_for_frozen

from .helpers import environment


@pytest.mark.linux
def test_ld_library_path() -> None:
	with pytest.deprecated_call():
		monkeypatch_subprocess_for_frozen()
	ld_library_path_orig = "/orig_path"
	ld_library_path = "/path"
	with environment(LD_LIBRARY_PATH_ORIG=ld_library_path_orig, LD_LIBRARY_PATH=ld_library_path):
		assert os.environ.get("LD_LIBRARY_PATH_ORIG") == ld_library_path_orig
		assert os.environ.get("LD_LIBRARY_PATH") == ld_library_path
		with subprocess.Popen(["sleep", "1"]) as proc:
			ps_proc = psutil.Process(proc.pid)
			proc_env = ps_proc.environ()
			assert proc_env.get("LD_LIBRARY_PATH_ORIG") == ld_library_path_orig
			assert proc_env.get("LD_LIBRARY_PATH") == ld_library_path_orig
			assert os.environ.get("LD_LIBRARY_PATH_ORIG") == ld_library_path_orig
			assert os.environ.get("LD_LIBRARY_PATH") == ld_library_path
			proc.wait()
		assert os.environ.get("LD_LIBRARY_PATH_ORIG") == ld_library_path_orig
		assert os.environ.get("LD_LIBRARY_PATH") == ld_library_path


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
			r"C:\Program Files (x86)\Git\cmd"
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
