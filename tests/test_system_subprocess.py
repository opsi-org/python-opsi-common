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


@pytest.mark.windows
def test_run_as_user() -> None:
	patch_popen()
