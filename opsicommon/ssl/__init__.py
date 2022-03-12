# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
ssl
"""

import platform

from .common import as_pem, create_ca, create_server_cert, create_x590_name

if platform.system().lower() == "linux":
	from .linux import *
elif platform.system().lower() == "windows":
	from .windows import *
elif platform.system().lower() == "darwin":
	from .darwin import *
else:
	raise NotImplementedError(f"{platform.system().lower()} not supported")
