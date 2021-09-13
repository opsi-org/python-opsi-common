# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
ssl
"""

import platform
from opsicommon.logging import logger

if platform.system().lower() == 'linux':
	from .linux import *
elif platform.system().lower() == 'windows':
	from .windows import *
elif platform.system().lower() == 'darwin':
	from .darwin import *
else:
	raise NotImplementedError(f"{platform.system().lower()} not supported")

from .common import (
	as_pem, create_x590_name, create_ca, create_server_cert
)
