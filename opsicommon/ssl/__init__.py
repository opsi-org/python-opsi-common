# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
ssl
"""

import platform

from .common import as_pem, create_ca, create_server_cert, create_x509_name, is_self_signed, x509_name_from_dict, x509_name_to_dict

if platform.system().lower() == "linux":
	from .linux import *  # noqa: F403
elif platform.system().lower() == "windows":
	from .windows import *  # noqa: F403
elif platform.system().lower() == "darwin":
	from .darwin import *  # noqa: F403
else:
	raise NotImplementedError(f"{platform.system().lower()} not supported")
