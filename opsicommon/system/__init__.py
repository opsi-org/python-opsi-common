# -*- coding: utf-8 -*-
"""
:copyright: uib GmbH <info@uib.de>
This file is part of opsi - https://www.opsi.org

:license: GNU Affero General Public License version 3
"""

import sys
from collections import namedtuple

Session = namedtuple('Session', ["id", "type", "username", "terminal", "login_pid", "started"])

if sys.platform == "linux":
	from .linux import (
		get_user_sessions,
		run_process_in_session
	)
