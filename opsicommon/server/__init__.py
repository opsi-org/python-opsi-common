# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
server specific
"""

import json
import subprocess
from functools import lru_cache
from typing import Any

from opsicommon.logging import get_logger, secret_filter

logger = get_logger(__name__)


@lru_cache
def _opsiconfd_get_config() -> dict[str, Any]:
	proc = subprocess.run(["opsiconfd", "get-config"], shell=False, check=True, capture_output=True, text=True, encoding="utf-8")
	return json.loads(proc.stdout)


def get_opsiconfd_config(template: dict[str, Any] | None = None, ignore_error: bool = True) -> dict[str, str]:
	config = dict(template) if template else {}
	try:
		for attribute, value in _opsiconfd_get_config().items():
			if "passphrase" in attribute or "password" in attribute:
				secret_filter.add_secrets(value)
			if not template or attribute in template:
				config[attribute] = value
	except Exception as err:
		if not ignore_error:
			raise
		logger.debug("Failed to get opsiconfd config %s", err)
	return config
