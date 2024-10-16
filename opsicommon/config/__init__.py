# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

from .opsi import (
	OPSI_CA_CERT_FILE,
	OpsiConfig,
	get_opsiconfd_user,
)

__all__ = [
	"OPSI_CA_CERT_FILE",
	"OpsiConfig",
	"get_opsiconfd_user",
]
