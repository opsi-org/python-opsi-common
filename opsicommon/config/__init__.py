# opsicommon is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2025 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0-only

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
