# opsicommon is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2025 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0-only

"""
This file is part of opsi - https://www.opsi.org
"""

CONNECTION_USER_CHANNEL = "@"
CONNECTION_SESSION_CHANNEL = "$"
EVENT_TYPES = (
	"app_state_changed",
	"config_created",
	"config_deleted",
	"config_updated",
	"configState_created",
	"configState_deleted",
	"configState_updated",
	"host_connected",
	"host_created",
	"host_deleted",
	"host_disconnected",
	"host_updated",
	"log_updated",
	"productOnClient_created",
	"productOnClient_deleted",
	"productOnClient_updated",
	"test",
	"user_connected",
	"user_disconnected",
)
