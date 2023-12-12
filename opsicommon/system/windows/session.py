
# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
system.windows.session
"""

import warnings
from dataclasses import dataclass
from enum import Enum
from typing import Iterable

import win32ts  # type: ignore[import-not-found]


# pylint: disable=c-extension-no-member
class WtsProtocol(Enum):
	CONSOLE = win32ts.WTS_PROTOCOL_TYPE_CONSOLE
	CITRIX = win32ts.WTS_PROTOCOL_TYPE_ICA
	RDP = win32ts.WTS_PROTOCOL_TYPE_RDP

# pylint: disable=c-extension-no-member
class WtsState(Enum):
	ACTIVE = win32ts.WTSActive
	CONNECTED = win32ts.WTSConnected
	CONNECT_QUERY = win32ts.WTSConnectQuery
	SHADOW = win32ts.WTSShadow
	DISCONNECTED = win32ts.WTSDisconnected
	IDLE = win32ts.WTSIdle
	LISTEN = win32ts.WTSListen
	RESET = win32ts.WTSReset
	DOWN = win32ts.WTSDown
	INIT = win32ts.WTSInit

@dataclass
class WindowsSession:
	session_id: int
	username: str | None
	domain: str | None
	wts_protocol: WtsProtocol
	wts_state: WtsState

def get_windows_sessions(
	session_ids: Iterable[int | str] | int | str | None = None,
	protocols: Iterable[WtsProtocol | str] | WtsProtocol | str | None = None,
	states: Iterable[WtsState | str] | WtsState | str | None = None
) -> list[WindowsSession]:
	if session_ids:
		session_ids = [int(s) for s in ([session_ids] if isinstance(session_ids, (int, str)) else session_ids)]
	else:
		session_ids = []
	if protocols:
		protocols = [WtsProtocol(p) for p in ([protocols] if isinstance(protocols, (WtsProtocol, str)) else protocols)]
	else:
		protocols = []
	if states:
		states = [WtsState(s) for s in ([states] if isinstance(states, (WtsState, str)) else states)]
	else:
		states = []

	sessions = []
	server = win32ts.WTS_CURRENT_SERVER_HANDLE
	for session in win32ts.WTSEnumerateSessions(server):
		session_id = int(session["SessionId"])
		if session_ids and session_id not in session_ids:
			continue
		wts_state = WtsState(session["State"])
		if states and wts_state not in states:
			continue
		wts_protocol = WtsProtocol(win32ts.WTSQuerySessionInformation(server, session_id, win32ts.WTSClientProtocolType))
		if protocols and wts_protocol not in protocols:
			continue
		username = win32ts.WTSQuerySessionInformation(server, session_id, win32ts.WTSUserName) or None
		sessions.append(
			WindowsSession(
				session_id = session_id,
				username=username,
				domain=win32ts.WTSQuerySessionInformation(server, session_id, win32ts.WTSDomainName) or None,
				wts_protocol=wts_protocol,
				wts_state=wts_state
			)
		)
	return sessions
