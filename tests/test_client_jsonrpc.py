# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

from opsicommon.client.jsonrpc import JSONRPCClient

from .helpers import http_jsonrpc_server


def test_connect():
	with http_jsonrpc_server() as server:
		client = JSONRPCClient(f"http://localhost:{server.port}")
		response = client.get("/")
		assert response.content.decode("utf-8") == "OK"
