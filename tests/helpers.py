# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
Helpers for testing opsi.
"""

import json
import threading
import socket
from contextlib import closing, contextmanager
import http.server
import socketserver

class HTTPJSONRPCServerRequestHandler(http.server.SimpleHTTPRequestHandler):
	def do_POST(self):  # pylint: disable=invalid-name
		length = int(self.headers['Content-Length'])
		request = json.loads(self.rfile.read(length))
		response = {"id": request["id"], "result": []}
		response = json.dumps(response).encode("utf-8")
		self.send_response(200, "OK")
		self.send_header("Content-Length", str(len(response)))
		self.send_header("Content-Type", "application/json")
		self.end_headers()
		self.wfile.write(response)

	def do_GET(self):
		response = "OK".encode("utf-8")
		self.send_response(200, "OK")
		self.send_header("Content-Length", str(len(response)))
		self.end_headers()
		self.wfile.write(response)

class HTTPJSONRPCServer(threading.Thread):
	def __init__(self):
		super().__init__()
		# Auto select free port
		with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
			sock.bind(('', 0))
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.port = sock.getsockname()[1]
		self.server = None

	def run(self):
		class Handler(HTTPJSONRPCServerRequestHandler):
			def __init__(self, *args, **kwargs):
				super().__init__(*args, **kwargs)
		self.server = socketserver.TCPServer(("", self.port), Handler)
		#print("Server started at localhost:" + str(self.port))
		self.server.serve_forever()

	def stop(self):
		if self.server:
			self.server.shutdown()


@contextmanager
def http_jsonrpc_server():
	server = HTTPJSONRPCServer()
	server.daemon = True
	server.start()
	try:
		yield server
	finally:
		server.stop()
