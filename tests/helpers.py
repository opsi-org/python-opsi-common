# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
Helpers for testing opsi.
"""

import os
import gzip
import json
import time
import threading
import socket
from contextlib import closing, contextmanager
import http.server
import socketserver
import lz4
import msgpack


class HTTPJSONRPCServerRequestHandler(http.server.SimpleHTTPRequestHandler):
	def _log(self, data):  # pylint: disable=invalid-name
		if not self.server.log_file:
			return
		with open(self.server.log_file, "a", encoding="utf-8") as file:
			file.write(json.dumps(data))
			file.write("\n")
			file.flush()

	def version_string(self):
		for name, value in self.server.response_headers.items():
			if name.lower() == "server":
				return value
		return super().version_string()

	def _send_headers(self, headers=None):
		if self.server.response_delay:
			time.sleep(self.server.response_delay)
		headers = headers or {}
		headers.update(self.server.response_headers)
		for name, value in headers.items():
			if name.lower() == "server":
				continue
			value = value.replace("{server_address}", f"{self.server.server_address[0]}:{self.server.server_address[1]}")
			value = value.replace("{host}", self.headers["Host"])
			self.send_header(name, value)
		self.end_headers()

	def do_POST(self):  # pylint: disable=invalid-name
		length = int(self.headers['Content-Length'])
		request = self.rfile.read(length)
		#print(self.headers)

		if self.headers['Content-Encoding'] == "lz4":
			request = lz4.frame.decompress(request)
		elif self.headers['Content-Encoding'] == "gzip":
			request = gzip.decompress(request)

		if "json" in self.headers['Content-Type']:
			request = json.loads(request)
		elif "msgpack" in self.headers['Content-Type']:
			request = msgpack.loads(request)

		self._log({"method": "POST", "path": self.path, "headers": dict(self.headers), "request": request})
		response = None
		if self.server.response_body:
			response = self.server.response_body
		else:
			response = {"id": request["id"], "result": []}
			response = json.dumps(response).encode("utf-8")
		if self.server.response_status:
			self.send_response(self.server.response_status[0], self.server.response_status[1])
		else:
			self.send_response(200, "OK")
		headers = {
			"Content-Length": str(len(response)),
			"Content-Type": "application/json"
		}
		self._send_headers(headers)
		self.wfile.write(response)

	def do_GET(self):
		if self.server.response_status:
			self.send_response(self.server.response_status[0], self.server.response_status[1])
		else:
			self.send_response(200, "OK")
		self._log({"method": "GET", "path": self.path, "headers": dict(self.headers)})
		response = None
		if self.server.response_body:
			response = self.server.response_body
		else:
			response = "OK".encode("utf-8")
		headers = {
			"Content-Length": str(len(response))
		}
		self._send_headers(headers)
		self.wfile.write(response)

class HTTPJSONRPCServer(threading.Thread):  # pylint: disable=too-many-instance-attributes
	def __init__(self, log_file=None, response_headers=None, response_status=None, response_body=None, response_delay=None):  # pylint: disable=too-many-arguments
		super().__init__()
		self.running = threading.Event()
		self.log_file = str(log_file) if log_file else None
		self.response_headers = response_headers if response_headers else {}
		self.response_status = response_status if response_status else None
		self.response_body = response_body if response_body else None
		self.response_delay = response_delay if response_delay else None
		# Auto select free port
		with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
			sock.bind(('', 0))
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.port = sock.getsockname()[1]
		self.server = None

	def run(self):
		self.server = socketserver.TCPServer(("", self.port), HTTPJSONRPCServerRequestHandler)
		self.server.log_file = self.log_file
		self.server.response_headers = self.response_headers
		self.server.response_status = self.response_status
		self.server.response_body = self.response_body
		self.server.response_delay = self.response_delay
		#print("Server started at localhost:" + str(self.port))
		self.running.set()
		self.server.serve_forever()

	def stop(self):
		if self.server:
			self.server.shutdown()


@contextmanager
def http_jsonrpc_server(log_file=None, response_headers=None, response_status=None, response_body=None, response_delay=None):
	server = HTTPJSONRPCServer(log_file, response_headers, response_status, response_body, response_delay)
	server.daemon = True
	server.start()
	server.running.wait(3.0)
	try:
		yield server
	finally:
		server.stop()


@contextmanager
def environment(env_vars: dict):
	old_environ = os.environ.copy()
	os.environ.update(env_vars)
	#print(os.environ)
	yield
	os.environ.clear()
	os.environ.update(old_environ)
